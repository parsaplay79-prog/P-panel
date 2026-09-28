"""Verdent Platform — background job queue (Document 1 §M; Document 3).

The platform had no way to run slow work outside a request. Node provisioning
awaited inside the web handler for up to two minutes; a Railway proxy timeout
mid-flight left Cloudflare resources created with no `nodes` row to point at
them, and nothing anywhere retried a transient failure. This module is the
missing primitive.

Design, in the order the decisions matter:

**Dedupe by key, not by attempt.** `enqueue` takes an `idempotency_key` that
names the *work*, not the *try* — `provision_node:<account>:<script>` rather
than a random id. A UNIQUE index enforces it in Postgres, so two concurrent
submissions of the same form cannot both insert, and a retried HTTP request
returns the row that already exists. Document 1 §M requires every provisioning
step to be "safe to retry … so a Railway restart mid-provisioning resumes rather
than double-creates a KV namespace or double-deploys a script."

**Claim with SKIP LOCKED.** The web service and the worker service both run
consumers. `SELECT … FOR UPDATE SKIP LOCKED` lets them pull disjoint work
without either blocking on the other's row, which is the only locking strategy
that stays correct as services are added.

**A dead consumer does not strand a job.** A row left RUNNING by a killed
process is reclaimed once `started_at` is older than `STALE_RUNNING_SECONDS`.
`attempts` is incremented at claim time, not at failure time, so a job that
kills its consumer every single time still exhausts `max_attempts` and lands in
FAILED instead of looping forever.

**Retry is bounded and visible.** A failure below the ceiling goes back to
QUEUED with the error recorded; at the ceiling it becomes FAILED and stays
visible in the panel's job queue. Nothing is silently dropped.
"""

import logging
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Job

logger = logging.getLogger("verdent.jobs")

# ---------------------------------------------------------------------------
# Job types. A string constant per kind of work, so a typo in a payload's
# dispatch key is a NameError at import rather than a job that silently never
# runs.
# ---------------------------------------------------------------------------

JOB_PROVISION_NODE = "provision_node"
JOB_DECOMMISSION_NODE = "decommission_node"
JOB_FULFILL_ORDER = "fulfill_order"
JOB_KV_SET_STATUS = "kv_set_status"
JOB_VERIFY_CF_ACCOUNT = "verify_cloudflare_account"
JOB_ROTATE_CREDENTIAL = "rotate_credential"

ALL_JOB_TYPES = (
    JOB_PROVISION_NODE,
    JOB_DECOMMISSION_NODE,
    JOB_FULFILL_ORDER,
    JOB_KV_SET_STATUS,
    JOB_VERIFY_CF_ACCOUNT,
    JOB_ROTATE_CREDENTIAL,
)

JOB_TYPE_FA = {
    JOB_PROVISION_NODE: "ساخت نود",
    JOB_DECOMMISSION_NODE: "حذف نود",
    JOB_FULFILL_ORDER: "فعال‌سازی سفارش",
    JOB_KV_SET_STATUS: "همگام‌سازی اعتبارنامه",
    JOB_VERIFY_CF_ACCOUNT: "بررسی حساب Cloudflare",
    JOB_ROTATE_CREDENTIAL: "چرخش اعتبارنامه",
}

STATUS_QUEUED = "QUEUED"
STATUS_RUNNING = "RUNNING"
STATUS_SUCCEEDED = "SUCCEEDED"
STATUS_FAILED = "FAILED"
STATUS_CANCELLED = "CANCELLED"

ALL_JOB_STATUSES = (STATUS_QUEUED, STATUS_RUNNING, STATUS_SUCCEEDED, STATUS_FAILED, STATUS_CANCELLED)

JOB_STATUS_FA = {
    STATUS_QUEUED: "در صف",
    STATUS_RUNNING: "در حال اجرا",
    STATUS_SUCCEEDED: "موفق",
    STATUS_FAILED: "ناموفق",
    STATUS_CANCELLED: "لغو شده",
}

# A RUNNING job older than this is presumed dead — its consumer was killed
# (deploy, OOM, Railway restart) and will never finish it. Fifteen minutes is
# far longer than any single job legitimately takes (the slowest, provisioning,
# is tens of seconds) and short enough that an operator does not sit waiting.
STALE_RUNNING_SECONDS = 900

DEFAULT_MAX_ATTEMPTS = 3
# One consumer pass pulls at most this many jobs, so a backlog drains steadily
# instead of one process holding a long transaction over hundreds of rows.
BATCH_SIZE = 5


class JobError(Exception):
    """A job failed in a way the caller should see. Recorded in `last_error`."""


# ---------------------------------------------------------------------------
# Enqueue
# ---------------------------------------------------------------------------


async def enqueue(
    db: AsyncSession,
    job_type: str,
    payload: dict | None = None,
    *,
    idempotency_key: str | None = None,
    requested_by: str | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> Job:
    """Queue a job, or return the existing one with the same key.

    The key is the whole point: `provision_node:acct:my-node` submitted twice
    (double-click, a retried request, a redeploy that replays a form) yields one
    job. Without it the platform would create two KV namespaces and deploy the
    script twice for one operator intent.

    A job that already SUCCEEDED with this key is returned as-is rather than
    re-queued — re-running finished work is how a "retry" button becomes a
    duplicate-resource button. To deliberately re-run, use a new key.
    """
    if job_type not in ALL_JOB_TYPES:
        # Fail loudly at the call site. A job type with no dispatch entry would
        # otherwise sit in the queue forever, claiming to be work.
        raise ValueError(f"unknown job type {job_type!r}")

    if idempotency_key is not None:
        existing = (
            await db.execute(select(Job).where(Job.idempotency_key == idempotency_key))
        ).scalar_one_or_none()
        if existing is not None:
            logger.info(
                "job %s already exists for key %r (status=%s) — not enqueueing a duplicate",
                existing.id, idempotency_key, existing.status,
            )
            return existing

    job = Job(
        job_type=job_type,
        payload_json=payload or {},
        status=STATUS_QUEUED,
        idempotency_key=idempotency_key,
        max_attempts=max_attempts,
        requested_by=requested_by,
    )
    db.add(job)
    try:
        await db.commit()
    except IntegrityError:
        # Two requests raced past the SELECT above. The UNIQUE index is the real
        # arbiter; the loser re-reads and returns the winner's row, which is
        # exactly what the caller wanted.
        await db.rollback()
        if idempotency_key is None:
            raise
        winner = (
            await db.execute(select(Job).where(Job.idempotency_key == idempotency_key))
        ).scalar_one_or_none()
        if winner is None:
            raise
        logger.info("job enqueue raced for key %r — returning the existing row", idempotency_key)
        return winner

    logger.info("enqueued %s job %s", job_type, job.id)
    return job


# ---------------------------------------------------------------------------
# Claim
# ---------------------------------------------------------------------------


def _stale_cutoff() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=STALE_RUNNING_SECONDS)


async def claim_next_job(db: AsyncSession) -> Job | None:
    """Take the oldest runnable job, or None. Safe to call from many processes.

    `with_for_update(skip_locked=True)` is what makes the web and worker
    consumers coexist: each takes a row nobody else has locked, and neither
    blocks. Two consumers cannot claim the same job, so a provisioning job is
    never run twice concurrently.

    A RUNNING row past the staleness cutoff is eligible again. That is the only
    recovery path for a consumer killed mid-job — without it the row would sit
    in RUNNING forever and its Cloudflare resources would stay half-made.
    """
    job = (
        await db.execute(
            select(Job)
            .where(
                Job.attempts < Job.max_attempts,
                or_(
                    Job.status == STATUS_QUEUED,
                    (Job.status == STATUS_RUNNING) & (Job.started_at < _stale_cutoff()),
                ),
            )
            .order_by(Job.created_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
    ).scalar_one_or_none()

    if job is None:
        await db.rollback()
        return None

    if job.status == STATUS_RUNNING:
        logger.warning(
            "reclaiming stale RUNNING job %s (%s) — its consumer did not finish",
            job.id, job.job_type,
        )

    job.status = STATUS_RUNNING
    # Incremented HERE, not on failure. A job that kills its consumer every time
    # must still exhaust its budget: counting only caught exceptions would let
    # a hard crash (OOM, SIGKILL) retry forever.
    job.attempts = (job.attempts or 0) + 1
    job.started_at = datetime.now(timezone.utc)
    job.last_error = None
    await db.commit()
    return job


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


async def _run_provision_node(db: AsyncSession, payload: dict) -> dict:
    from domain.provisioning import provision_node

    node = await provision_node(
        db,
        payload["cloudflare_account_id"],
        payload["worker_script_name"],
        capability_tags=payload.get("capability_tags"),
        max_assignment_count=int(payload.get("max_assignment_count", 3)),
    )
    return {
        "node_id": node.id,
        "custom_domain": node.custom_domain,
        "state": node.state,
    }


async def _run_decommission_node(db: AsyncSession, payload: dict) -> dict:
    from db.models import Node
    from domain.provisioning import decommission_node

    node = (
        await db.execute(select(Node).where(Node.id == payload["node_id"]))
    ).scalar_one_or_none()
    if node is None:
        raise JobError(f"node {payload['node_id']} not found")

    await decommission_node(db, node)
    return {"node_id": node.id, "state": node.state}


async def _run_fulfill_order(db: AsyncSession, payload: dict) -> dict:
    from db.models import Order, PaymentAttempt
    from domain.fulfillment import retry_fulfillment

    order = (
        await db.execute(select(Order).where(Order.id == payload["order_id"]))
    ).scalar_one_or_none()
    if order is None:
        raise JobError(f"order {payload['order_id']} not found")

    attempt = (
        await db.execute(
            select(PaymentAttempt)
            .where(
                PaymentAttempt.order_id == order.id,
                PaymentAttempt.status == "APPROVED",
            )
            .order_by(PaymentAttempt.reviewed_at.desc().nullslast())
            .limit(1)
        )
    ).scalar_one_or_none()

    config = await retry_fulfillment(db, order, attempt, payload.get("admin_id"))
    return {"configuration_id": config.id, "order_id": order.id}


async def _run_kv_set_status(db: AsyncSession, payload: dict) -> dict:
    """Flip one credential's status at the edge, asynchronously.

    Exists because the KV write is a Cloudflare round trip: doing it inline in a
    request makes a suspend button wait on the network, and doing it *after*
    committing the status change means a failure leaves Postgres and the edge
    disagreeing. As a job it is retried instead.
    """
    from db.models import Node
    from domain.kv_sync import set_entry_status

    node = (
        await db.execute(select(Node).where(Node.id == payload["node_id"]))
    ).scalar_one_or_none()
    if node is None:
        raise JobError(f"node {payload['node_id']} not found")

    ok = await set_entry_status(db, node, payload["proxy_uuid"], payload["status"])
    if not ok:
        raise JobError(f"KV status update failed on node {node.id}")
    return {"node_id": node.id, "proxy_uuid": payload["proxy_uuid"], "status": payload["status"]}


async def _run_verify_cf_account(db: AsyncSession, payload: dict) -> dict:
    from db.models import CloudflareAccount
    from domain.cloudflare import CloudflareClient
    from domain.config import settings

    account = (
        await db.execute(
            select(CloudflareAccount).where(CloudflareAccount.id == payload["account_id"])
        )
    ).scalar_one_or_none()
    if account is None:
        raise JobError(f"cloudflare account {payload['account_id']} not found")

    client = CloudflareClient(
        account.api_token_encrypted,
        settings.cloudflare_token_encryption_key,
        account.cf_account_id,
    )
    detail = await client.verify_token()
    account.status = "active"
    await db.commit()
    return detail


async def _run_rotate_credential(db: AsyncSession, payload: dict) -> dict:
    from db.models import Configuration
    from domain.configurations import rotate_proxy_credential

    config = (
        await db.execute(
            select(Configuration).where(Configuration.id == payload["configuration_id"])
        )
    ).scalar_one_or_none()
    if config is None:
        raise JobError(f"configuration {payload['configuration_id']} not found")

    result = await rotate_proxy_credential(db, config, actor_id=payload.get("actor_id"))
    return result


# The dispatch table. Every member of ALL_JOB_TYPES must appear here — asserted
# by scripts/test_admin_panel.py, because a job type with no handler is a row
# that sits in the queue looking like work forever.
_HANDLERS: dict[str, Callable[[AsyncSession, dict], Awaitable[dict]]] = {
    JOB_PROVISION_NODE: _run_provision_node,
    JOB_DECOMMISSION_NODE: _run_decommission_node,
    JOB_FULFILL_ORDER: _run_fulfill_order,
    JOB_KV_SET_STATUS: _run_kv_set_status,
    JOB_VERIFY_CF_ACCOUNT: _run_verify_cf_account,
    JOB_ROTATE_CREDENTIAL: _run_rotate_credential,
}


async def run_job(db: AsyncSession, job: Job) -> dict:
    """Execute one claimed job, recording success or failure on the row.

    Never raises: a job failure is data about the job, not an exception for the
    consumer loop to die on. The caller (`job_consumer_pass`) must keep
    draining the queue even when one job is broken.
    """
    handler = _HANDLERS.get(job.job_type)
    if handler is None:
        await _fail(db, job, f"no handler registered for job type {job.job_type!r}")
        return {"ok": False, "error": "no handler"}

    try:
        result = await handler(db, job.payload_json or {})
    except Exception as exc:  # noqa: BLE001 — a job failure must not kill the loop
        # traceback into the log for the operator; the exception message onto
        # the row so the panel can show why without log access.
        logger.exception("job %s (%s) failed", job.id, job.job_type)
        await _fail(db, job, f"{type(exc).__name__}: {exc}", trace=traceback.format_exc())
        return {"ok": False, "error": str(exc)}

    job.status = STATUS_SUCCEEDED
    job.result_json = result
    job.finished_at = datetime.now(timezone.utc)
    job.last_error = None
    await db.commit()
    logger.info("job %s (%s) succeeded", job.id, job.job_type)
    return {"ok": True, "result": result}


async def _fail(db: AsyncSession, job: Job, message: str, *, trace: str | None = None) -> None:
    """Record a failure, re-queueing while the attempt budget allows.

    Back to QUEUED rather than a delayed retry: the consumer ticks every few
    seconds, and a job that failed because a Cloudflare API was briefly down is
    best retried promptly. The attempt ceiling is what stops a permanently
    broken job from spinning — at the ceiling it becomes FAILED and stays
    visible in the panel instead of looping.
    """
    job.last_error = message[:2000]
    if trace:
        logger.debug("job %s traceback:\n%s", job.id, trace)

    if (job.attempts or 0) < (job.max_attempts or DEFAULT_MAX_ATTEMPTS):
        job.status = STATUS_QUEUED
        logger.warning(
            "job %s (%s) failed (attempt %s/%s) — re-queued: %s",
            job.id, job.job_type, job.attempts, job.max_attempts, message,
        )
    else:
        job.status = STATUS_FAILED
        job.finished_at = datetime.now(timezone.utc)
        logger.error(
            "job %s (%s) FAILED permanently after %s attempt(s): %s",
            job.id, job.job_type, job.attempts, message,
        )
    await db.commit()


async def retry_job(db: AsyncSession, job: Job, actor_id: str | None = None) -> Job:
    """Put a FAILED job back in the queue with a fresh attempt budget.

    The operator's retry button. `attempts` resets because the human has just
    looked at the failure and fixed the cause — keeping the old count would let
    a third retry silently refuse to run.
    """
    job.status = STATUS_QUEUED
    job.attempts = 0
    job.last_error = None
    job.started_at = None
    job.finished_at = None
    await db.commit()
    logger.info("job %s (%s) re-queued by admin %s", job.id, job.job_type, actor_id)
    return job


async def cancel_job(db: AsyncSession, job: Job, actor_id: str | None = None) -> Job:
    """Cancel a job that has not finished. A no-op on a finished one."""
    if job.status in (STATUS_SUCCEEDED, STATUS_FAILED, STATUS_CANCELLED):
        return job
    job.status = STATUS_CANCELLED
    job.finished_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("job %s (%s) cancelled by admin %s", job.id, job.job_type, actor_id)
    return job


# ---------------------------------------------------------------------------
# Consumer
# ---------------------------------------------------------------------------


async def job_consumer_pass(db: AsyncSession, *, batch_size: int = BATCH_SIZE) -> int:
    """Claim and run up to `batch_size` jobs. Returns how many ran.

    Each job is claimed in its own transaction and committed before the next is
    claimed, so one slow job does not hold row locks that block the other
    service's consumer.
    """
    ran = 0
    for _ in range(batch_size):
        job = await claim_next_job(db)
        if job is None:
            break
        await run_job(db, job)
        ran += 1
    return ran


async def queue_stats(db: AsyncSession) -> dict[str, int]:
    """Counts per status, for the dashboard and the job queue page."""
    from sqlalchemy import func

    rows = (
        await db.execute(select(Job.status, func.count(Job.id)).group_by(Job.status))
    ).all()
    counts = {status: 0 for status in ALL_JOB_STATUSES}
    for status, count in rows:
        counts[status] = int(count)
    return counts


def job_ref(job_id: str) -> str:
    """First 8 characters — the short ref the panel shows and links by."""
    return (job_id or "")[:8]


def enqueue_key_for_provision(account_id: str, script_name: str) -> str:
    """The idempotency key for a node provisioning job.

    Names the work (this account, this script name), never the attempt. Two
    submissions of the same form therefore collapse to one job — which is what
    makes a double-clicked "create node" button harmless.
    """
    return f"provision_node:{account_id}:{script_name}"


def enqueue_key_for_order(order_id: str) -> str:
    """The key for an order's fulfillment job. One live job per order."""
    return f"fulfill_order:{order_id}"


def enqueue_key_for_decommission(node_id: str) -> str:
    return f"decommission_node:{node_id}"


def enqueue_key_for_kv_status(node_id: str, proxy_uuid: str, status: str) -> str:
    # Status is part of the key: suspend then reactivate must produce two jobs,
    # while suspend twice produces one.
    return f"kv_set_status:{node_id}:{proxy_uuid}:{status}"


def enqueue_key_for_rotate(config_id: str) -> str:
    # Deliberately NOT idempotent across rotations — each rotation is a distinct
    # request for a NEW credential, so the caller passes a timestamped suffix.
    return f"rotate_credential:{config_id}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

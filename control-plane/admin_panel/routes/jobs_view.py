"""Jobs — the queue view: what is queued, what failed, and the two levers.

Document 1 §M makes provisioning a state-machine-driven background job. That
decision has a consequence the panel has to carry: work that used to either
succeed or fail inside a request now *waits*, and an operator needs to see the
queue. Without this page, a node stuck in PROVISIONING is a spinner with no
explanation and no retry.

Two levers, and they are different:

  * **Retry** a FAILED job. `retry_job` resets the attempt budget, because the
    operator has just looked at the failure and fixed the cause — keeping the
    old count would let a third retry silently refuse to run.
  * **Cancel** a QUEUED job. A queued job that is no longer wanted (a node name
    the operator has since changed their mind about) would otherwise run
    eventually and create a resource nobody asked for.

A RUNNING job cannot be cancelled — the worker is inside the handler, and
marking the row CANCELLED would not stop it while leaving the queue claiming the
work never happened. The page says so rather than offering a button that lies.
"""

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import Admin, Job
from domain import jobs as jobs_domain
from domain import rbac
from domain.audit import audit

logger = logging.getLogger("verdent.admin_panel.jobs")

router = APIRouter()

SORT_COLUMNS = {
    "created": Job.created_at,
    "finished": Job.finished_at,
    "status": Job.status,
    "type": Job.job_type,
    "attempts": Job.attempts,
}


@router.get("/jobs")
async def jobs_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """The queue, defaulting to the work that needs attention.

    Default filter is QUEUED + RUNNING + FAILED. SUCCEEDED rows are the vast
    majority and the least interesting — a queue page that opens on a wall of
    finished work is a queue page nobody uses. `?status=SUCCEEDED` and
    `?status=all` are both available.
    """
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("status", "type"),
    )

    stmt = select(Job)
    count_stmt = select(func.count()).select_from(Job)

    conditions = []
    status_filter = query.filters.get("status")
    if status_filter in jobs_domain.ALL_JOB_STATUSES:
        conditions.append(Job.status == status_filter)
    elif status_filter != "all":
        conditions.append(
            Job.status.in_(
                [
                    jobs_domain.STATUS_QUEUED,
                    jobs_domain.STATUS_RUNNING,
                    jobs_domain.STATUS_FAILED,
                ]
            )
        )

    if query.filters.get("type") in jobs_domain.ALL_JOB_TYPES:
        conditions.append(Job.job_type == query.filters["type"])

    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(func.cast(Job.id, Text)).like(f"{query.q.lower()}%"),
                func.lower(Job.job_type).like(pattern),
                func.lower(func.coalesce(Job.last_error, "")).like(pattern),
            )
        )

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    jobs = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).scalars().all()

    requesters = {
        a.id: a
        for a in (
            await db.execute(
                select(Admin).where(Admin.id.in_([j.requested_by for j in jobs if j.requested_by]))
            )
        ).scalars().all()
    }

    counts = await jobs_domain.queue_stats(db)

    context = {
        "title": "صف کارها",
        "jobs": jobs,
        "requesters": requesters,
        "counts": counts,
        "page": page,
        "query": query,
        "base_path": "/admin/jobs",
        "JOB_TYPE_FA": jobs_domain.JOB_TYPE_FA,
        "JOB_STATUS_FA": jobs_domain.JOB_STATUS_FA,
        "ALL_JOB_TYPES": jobs_domain.ALL_JOB_TYPES,
        "ALL_JOB_STATUSES": jobs_domain.ALL_JOB_STATUSES,
        "STATUS_QUEUED": jobs_domain.STATUS_QUEUED,
        "STATUS_RUNNING": jobs_domain.STATUS_RUNNING,
        "STATUS_FAILED": jobs_domain.STATUS_FAILED,
        "active_nav": "/admin/jobs",
    }
    if is_htmx(request):
        return render(request, "jobs/_rows.html", **context)
    return render(request, "jobs/list.html", **context)


@router.get("/jobs/{job_id}")
async def job_detail(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """One job: its payload, its result, its error, and what it produced.

    The result is where the useful link lives — a finished provision job carries
    the new node's id and custom domain, which is how the operator gets from
    "the job succeeded" to the node it made.
    """
    job = (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if job is None:
        return redirect("/admin/jobs", err="notfound")

    requester = None
    if job.requested_by:
        requester = (
            await db.execute(select(Admin).where(Admin.id == job.requested_by))
        ).scalar_one_or_none()

    return render(
        request,
        "jobs/detail.html",
        title=f"کار {jobs_domain.job_ref(job.id)}",
        job=job,
        requester=requester,
        JOB_TYPE_FA=jobs_domain.JOB_TYPE_FA,
        JOB_STATUS_FA=jobs_domain.JOB_STATUS_FA,
        STATUS_QUEUED=jobs_domain.STATUS_QUEUED,
        STATUS_RUNNING=jobs_domain.STATUS_RUNNING,
        STATUS_FAILED=jobs_domain.STATUS_FAILED,
        STATUS_SUCCEEDED=jobs_domain.STATUS_SUCCEEDED,
        STATUS_CANCELLED=jobs_domain.STATUS_CANCELLED,
        active_nav="/admin/jobs",
    )


@router.post("/jobs/{job_id}/retry")
async def job_retry(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Re-queue a FAILED job with a fresh attempt budget.

    Only FAILED. Retrying a QUEUED job would reset a counter nothing has
    incremented; retrying a SUCCEEDED one would re-run work that already
    happened, which for `provision_node` means a second KV namespace and a
    second worker upload for a node that already exists.
    """
    job = (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if job is None:
        return redirect("/admin/jobs", err="notfound")

    if job.status != jobs_domain.STATUS_FAILED:
        return redirect(f"/admin/jobs/{job_id}", err="not_failed")

    await jobs_domain.retry_job(db, job, actor_id=admin.id)

    await audit(
        db,
        "job.retry",
        actor_id=admin.id,
        target_type="job",
        target_id=job.id,
        details={"job_type": job.job_type, "previous_attempts": job.attempts},
    )
    return redirect(f"/admin/jobs/{job_id}", ok="requeued")


@router.post("/jobs/{job_id}/cancel")
async def job_cancel(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Cancel a QUEUED job. Refuses on a RUNNING one, and says why.

    A running job is inside its handler; flipping the row to CANCELLED would not
    stop it, and the queue would then claim work never happened while the
    Cloudflare calls continue. The honest answer is "wait, or let it finish and
    undo the result".
    """
    job = (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if job is None:
        return redirect("/admin/jobs", err="notfound")

    if job.status == jobs_domain.STATUS_RUNNING:
        return redirect(f"/admin/jobs/{job_id}", err="is_running")

    if job.status in (
        jobs_domain.STATUS_SUCCEEDED,
        jobs_domain.STATUS_FAILED,
        jobs_domain.STATUS_CANCELLED,
    ):
        return redirect(f"/admin/jobs/{job_id}", err="already_finished")

    await jobs_domain.cancel_job(db, job, actor_id=admin.id)

    await audit(
        db,
        "job.cancel",
        actor_id=admin.id,
        target_type="job",
        target_id=job.id,
        details={"job_type": job.job_type},
    )
    return redirect(f"/admin/jobs/{job_id}", ok="cancelled")

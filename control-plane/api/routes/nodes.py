"""Verdent Platform — internal node endpoints (HMAC-authenticated).

Document 5, "Node-to-Control-Plane auth" + replay protection:
- POST /internal/nodes/{node_id}/usage  — append usage events (append-only ledger)
- POST /internal/nodes/{node_id}/health — supplementary health samples

Every request is verified in four steps:
  1. node lookup + state check (DECOMMISSIONED rejected)
  2. timestamp window + HMAC over the raw body
  3. nonce freshness: SET NX against Redis (domain.security.consume_nonce) —
     a nonce is only spent by a request that already carried the node's secret,
     so an attacker without it cannot burn a node's nonces. The price is that
     a node retrying a request whose response was lost is rejected as a replay;
     that is safe because each endpoint is idempotent anyway. See
     settings.node_replay_fail_open for what an unreachable Redis does.
  4. per-endpoint invariants: a usage event may only name a configuration
     assigned to the calling node, and a health sample must advance
     (node_id, check_type) in checked_at.

Endpoint-level idempotency is separate and independent of step 3: usage is
keyed on (connection_id, sequence_number) UNIQUE — a duplicate is acknowledged
with 200 and dropped, never double-counted — and health is a monotonic
checked_at guard, since node_health_samples has no idempotency key.
"""

import logging
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from db.base import get_db
from db.models import ConfigurationNodeAssignment, NodeHealthSample, Node, UsageEvent
from domain.security import (
    NonceStoreUnavailable,
    compute_expected_signature,
    consume_nonce,
    get_redis,
    secure_compare,
    timestamp_within_window,
)

logger = logging.getLogger("verdent.platform.nodes")

# ck_health_samples_check_type in schema.sql / migration 001. Validated here so
# a bad value is a 400 the node can act on, not a 500 from the DB CHECK.
HEALTH_CHECK_TYPES = ("control_plane", "data_plane", "dns")

# Idempotency key for a health sample, the way (connection_id,
# sequence_number) is for a usage event. Checked BEFORE the insert so a bad
# value is still a 400.
HEALTH_SAMPLE_DUP = "uq_health_samples_node_check_time"

# str(asyncpg's UniqueViolationError) -> "duplicate key value violates unique
# constraint \"uq_usage_events_connection_sequence\""; psycopg puts the class
# name up front instead. Keyed on the constraint name rather than the type,
# because a type check would also swallow a duplicate on some other key and
# keep hiding real integrity failures from the node.
PG_DUP_KEY_RE = re.compile(r'duplicate key value violates unique constraint "([^"]+)"')

router = APIRouter(prefix="/internal/nodes", tags=["internal"])


class AuthError(Exception):
    pass


async def verify_node_auth(
    node_id: str,
    request: Request,
    x_verdent_timestamp: str,
    x_verdent_nonce: str,
    x_verdent_signature: str,
    db: AsyncSession,
) -> Node:
    if not timestamp_within_window(x_verdent_timestamp):
        raise AuthError("timestamp outside validity window")

    node = (
        await db.execute(select(Node).where(Node.id == node_id))
    ).scalar_one_or_none()

    if node is None:
        raise AuthError("unknown node")

    if node.state == "DECOMMISSIONED":
        raise AuthError("node is decommissioned")

    expected = compute_expected_signature(
        node_secret_hash=node.node_secret_hash or "",
        node_id=node_id,
        timestamp=x_verdent_timestamp,
        nonce=x_verdent_nonce,
        body=await request.body(),
    )

    if not secure_compare(x_verdent_signature, expected):
        raise AuthError("invalid signature")

    # Past this point the request is genuine, so a second attempt with the same
    # nonce+timestamp+body can only be a replay of it — unless Redis is down,
    # which leaves us unable to tell (see domain.security.consume_nonce).
    if not x_verdent_nonce:
        raise AuthError("missing nonce")

    if not await consume_nonce(get_redis(), node_id, x_verdent_nonce):
        raise NonceStoreUnavailable("nonce already used")

    return node


def _status_for_auth_error(exc: Exception) -> int:
    # A replayed request is a 401: whatever produced it, the caller is not
    # authorized to send it again. Deliberately not a 403, because a node
    # retrying a request whose response was lost looks exactly like a replay
    # and must not be treated as a compromise.
    if isinstance(exc, NonceStoreUnavailable):
        return 401
    return 403


class UsageEventPayload(BaseModel):
    configId: str
    connectionId: str
    sequenceNumber: int
    bytesUp: int
    bytesDown: int
    windowStartedAt: str
    reportedAt: str

    @field_validator("configId", "connectionId")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("sequenceNumber", "bytesUp", "bytesDown")
    @classmethod
    def _non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("must be non-negative")
        return value


class UsageEventAck(BaseModel):
    status: str = "ok"
    dropped: bool = False


USAGE_DUP_KEY = "uq_usage_events_connection_sequence"


def _unique_constraint_names(exc: IntegrityError) -> set[str]:
    """Which unique constraints this IntegrityError actually names.

    Only ever true for a UNIQUE violation; a foreign-key violation (or a
    CHECK, or NOT NULL) matches nothing, so it cannot be mistaken for a
    duplicate and silently dropped.
    """
    match = PG_DUP_KEY_RE.search(str(exc.orig))
    return {match.group(1)} if match else set()


@router.post("/{node_id}/usage")
async def ingest_usage(
    node_id: str,
    payload: UsageEventPayload,
    request: Request,
    x_verdent_timestamp: str = Header(),
    x_verdent_nonce: str = Header(),
    x_verdent_signature: str = Header(),
    db: AsyncSession = Depends(get_db),
) -> UsageEventAck:
    try:
        await verify_node_auth(
            node_id=node_id,
            request=request,
            x_verdent_timestamp=x_verdent_timestamp,
            x_verdent_nonce=x_verdent_nonce,
            x_verdent_signature=x_verdent_signature,
            db=db,
        )
    except (AuthError, NonceStoreUnavailable) as exc:
        raise HTTPException(status_code=_status_for_auth_error(exc), detail=str(exc)) from exc

    # Before the insert, not as an IntegrityError afterwards: a configId the
    # node does not serve must be a 403 the node can see, never a row and never
    # a silent drop. Without this check a compromised node could bill any
    # customer arbitrary traffic until the quota cut them off.
    if not await _node_serves_configuration(db, node_id, payload.configId):
        raise HTTPException(
            status_code=403,
            detail="configuration is not assigned to this node",
        )

    try:
        event = UsageEvent(
            configuration_id=payload.configId,
            node_id=node_id,
            connection_id=payload.connectionId,
            sequence_number=payload.sequenceNumber,
            bytes_up=payload.bytesUp,
            bytes_down=payload.bytesDown,
            window_started_at=datetime.fromisoformat(payload.windowStartedAt),
        )

        db.add(event)
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        if USAGE_DUP_KEY in _unique_constraint_names(exc):
            # (connection_id, sequence_number) already exists — a retried flush.
            # Acknowledge 200 and drop: a duplicate is never an accumulate.
            return UsageEventAck(dropped=True)
        # Anything else (foreign key, CHECK, NOT NULL) is a real failure. It
        # used to be reported as a drop, so a node whose configuration was
        # deleted kept reporting usage and the control plane quietly kept none
        # of it. Surface it as 5xx so the node retries and keeps its buffer.
        logger.exception("usage event for %s failed on node %s", payload.configId, node_id)
        raise HTTPException(status_code=500, detail="failed to append usage event") from exc
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise HTTPException(status_code=500, detail="failed to append usage event") from exc

    return UsageEventAck()


async def _node_serves_configuration(db: AsyncSession, node_id: str, configuration_id: str) -> bool:
    """Is `configuration_id` currently assigned to `node_id`?"""
    assigned = await db.execute(
        select(ConfigurationNodeAssignment.id).where(
            ConfigurationNodeAssignment.configuration_id == configuration_id,
            ConfigurationNodeAssignment.node_id == node_id,
            ConfigurationNodeAssignment.revoked_at.is_(None),
        )
    )
    return assigned.scalar_one_or_none() is not None


class HealthSamplePayload(BaseModel):
    checkType: str
    success: bool
    latencyMs: float | None = None
    jitterMs: float | None = None
    packetLoss: float | None = None
    checkedAt: str | None = None


@router.post("/{node_id}/health")
async def ingest_health(
    node_id: str,
    payload: HealthSamplePayload,
    request: Request,
    x_verdent_timestamp: str = Header(),
    x_verdent_nonce: str = Header(),
    x_verdent_signature: str = Header(),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        await verify_node_auth(
            node_id=node_id,
            request=request,
            x_verdent_timestamp=x_verdent_timestamp,
            x_verdent_nonce=x_verdent_nonce,
            x_verdent_signature=x_verdent_signature,
            db=db,
        )
    except (AuthError, NonceStoreUnavailable) as exc:
        raise HTTPException(status_code=_status_for_auth_error(exc), detail=str(exc)) from exc

    # Validated here, not left to ck_health_samples_check_type: a DB CHECK
    # violation arrives as an IntegrityError, which the node sees as a 500 and
    # cannot act on. An unknown check type is the node's mistake, so 400.
    if payload.checkType not in HEALTH_CHECK_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"checkType must be one of: {', '.join(HEALTH_CHECK_TYPES)}",
        )

    # The node's own clock, not the arrival time: a health pass reads this table
    # to decide when a node went bad, and a backlog flushed after a partition
    # would otherwise look like a burst of fresh failures. Clamped to arrival
    # time so a node with a fast clock cannot fence itself out of its own
    # series and, for a healthy node, pin OFFLINE forever (offline_since is
    # only cleared on a later, genuinely newer sample).
    try:
        checked_at = _parse_timestamp(payload.checkedAt) if payload.checkedAt else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"checkedAt: {exc}") from exc

    now = datetime.now(timezone.utc)
    if checked_at is None or checked_at > now:
        checked_at = now

    # Idempotency. node_health_samples carries no idempotency key, and adding a
    # UNIQUE (node_id, check_type, checked_at) would mean a migration — so the
    # key is enforced here instead: a sample is only new information if it is
    # strictly newer than the last one recorded for the same (node, check). A
    # replay, or any out-of-order straggler, is acknowledged and discarded, so
    # the table cannot be inflated by a compromised node.
    #
    # FOR UPDATE locks the newest row and serialises concurrent writers. It has
    # one gap: when the series has no rows yet there is nothing to lock, so two
    # simultaneous first samples can both land. That is a one-off at the birth
    # of a series, not a growth vector, and closing it properly needs the
    # unique index this deliberately avoids.
    newest = (
        await db.execute(
            select(NodeHealthSample.checked_at)
            .where(
                NodeHealthSample.node_id == node_id,
                NodeHealthSample.check_type == payload.checkType,
            )
            .order_by(NodeHealthSample.checked_at.desc())
            .limit(1)
            .with_for_update()
        )
    ).scalar_one_or_none()

    if newest is not None and checked_at <= newest:
        return {"status": "ok", "dropped": True}

    sample = NodeHealthSample(
        node_id=node_id,
        check_type=payload.checkType,
        success=payload.success,
        latency_ms=payload.latencyMs,
        jitter_ms=payload.jitterMs,
        packet_loss=payload.packetLoss,
        checked_at=checked_at,
    )

    db.add(sample)

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        if HEALTH_SAMPLE_DUP in _unique_constraint_names(exc):
            return {"status": "ok", "dropped": True}
        # Any other IntegrityError means the row was written against a state
        # the node did not know about. Say so — a 500 the node can see beats a
        # 200 that tells it everything is fine.
        logger.exception("health sample for %s failed on node %s", payload.checkType, node_id)
        raise HTTPException(status_code=500, detail="failed to record health sample") from exc

    return {"status": "ok"}


def _parse_timestamp(value: str) -> datetime:
    """ISO-8601 as the rest of the API writes it, always tz-aware UTC.

    An offset-less string is rejected rather than assumed to be UTC: the node's
    clock is only meaningful if we know its zone, and a silent guess would put
    the sample at the wrong end of the monotonic guard.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("must be an ISO-8601 timestamp") from None

    if parsed.tzinfo is None:
        raise ValueError("must include a UTC offset (e.g. 2026-09-25T12:00:00Z)")
    return parsed.astimezone(timezone.utc)

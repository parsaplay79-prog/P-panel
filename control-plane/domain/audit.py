"""Verdent Platform — audit logging (Phase 5, used everywhere).

Every admin/state-changing action appends an audit_log row. Never raises:
auditing must not break the action it records.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AuditLog

logger = logging.getLogger("verdent.audit")


async def audit(
    db: AsyncSession,
    action: str,
    *,
    actor_type: str = "admin",
    actor_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
) -> None:
    try:
        db.add(
            AuditLog(
                actor_type=actor_type,
                actor_id=actor_id,
                action=action,
                target_type=target_type or "",
                target_id=target_id,
                # The dict, NOT json.dumps(...). details_json is a JSONB
                # column: SQLAlchemy serializes it itself, so passing an
                # already-encoded string stores a JSON *string*
                # ("{\"order_id\":...}") instead of a JSON object. Everything
                # downstream — `details_json->>'key'` in SQL, or a reader
                # doing row.details_json["key"] — then silently returns NULL.
                details_json=details or {},
            )
        )
        await db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("audit log failed for action %s", action)
        await db.rollback()

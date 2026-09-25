"""Verdent Platform — usage reconciliation (Phase 5, worker service).

The AFTER-INSERT trigger keeps `usage_daily_aggregates` incrementally fresh.
This job catches drift (manual rows, partial writes): for every
(config, date) present in the ledger, it recomputes the exact daily sums and
upserts them — the aggregate table is always repairable from the append-only
ledger, never the other way around.

COST: the ledger is append-only and never pruned, so an unbounded GROUP BY
re-derives every day since the platform launched, every five minutes, to find
nothing — the read cost grows forever while the write cost is zero after the
first pass. The scan is therefore bounded to a recent window by default, and
the worker does an unbounded pass once a day so a row corrupted by hand is
still repaired eventually.
"""

import logging
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select, text as sql_text

from db.base import SessionLocal
from db.models import UsageDailyAggregate, UsageEvent

logger = logging.getLogger("verdent.reconcile")

RECONCILE_LOOKBACK_DAYS = 7


async def reconcile_usage(*, since: date | None = None) -> dict:
    """Re-derive daily aggregates from the ledger.

    `since` bounds the scan to ledger rows reported on or after that date;
    None means a full pass.
    """
    async with SessionLocal() as db:
        # exact truth from the ledger
        query = (
            select(
                UsageEvent.configuration_id,
                sql_text("(usage_events.reported_at AT TIME ZONE 'UTC')::date AS usage_date"),
                sql_text("COALESCE(SUM(usage_events.bytes_up), 0) AS up"),
                sql_text("COALESCE(SUM(usage_events.bytes_down), 0) AS down"),
            )
            .group_by(
                UsageEvent.configuration_id,
                sql_text("(usage_events.reported_at AT TIME ZONE 'UTC')::date"),
            )
        )
        if since is not None:
            query = query.where(
                UsageEvent.reported_at
                >= datetime(since.year, since.month, since.day, tzinfo=timezone.utc)
            )

        truth = (await db.execute(query)).all()

        repaired = 0
        for config_id, usage_date, up, down in truth:
            up, down = int(up or 0), int(down or 0)
            d = usage_date if isinstance(usage_date, date) else date.fromisoformat(str(usage_date))

            agg = (
                await db.execute(
                    select(UsageDailyAggregate).where(
                        UsageDailyAggregate.configuration_id == config_id,
                        UsageDailyAggregate.usage_date == d,
                    )
                )
            ).scalar_one_or_none()

            expected_total = up + down
            if agg is None:
                db.add(
                    UsageDailyAggregate(
                        configuration_id=config_id,
                        usage_date=d,
                        bytes_up=up,
                        bytes_down=down,
                        total_bytes=expected_total,
                    )
                )
                repaired += 1
            elif (agg.bytes_up, agg.bytes_down, agg.total_bytes) != (up, down, expected_total):
                agg.bytes_up = up
                agg.bytes_down = down
                agg.total_bytes = expected_total
                repaired += 1

        await db.commit()

    result = {"ledger_groups": len(truth), "repaired": repaired, "since": str(since) if since else "full"}
    if repaired:
        logger.info("reconciled %d aggregate row(s)", repaired)
    return result

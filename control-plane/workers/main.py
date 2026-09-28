"""Verdent Platform — worker service entrypoint (Railway service: `worker`).

Per Dockerfile: start = `python -m workers.main`

Responsibilities (Document 6 §N — all sub-5-minute loops live here, not in
Railway cron):
  1. Job queue consumer (provisioning retries — Phase 2)
  2. Usage reconciliation loop (Phase 5 — repairs aggregate drift)
  3. Node health-check loop (Phase 2/3 — hysteresis + failover)
  4. Quota/expiry push loop (Phase 5 — disable over-quota credentials at the edge)
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from db.base import SessionLocal
from db.migrate import run_migrations
from domain.health import HEALTH_CHECK_INTERVAL, health_check_pass
from domain.jobs import job_consumer_pass
from domain.notifications import expiry_and_quota_sweep
from domain.reconcile import RECONCILE_LOOKBACK_DAYS, reconcile_usage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("verdent.worker")

JOB_POLL_INTERVAL = 5            # seconds — a queued node job should start promptly
RECONCILE_INTERVAL = 300          # 5 min
QUOTA_PUSH_INTERVAL = 300         # 5 min
FULL_RECONCILE_INTERVAL = 86400   # once a day: unbounded pass


async def job_queue_loop() -> None:
    """Drain the background queue.

    This used to be a stub that slept for an hour and logged that retries
    "happen via the admin panel" — but the panel had no retry either, so a node
    whose provisioning failed was simply lost. The loop is now real: claim with
    SKIP LOCKED (so the web service's own consumer and this one never collide),
    run, record the outcome.

    Every job opens its own session. A long-lived session in a loop holds a
    connection and a snapshot across minutes of work, and one failed job would
    poison the transaction for the next — `job_consumer_pass` commits per job
    and `run_job` never raises.
    """
    logger.info("job queue consumer started (poll every %ss)", JOB_POLL_INTERVAL)
    while True:
        try:
            async with SessionLocal() as db:
                ran = await job_consumer_pass(db)
            if ran == 0:
                await asyncio.sleep(JOB_POLL_INTERVAL)
        except Exception:  # noqa: BLE001 — the loop must survive anything
            logger.exception("job consumer pass failed")
            await asyncio.sleep(JOB_POLL_INTERVAL)


async def usage_reconcile_loop() -> None:
    """Recent window every tick; the whole ledger once a day.

    The unbounded pass is what actually guarantees "aggregates are always
    repairable from the ledger", but running it every five minutes re-derives
    every day since launch to find nothing. The bounded pass keeps today's
    numbers honest, which is what quota checks read; the daily full pass
    still reaches a row that was corrupted by hand months ago.
    """
    logger.info(
        "reconciliation loop started (every %ss, last %s days; full pass every %ss)",
        RECONCILE_INTERVAL, RECONCILE_LOOKBACK_DAYS, FULL_RECONCILE_INTERVAL,
    )
    last_full: datetime | None = None
    while True:
        try:
            now = datetime.now(timezone.utc)
            if last_full is None or (now - last_full) >= timedelta(seconds=FULL_RECONCILE_INTERVAL):
                await reconcile_usage()          # full pass, `since=None`
                last_full = now
            else:
                await reconcile_usage(since=(now - timedelta(days=RECONCILE_LOOKBACK_DAYS)).date())
        except Exception:  # noqa: BLE001
            logger.exception("reconciliation failed")
        await asyncio.sleep(RECONCILE_INTERVAL)


async def health_loop() -> None:
    logger.info("health loop started (every %ss)", HEALTH_CHECK_INTERVAL)
    while True:
        try:
            await health_check_pass()
        except Exception:  # noqa: BLE001
            logger.exception("health pass failed")
        await asyncio.sleep(HEALTH_CHECK_INTERVAL)


async def quota_push_loop() -> None:
    logger.info("quota/expiry push loop started (every %ss)", QUOTA_PUSH_INTERVAL)
    while True:
        try:
            await expiry_and_quota_sweep()
        except Exception:  # noqa: BLE001
            logger.exception("quota sweep failed")
        await asyncio.sleep(QUOTA_PUSH_INTERVAL)


async def main() -> None:
    logger.info("verdent worker starting")
    # The web service also migrates on boot, and all three start at once on
    # deploy. run_migrations takes the same advisory lock, so whichever service
    # wins migrates and the others block until it finishes. Not fatal if the web
    # service already did it — command.upgrade is a no-op at head.
    await run_migrations()
    await asyncio.gather(
        job_queue_loop(),
        usage_reconcile_loop(),
        health_loop(),
        quota_push_loop(),
    )


if __name__ == "__main__":
    asyncio.run(main())

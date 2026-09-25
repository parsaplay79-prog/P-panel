"""Verdent Platform — Telegram webhook route.

POST /webhook/{secret} — the path secret IS the first auth layer; Telegram's
X-Telegram-Bot-Api-Secret-Token header (set at registration) is the second.
No secret, no service.
"""

import logging

from fastapi import APIRouter, Header, HTTPException, Request

from domain.config import settings
from domain.security import get_redis

logger = logging.getLogger("verdent.bot.webhook")

router = APIRouter(tags=["telegram"])

UPDATE_DEDUPE_PREFIX = "tg:update:"
# Telegram redelivers an unacknowledged update with exponential backoff over
# several minutes; 15 min covers the whole retry window with room to spare.
UPDATE_DEDUPE_TTL_SECONDS = 900


async def _claim_update(update_id: int) -> bool:
    """True if this update has not been handled yet.

    Telegram re-sends an update whenever our 200 does not reach it in time,
    and it re-sends the SAME update_id. The dispatcher has no dedupe of its
    own, so a redelivered callback runs the whole handler again: a customer
    pressing "buy" once can end up with two orders, and a re-delivered
    receipt re-runs provisioning.

    Fails OPEN — the opposite of the node-ingest nonce store, deliberately.
    There, an unrecorded nonce could mean forged traffic, so refusing is
    right. Here the worst case of a Redis outage is that a rare redelivery
    is processed twice, while failing closed would silently drop every
    update and take the entire bot down for as long as Redis is missing.
    """
    try:
        stored = await get_redis().set(
            f"{UPDATE_DEDUPE_PREFIX}{update_id}",
            "1",
            nx=True,
            ex=UPDATE_DEDUPE_TTL_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 — any Redis failure is unavailability
        logger.warning(
            "update dedupe unavailable (%s); processing update %s without "
            "dedupe — a redelivery could be handled twice",
            exc,
            update_id,
        )
        return True
    return stored is not None


@router.post("/webhook/{secret_token}")
async def telegram_webhook(
    secret_token: str,
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
):
    if secret_token != settings.telegram_webhook_secret_token:
        raise HTTPException(status_code=403, detail="forbidden")

    if settings.telegram_webhook_secret_token and (
        x_telegram_bot_api_secret_token != settings.telegram_webhook_secret_token
    ):
        raise HTTPException(status_code=403, detail="forbidden")

    if not settings.telegram_bot_token:
        raise HTTPException(status_code=503, detail="bot disabled")

    update_json = await request.json()

    from aiogram.types import Update

    try:
        update = Update.model_validate(update_json, context={"bot": None})
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="bad update")

    if not await _claim_update(update.update_id):
        logger.info("duplicate update %s ignored", update.update_id)
        return {"ok": True}

    from bot import webhook as bot_webhook

    if bot_webhook.bot is None:
        from aiogram import Bot
        from aiogram.client.default import DefaultBotProperties
        from aiogram.enums import ParseMode

        bot_webhook.bot = Bot(
            token=settings.telegram_bot_token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        )

    await bot_webhook.dp.feed_update(bot_webhook.bot, update)
    return {"ok": True}

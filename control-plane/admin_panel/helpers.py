"""Verdent Platform — helpers shared by every admin panel route.

Three things every page needs and none of them should reimplement:

  * `render` — one wrapper over `TemplateResponse` so the HTMX-vs-full-page
    decision and the flash messages are handled identically everywhere;
  * `flash` — redirect with a message code, read back on the next render;
  * `notify_customer` — the Telegram send, best-effort, reusing the bot's own
    templates so the customer cannot tell which surface the admin used.

`flash` uses query parameters rather than a session cookie. The panel has no
server-side session store (the cookie is a signed bearer token and nothing
else), and a flash message is not worth adding one — a redirect carrying
`?ok=approved` is idempotent, survives a refresh honestly (the message stays
until you navigate away), and cannot desynchronize from the page it belongs to.
"""

import logging
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import RedirectResponse

from admin_panel.templating import templates

logger = logging.getLogger("verdent.admin_panel")


def render(request: Request, template: str, *, status_code: int = 200, **context):
    return templates.TemplateResponse(request, template, context, status_code=status_code)


def partial(request: Request, template: str, *, status_code: int = 200, **context):
    """Render a fragment for HTMX to swap in.

    Same function as `render` — the distinction is the template, which for a
    partial extends nothing. Kept as a separate name so a route reads as what
    it is doing and a partial cannot accidentally be served as a full page.
    """
    return templates.TemplateResponse(request, template, context, status_code=status_code)


def redirect(path: str, **params) -> RedirectResponse:
    """303 to `path` with non-empty params as a query string."""
    clean = {k: v for k, v in params.items() if v not in (None, "")}
    if clean:
        from urllib.parse import urlencode

        path = f"{path}?{urlencode(clean)}"
    return RedirectResponse(path, status_code=303)


async def notify_customer(telegram_user_id: int, text: str) -> bool:
    """Best-effort Telegram delivery. Never raises.

    Reuses `bot.webhook.send_message` — the same helper the bot uses — so a
    message sent from the panel is indistinguishable from one sent from
    Telegram. A Telegram outage must not roll back a decision the admin has
    already made; the audit row is the durable record.
    """
    from bot.webhook import send_message

    try:
        await send_message(telegram_user_id, text)
        return True
    except Exception:  # noqa: BLE001 — send_message is documented never to raise
        logger.exception("customer notification failed for %s", telegram_user_id)
        return False


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def fmt_dt(value: datetime | None, *, with_time: bool = True) -> str:
    """Persian-friendly timestamp, UTC. Empty string for None.

    Deliberately UTC and labelled as such in the template rather than converted:
    the server has no reliable notion of the operator's timezone, and a
    timestamp silently rendered in the wrong zone is worse than one that says
    which zone it is.
    """
    if value is None:
        return "—"
    if with_time:
        return value.strftime("%Y-%m-%d %H:%M")
    return value.strftime("%Y-%m-%d")

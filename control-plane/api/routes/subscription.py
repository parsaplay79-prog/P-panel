"""Verdent Platform — public subscription endpoint (Document 3 §L).

GET /s/{subscription_token}
  - auth by capability token only (rotatable independently of proxy creds)
  - returns base64 vless:// URI list + standard subscription headers
  - subscription-userinfo carries upload/download/total/expire from the
    usage ledger (Document 3 §L)
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.base import get_db
from db.models import Configuration
from domain.subscriptions import (
    active_assignments,
    build_subscription_body,
    render_vless_uri,
    usage_current_period_detail,
)

router = APIRouter(tags=["subscriptions"])


@router.get("/s/{subscription_token}")
async def get_subscription(
    subscription_token: str,
    user_agent: str | None = Header(default=None, alias="User-Agent"),
    db: AsyncSession = Depends(get_db),
) -> Response:
    config = (
        await db.execute(
            select(Configuration).where(
                Configuration.subscription_token == subscription_token
            )
        )
    ).scalar_one_or_none()

    if config is None or config.status == "DELETED":
        raise HTTPException(status_code=404, detail="not found")

    # The credential handed out below is a working proxy login. A config that
    # is not ACTIVE must not receive one: an EXPIRED or SUSPENDED customer
    # fetching their link would otherwise get a live vless:// URI and keep
    # using the service for free. The empty 200 (rather than a 404) is
    # deliberate — clients treat a non-200 as a fetch failure and keep showing
    # their cached, still-working config, so the update has to succeed and
    # carry nothing.
    if config.status != "ACTIVE":
        return Response(
            content="",
            headers={"content-type": "text/plain; charset=utf-8"},
        )

    # Expiry is NOT written here. Doing so made this endpoint the second
    # writer of the EXPIRED transition, and because the sweep only selects
    # ACTIVE configs, a config expired here disappeared from the sweep before
    # it could disable the customer's edge credential — leaving the proxy
    # relaying traffic for a subscription that had ended. The sweep now owns
    # the whole transition (status + edge KV) in one place.

    assignments = await active_assignments(db, config)
    uris = [
        render_vless_uri(
            node.custom_domain or "",
            str(assignment.proxy_uuid),
            config.display_name,
        )
        for assignment, node in assignments
        if node.custom_domain
    ]

    _used, bytes_up, bytes_down, quota = await usage_current_period_detail(db, config)

    # upload/download are per-direction, NOT the period total in both fields.
    # Clients draw two bars and sum them; duplicating the total made every
    # client show double the real usage.
    userinfo_parts = [f"upload={bytes_up}", f"download={bytes_down}", f"total={quota or 0}"]
    if config.expires_at:
        userinfo_parts.append(f"expire={int(config.expires_at.timestamp())}")

    headers = {
        "content-type": "text/plain; charset=utf-8",
        "profile-title": config.display_name,
        "profile-update-interval": "6",
        "subscription-userinfo": "; ".join(userinfo_parts),
    }

    body = build_subscription_body(uris) if uris else ""
    return Response(content=body, headers=headers)

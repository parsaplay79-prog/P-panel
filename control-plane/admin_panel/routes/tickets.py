"""Support tickets — the queue, one thread, reply, close.

The bot already had tickets; this page is the same conversation on a real
keyboard, with the customer's context next to it. That context is the reason the
page exists: answering "why is my config not working" from the bot means
switching to a second surface to look at the config, and from here the
customer's configs, orders and current usage are one click away.

Ticket resolution goes through `domain.support.ticket_by_ref`, which is shared
with the bot and returns None on an *ambiguous* prefix as well as a missing one.
That rule is not duplicated here on purpose: an 8-hex-character prefix can
collide across the table, and resolving it to the wrong ticket would show one
customer another customer's private messages.

Replying notifies the customer with the bot's own message template, so the
customer sees the same formatting whether the answer came from Telegram or from
here.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import notify_customer, redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import Customer, SupportMessage, SupportTicket
from domain import rbac
from domain import support as support_domain
from domain.audit import audit

logger = logging.getLogger("verdent.admin_panel.tickets")

router = APIRouter()

TICKET_STATUS_FA = {
    support_domain.STATUS_OPEN: "باز",
    support_domain.STATUS_ANSWERED: "پاسخ داده شده",
    support_domain.STATUS_CLOSED: "بسته",
}

TICKET_STATUS_TAG = {
    support_domain.STATUS_OPEN: "tag-warn",
    support_domain.STATUS_ANSWERED: "tag-ok",
    support_domain.STATUS_CLOSED: "",
}

SORT_COLUMNS = {
    "updated": SupportTicket.updated_at,
    "created": SupportTicket.created_at,
    "status": SupportTicket.status,
}


@router.get("/tickets")
async def tickets_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    """Tickets awaiting a customer, newest first. CLOSED is excluded by default.

    A closed ticket that the customer reopens comes back as `open` via
    `derive_status`, so nothing is lost by not showing closed ones in the queue —
    and a queue that includes finished work stops being a queue.
    """
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="updated",
        filter_keys=("status",),
    )

    stmt = select(SupportTicket, Customer).join(
        Customer, Customer.id == SupportTicket.customer_id
    )
    count_stmt = select(func.count()).select_from(SupportTicket)

    conditions = []
    status_filter = query.filters.get("status")
    if status_filter in TICKET_STATUS_FA:
        conditions.append(SupportTicket.status == status_filter)
    elif status_filter == "all":
        pass
    else:
        conditions.append(
            SupportTicket.status.in_([support_domain.STATUS_OPEN, support_domain.STATUS_ANSWERED])
        )

    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(func.cast(SupportTicket.id, Text)).like(f"{query.q.lower()}%"),
                func.lower(SupportTicket.subject).like(pattern),
                func.lower(func.cast(Customer.telegram_user_id, Text)).like(pattern),
                func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
            )
        )

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    rows = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).all()

    items = [
        {"ticket": ticket, "customer": customer, "ref": support_domain.ticket_ref(ticket.id)}
        for ticket, customer in rows
    ]

    # Message counts, grouped — the queue shows "how much has been said" as a
    # hint at which thread is live without opening each one.
    message_counts = dict(
        (
            await db.execute(
                select(SupportMessage.ticket_id, func.count(SupportMessage.id)).group_by(
                    SupportMessage.ticket_id
                )
            )
        ).all()
    )

    context = {
        "title": "تیکت‌های پشتیبانی",
        "items": items,
        "message_counts": {k: int(v) for k, v in message_counts.items()},
        "page": page,
        "query": query,
        "base_path": "/admin/tickets",
        "TICKET_STATUS_FA": TICKET_STATUS_FA,
        "TICKET_STATUS_TAG": TICKET_STATUS_TAG,
        "active_nav": "/admin/tickets",
    }
    if is_htmx(request):
        return render(request, "tickets/_rows.html", **context)
    return render(request, "tickets/list.html", **context)


async def _load_thread(db: AsyncSession, ref: str):
    """(ticket, customer, messages) for a short ref, or (None, None, []).

    Resolution — including the ambiguity rule — lives in
    `domain.support.ticket_by_ref`, shared with the bot.
    """
    ticket = await support_domain.ticket_by_ref(db, ref)
    if ticket is None:
        return None, None, []

    customer = (
        await db.execute(select(Customer).where(Customer.id == ticket.customer_id))
    ).scalar_one_or_none()

    messages = (
        await db.execute(
            select(SupportMessage)
            .where(SupportMessage.ticket_id == ticket.id)
            .order_by(SupportMessage.created_at.asc())
        )
    ).scalars().all()
    return ticket, customer, messages


@router.get("/tickets/{ref}")
async def ticket_detail(
    ref: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    ticket, customer, messages = await _load_thread(db, ref)
    if ticket is None:
        return redirect("/admin/tickets", err="notfound")

    # The customer's live configs, so the reply can be written with the actual
    # state in front of the operator rather than after switching pages.
    from db.models import Configuration
    from domain import configurations as config_domain
    from domain import customers as customer_domain

    configs = (
        await db.execute(
            select(Configuration)
            .where(Configuration.customer_id == ticket.customer_id)
            .order_by(Configuration.created_at.desc())
            .limit(20)
        )
    ).scalars().all()

    return render(
        request,
        "tickets/detail.html",
        title=f"تیکت {ref}",
        ticket=ticket,
        customer=customer,
        messages=messages,
        configs=configs,
        ref=ref,
        TICKET_STATUS_FA=TICKET_STATUS_FA,
        TICKET_STATUS_TAG=TICKET_STATUS_TAG,
        CONFIG_STATUS_FA=config_domain.CONFIG_STATUS_FA,
        # `detail.html` labels the customer's own status next to the ticket
        # status, the same mapping the customers page renders. The template
        # environment is StrictUndefined, so omitting it 500s this page.
        CUSTOMER_STATUS_FA=customer_domain.CUSTOMER_STATUS_FA,
        active_nav="/admin/tickets",
    )


@router.post("/tickets/{ref}/reply")
async def ticket_reply(
    ref: str,
    body: str = Form(""),
    close_after: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    """Append an admin reply and notify the customer.

    `author_telegram_id`, not the admin row id: the column is defined as a
    Telegram id on purpose, and an admin replying here is the same person who
    replies from Telegram — recording a uuid there would make the two paths
    write different-looking rows for the same human.

    `close_after` is a checkbox on the reply form rather than a second button,
    because the common case is "here is the answer, and we are done" and doing
    it in one action avoids a state where the reply is sent but the ticket sits
    open waiting for someone to close it.
    """
    body = body.strip()
    if not body:
        return redirect(f"/admin/tickets/{ref}", err="empty")

    ticket, customer, _messages = await _load_thread(db, ref)
    if ticket is None:
        return redirect("/admin/tickets", err="notfound")

    await support_domain.add_message(db, ticket, "admin", admin.telegram_user_id, body)

    if close_after:
        await support_domain.close_ticket(db, ticket)

    await audit(
        db,
        "support.reply",
        actor_id=admin.id,
        target_type="support_ticket",
        target_id=ticket.id,
        details={"ref": ref, "closed": bool(close_after)},
    )

    if customer is not None:
        await notify_customer(customer.telegram_user_id, _reply_message(ref, body))

    return redirect(f"/admin/tickets/{ref}", ok="replied")


@router.post("/tickets/{ref}/close")
async def ticket_close(
    ref: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    """Close a ticket. A later customer message reopens it (`derive_status`)."""
    ticket, customer, _messages = await _load_thread(db, ref)
    if ticket is None:
        return redirect("/admin/tickets", err="notfound")

    if ticket.status == support_domain.STATUS_CLOSED:
        return redirect(f"/admin/tickets/{ref}", ok="already_closed")

    await support_domain.close_ticket(db, ticket)

    await audit(
        db,
        "support.close",
        actor_id=admin.id,
        target_type="support_ticket",
        target_id=ticket.id,
        details={"ref": ref},
    )

    if customer is not None:
        await notify_customer(
            customer.telegram_user_id,
            f"🔒 تیکت <code>{ref}</code> بسته شد. اگر سؤال دیگری دارید، تیکت جدیدی باز کنید.",
        )

    return redirect(f"/admin/tickets/{ref}", ok="closed")


def _reply_message(ref: str, body: str) -> str:
    """The customer-facing notice, using the bot's own template.

    Imported from `bot/texts.py` rather than written here so a reply sent from
    the panel and one sent from Telegram render identically — the customer has
    no way to tell the surfaces apart, and a second copy of the copy would
    eventually drift.
    """
    from bot import texts

    return texts.MSG_SUPPORT_ADMIN_TICKET_ANSWER.format(
        ref=ref,
        status_fa=texts.SUPPORT_STATUS_FA.get(
            support_domain.STATUS_ANSWERED, support_domain.STATUS_ANSWERED
        ),
        transcript=texts.MSG_SUPPORT_ADMIN_TRANSCRIPT_ITEM.format(
            author="پشتیبانی",
            when=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            body=body,
        ),
    )

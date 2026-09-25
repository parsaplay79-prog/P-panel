"""Verdent Platform — support tickets (Phase 6).

The support button used to print static text and stop there. A customer who
followed its instruction ("پیام بگذارید") sent their message into a void:
nothing was stored, no admin was told, and the customer had no id to quote
when they followed up. This module is the durable half of the fix — the
telegram layer creates and renders, but the rules live here so they can be
tested without a bot.

Status is a three-value machine, deliberately not free-form:

  open      a customer message is unanswered
  answered  an admin has replied since the customer's last message
  closed    an admin closed it; the customer can still reopen by writing

`answered` exists because "open" cannot express it: without it, an admin reply
followed by a customer follow-up is indistinguishable from one with no reply
at all, and the admin queue cannot tell a solved ticket from a live one.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import SupportMessage, SupportTicket

logger = logging.getLogger("verdent.support")

STATUS_OPEN = "open"
STATUS_ANSWERED = "answered"
STATUS_CLOSED = "closed"

ALL_STATUSES = (STATUS_OPEN, STATUS_ANSWERED, STATUS_CLOSED)

MAX_SUBJECT_LEN = 120


def derive_status(ticket: SupportTicket, added_by: str) -> str:
    """The status a ticket takes when a message with this author is added.

    Pure so the machine can be tested exhaustively without a database:

      customer message  -> open  (an answer is stale the moment a new
                                   question arrives)
      admin message     -> answered, unless the ticket is closed — closing is
                                   deliberate and a stray reply must not
                                   silently reopen it
    """
    if added_by == "customer":
        return STATUS_OPEN
    if ticket.status == STATUS_CLOSED:
        return STATUS_CLOSED
    return STATUS_ANSWERED


async def create_ticket(
    db: AsyncSession,
    customer_id: str,
    telegram_user_id: int,
    body: str,
    subject: str = "",
) -> SupportTicket:
    """Open a ticket with its first customer message, and return it."""
    ticket = SupportTicket(
        customer_id=customer_id,
        subject=subject[:MAX_SUBJECT_LEN],
        status=STATUS_OPEN,
    )
    db.add(ticket)
    # Flush so the ticket has an id before the message references it; without
    # this the message insert fails on a null foreign key at commit time,
    # after the caller has already been told the ticket exists.
    await db.flush()

    db.add(
        SupportMessage(
            ticket_id=ticket.id,
            author_type="customer",
            author_telegram_id=telegram_user_id,
            body=body,
        )
    )
    await db.commit()
    await db.refresh(ticket)
    logger.info("support ticket %s opened by %s", ticket.id[:8], telegram_user_id)
    return ticket


async def add_message(
    db: AsyncSession,
    ticket: SupportTicket,
    author_type: str,
    author_telegram_id: int,
    body: str,
) -> SupportTicket:
    """Append a message and move the ticket to the status that author implies.

    `ticket` must already belong to the session — the caller has just loaded
    it, so re-fetching would only risk reading a stale row.
    """
    if author_type not in ("customer", "admin"):
        raise ValueError(f"author_type must be customer or admin, got {author_type!r}")

    db.add(
        SupportMessage(
            ticket_id=ticket.id,
            author_type=author_type,
            author_telegram_id=author_telegram_id,
            body=body,
        )
    )
    ticket.status = derive_status(ticket, author_type)
    # updated_at is what both queues order by, and the column default is
    # server-side now() — so a message can be added to a ticket that then
    # sorts as older than a ticket nobody has written to. Stamped here.
    ticket.updated_at = datetime.now(timezone.utc)
    if author_type == "admin":
        ticket.last_admin_reply_at = ticket.updated_at
    await db.commit()
    await db.refresh(ticket)
    return ticket


async def close_ticket(db: AsyncSession, ticket: SupportTicket) -> SupportTicket:
    """Close a ticket. A later customer message reopens it (see derive_status)."""
    ticket.status = STATUS_CLOSED
    ticket.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(ticket)
    return ticket


async def ticket_by_ref(db: AsyncSession, ref: str) -> SupportTicket | None:
    """Resolve the 8-character ref shown in a callback to its ticket.

    The id column is `uuid`, and Postgres has no `uuid LIKE text` operator —
    `SupportTicket.id.like(f"{ref}%")` renders as a statement that dies with
    "operator does not exist: uuid ~~* unknown", which is the same class of
    error as the bigint-vs-varchar bug this project already hit once. The id
    is cast to text for the comparison instead.

    Returns None when the prefix is not unique, not just when it matches
    nothing: a 8-hex-character prefix is short enough that a collision across
    the table is not the customer's fault, and resolving it to the wrong
    ticket would show one customer another customer's private messages.
    """
    rows = (
        await db.execute(
            select(SupportTicket).where(
                cast(SupportTicket.id, String).like(f"{ref}%")
            )
        )
    ).scalars().all()
    if len(rows) != 1:
        if len(rows) > 1:
            logger.warning(
                "support ref %r matched %d tickets; treating as not-found",
                ref,
                len(rows),
            )
        return None
    return rows[0]


async def customer_tickets(db: AsyncSession, customer_id: str) -> list[SupportTicket]:
    """The customer's tickets, newest first, for the support menu."""
    return list(
        (
            await db.execute(
                select(SupportTicket)
                .where(SupportTicket.customer_id == customer_id)
                .order_by(SupportTicket.updated_at.desc())
            )
        ).scalars().all()
    )


async def open_tickets(db: AsyncSession) -> list[SupportTicket]:
    """Tickets awaiting a customer, newest first — the admin queue.

    CLOSED is excluded: a closed ticket that the customer reopened comes back
    as `open` via derive_status, so nothing is lost by not showing closed ones.
    """
    return list(
        (
            await db.execute(
                select(SupportTicket)
                .where(SupportTicket.status.in_([STATUS_OPEN, STATUS_ANSWERED]))
                .order_by(SupportTicket.updated_at.desc())
            )
        ).scalars().all()
    )


def ticket_ref(ticket_id: str) -> str:
    """The short id shown to humans. SupportTicket ids are UUIDs, so the
    customer quoting "8f3a1c" is quoting the same thing an admin sees."""
    return ticket_id[:8]

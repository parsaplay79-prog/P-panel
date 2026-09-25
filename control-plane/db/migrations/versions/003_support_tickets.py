"""support tickets: persist the conversation the support button used to swallow

The support menu answered with static copy telling the customer to leave a
message, and then dropped it. Nothing was stored, no admin was notified, and
the customer had no ticket id to quote on a follow-up — a button that reads
like a workflow but is not one.

Two tables, because the conversation is append-only and two-sided. One table
with last_message columns would lose the customer's original question the
moment an admin replied.

Revision ID: 003
Revises: 002
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: str = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "support_tickets",
        sa.Column("id", postgresql.UUID(as_uuid=False), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("customer_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("subject", sa.Text(), server_default="", nullable=False),
        sa.Column("status", sa.Text(), server_default="open", nullable=False),
        sa.Column("last_admin_reply_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("status IN ('open', 'answered', 'closed')", name="ck_support_tickets_status"),
        sa.ForeignKeyConstraint(["customer_id"], ["customers.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_support_tickets_customer", "support_tickets", ["customer_id"])
    op.create_index("idx_support_tickets_status", "support_tickets", ["status"])

    op.create_table(
        "support_messages",
        sa.Column("id", postgresql.UUID(as_uuid=False), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("ticket_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("author_type", sa.Text(), nullable=False),
        sa.Column("author_telegram_id", sa.BigInteger(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("author_type IN ('customer', 'admin')", name="ck_support_messages_author_type"),
        sa.ForeignKeyConstraint(["ticket_id"], ["support_tickets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_support_messages_ticket", "support_messages", ["ticket_id"])


def downgrade() -> None:
    # Messages first: they carry the foreign key. Dropping the parent while
    # the child still references it is exactly the kind of thing that makes a
    # downgrade look like it worked and leave the schema broken.
    op.drop_index("idx_support_messages_ticket", table_name="support_messages")
    op.drop_table("support_messages")

    op.drop_index("idx_support_tickets_status", table_name="support_tickets")
    op.drop_index("idx_support_tickets_customer", table_name="support_tickets")
    op.drop_table("support_tickets")

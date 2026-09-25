"""audit_log: allow a customer as the actor of a customer-initiated change

audit_log.actor_type was constrained to ('admin', 'system'), which is correct
for every action the platform had until now: admins act, and the system acts on
its own. A customer renaming their own configuration is neither, and the two
dishonest options are both worse than widening the constraint —

  * actor_type='admin' would attribute a customer's action to an admin, which
    is exactly the kind of record that misleads an investigation;
  * actor_type='system' would say the platform did it, hiding the real actor.

The trap is that `domain.audit.audit()` catches every exception and logs it
rather than raising, so writing an out-of-range actor_type would not surface as
an error anywhere — the row would simply never appear, and the rename would
look unaudited. Widening the CHECK is what makes the record possible at all.

Widening a CHECK never fails on existing rows, so this is safe to apply to a
populated table.

Revision ID: 004
Revises: 003
"""

from alembic import op

revision: str = "004"
down_revision: str = "003"
branch_labels = None
depends_on = None

_CONSTRAINT = "ck_audit_log_actor_type"


def upgrade() -> None:
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.create_check_constraint(
        _CONSTRAINT,
        "audit_log",
        "actor_type IN ('admin', 'system', 'customer')",
    )


def downgrade() -> None:
    # Narrowing back is NOT safe on data written after this migration: any row
    # with actor_type='customer' would violate the restored constraint and the
    # ALTER would fail. Delete or reclassify those rows first — deliberately
    # not done automatically, because silently rewriting an audit record to
    # make a downgrade succeed is worse than the failed downgrade.
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.create_check_constraint(
        _CONSTRAINT,
        "audit_log",
        "actor_type IN ('admin', 'system')",
    )

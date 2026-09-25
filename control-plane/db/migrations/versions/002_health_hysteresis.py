"""health hysteresis: persist the counters that make OFFLINE reachable

The health loop opens a new session every pass, so the consecutive-failure
counter lived only on the ORM object and always read back as 0. That made
DEGRADED (2 failures) and OFFLINE (5 failures) unreachable, and left
failover_offline_nodes() — which selects on state == 'OFFLINE' — as dead
code. A node could die and keep serving customers indefinitely.

offline_since is the second half of the same bug: the old code approximated
"has been offline for 10 minutes" using the most recent FAILED sample, but a
failed sample is written every 60 seconds, so that timestamp was never more
than a minute old and the gate never opened. Persisting the moment the node
went OFFLINE is the only way to express "stayed offline".

Revision ID: 002
Revises: 001
"""

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: str = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "nodes",
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "nodes",
        sa.Column("consecutive_successes", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "nodes",
        sa.Column("offline_since", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("nodes", "offline_since")
    op.drop_column("nodes", "consecutive_successes")
    op.drop_column("nodes", "consecutive_failures")

"""jobs: a real background queue for slow, retryable work

Provisioning a node is the job this table was built for. Document 1 §M:

    "This is a state-machine-driven background job (Document 3, background
    worker), not a single long-running request — provisioning can legitimately
    take tens of seconds (Worker deployment propagation isn't instant), which
    doesn't belong in the request/response cycle of an admin API call."

Before this migration the panel did the forbidden thing: `POST /admin/nodes/new`
awaited `provision_node()` inline for up to two minutes. Three concrete failures
came out of that, none of them theoretical:

  * a Railway proxy timeout mid-provision left a KV namespace and a worker
    script deployed on Cloudflare with NO `nodes` row — invisible to the panel,
    un-deletable from it, and the next attempt collided with the script name;
  * the browser showed a spinner with no progress and no way to tell "still
    working" from "hung";
  * nothing retried. `provision_node` was called once from a request handler, so
    a transient Cloudflare 500 was terminal.

`idempotency_key` UNIQUE is the column that makes Document 1 §M's "safe to
retry" real. A job's key names the work, not the attempt: re-submitting the
form, a retried HTTP request, or a consumer that crashed after claiming all
produce the same key, and `enqueue` returns the existing row rather than
creating a second job.

`requested_by` is nullable and points at `admins.id`, so the queue view can show
which operator asked for a node. Nullable because a job may be enqueued by a
system path (the cron sweep re-queueing a stuck order) with no human behind it.

Revision ID: 006
Revises: 005
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "006"
down_revision: str = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", UUID(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("job_type", sa.Text(), nullable=False),
        sa.Column("payload_json", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.Text(), nullable=False, server_default="QUEUED"),
        sa.Column("idempotency_key", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("result_json", JSONB(), nullable=True),
        sa.Column("requested_by", UUID(as_uuid=False), sa.ForeignKey("admins.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELLED')",
            name="ck_jobs_status",
        ),
    )
    # UNIQUE, not merely indexed: this constraint IS the dedupe. Without it two
    # concurrent submissions both insert and both provision.
    op.create_index("uq_jobs_idempotency_key", "jobs", ["idempotency_key"], unique=True)
    op.create_index("idx_jobs_status_created", "jobs", ["status", "created_at"])


def downgrade() -> None:
    # Dropping this table abandons any work still queued. The rows are a record
    # of what was asked for and what happened; a downgrade loses that, and the
    # in-flight Cloudflare resources it was creating are left half-made with
    # nothing left to point at them. Stated plainly rather than compensated for.
    op.drop_index("idx_jobs_status_created", table_name="jobs")
    op.drop_index("uq_jobs_idempotency_key", table_name="jobs")
    op.drop_table("jobs")

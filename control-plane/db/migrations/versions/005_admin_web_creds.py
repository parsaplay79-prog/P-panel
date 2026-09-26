"""admin web credentials: give the panel its own login, separate from Telegram

The web Admin Panel had no way in. Every admin action lived behind the Telegram
bot, so an operator without a Telegram client open — or whose bot token was
misconfigured — could not review a payment, answer a support ticket, or add a
node. The panel routes existed in the plan and nowhere in the code.

Three columns rather than a new table, because an admin IS one person with one
role: a separate `admin_web_users` table would let the same human hold two
roles and make "what can this admin do" ambiguous. `web_username` and
`web_password_hash` are nullable so the two kinds of admin coexist — a
Telegram-only admin simply has no web login, and adding these columns does not
invalidate the bootstrap OWNER row that `ensure_bootstrap_owner` created from
TELEGRAM_OWNER_ID before any web account existed.

`token_version` is what makes logout actually revoke. A signed session cookie
is a bearer token: clearing the browser cookie does not stop a copy of it from
working until it expires. Bumping this integer invalidates every session issued
before the bump, which is the only way to kill a leaked cookie — so it is
NOT NULL with a default, and every session carries the version it was issued
at.

A UNIQUE constraint on a nullable column is deliberate: Postgres allows many
NULLs in a unique index, so every Telegram-only admin keeps web_username NULL
without colliding, while any two admins who do have web logins cannot share a
username.

Revision ID: 005
Revises: 004
"""

from alembic import op
import sqlalchemy as sa

revision: str = "005"
down_revision: str = "004"
branch_labels = None
depends_on = None

_USERNAME_CONSTRAINT = "uq_admins_web_username"


def upgrade() -> None:
    op.add_column("admins", sa.Column("web_username", sa.Text(), nullable=True))
    op.add_column("admins", sa.Column("web_password_hash", sa.Text(), nullable=True))
    op.add_column(
        "admins",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_unique_constraint(_USERNAME_CONSTRAINT, "admins", ["web_username"])


def downgrade() -> None:
    # Dropping these columns destroys the only credential an admin has for the
    # web panel. There is no way to recover the password hashes, and the
    # usernames are gone too, so a downgrade leaves every admin with a Telegram
    # login and no web login. Deliberately not compensated for: a downgrade
    # that silently kept a copy of the hashes somewhere would be a worse
    # surprise than an empty login.
    op.drop_constraint(_USERNAME_CONSTRAINT, "admins", type_="unique")
    op.drop_column("admins", "token_version")
    op.drop_column("admins", "web_password_hash")
    op.drop_column("admins", "web_username")

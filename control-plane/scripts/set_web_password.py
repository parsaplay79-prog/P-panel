"""Set (or rotate) the web Admin Panel credentials for one admin.

Run this once after the first deploy, and again whenever an admin needs a web
login or a new password:

    cd control-plane
    python scripts/set_web_password.py --telegram-id 123456789 --username owner

You will be prompted for the password twice; it is never echoed, never taken
from an argument (an argument lands in shell history and in `ps` output), and
never logged.

On Railway, where there is no interactive terminal for the first run:

    railway ssh --service web
    cd /app && python scripts/set_web_password.py --telegram-id 123456789 \
        --username owner --password-stdin <<'EOF'
    <the password>
    EOF

Why a script and not a page in the panel: the panel has no unauthenticated
"create the first admin" page on purpose. Anyone who reached such a page before
the real owner did would become OWNER, which is the whole privilege-escalation
hole this design avoids. The first credential therefore has to be set by
someone who already has shell access to the deployment — which is exactly the
person who owns it.

The script only ever UPDATES an existing admin row. It does not create admins:
an admin without a Telegram identity could not be created from the bot and
would be invisible to it, and the bootstrap OWNER already exists by the time
this is needed. Create the admin first (bot `/admin` → افزودن ادمین, or the
panel's ادمین‌ها page), then give it a web login here.
"""

import argparse
import asyncio
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from admin_panel.auth import hash_password  # noqa: E402
from db.base import SessionLocal  # noqa: E402
from db.models import Admin  # noqa: E402
from domain.audit import audit  # noqa: E402
from domain.config import settings  # noqa: E402

MIN_PASSWORD_LENGTH = 12


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        # One line, read without echo and without a prompt — the only form that
        # works over `railway ssh` with a heredoc.
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            sys.exit("ERROR: no password on stdin")
        return password

    first = getpass.getpass("New password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        sys.exit("ERROR: the two passwords do not match")
    return first


def _validate(username: str, password: str) -> None:
    username = username.strip()
    if not username:
        sys.exit("ERROR: username must not be empty")
    if " " in username or "$" in username:
        # `$` is a hazard in shell heredocs and in some .env loaders; a space
        # makes the value unquotable in most of the places it gets pasted.
        sys.exit("ERROR: username must not contain spaces or '$'")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"ERROR: password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.strip() != password:
        sys.exit("ERROR: password must not begin or end with whitespace")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Set web Admin Panel credentials for an admin.")
    parser.add_argument(
        "--telegram-id",
        default=str(settings.telegram_owner_id or ""),
        help="the admin's numeric Telegram id (defaults to TELEGRAM_OWNER_ID)",
    )
    parser.add_argument("--username", required=True, help="web login username")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin instead of prompting (for non-interactive shells)",
    )
    parser.add_argument(
        "--rotate-sessions",
        action="store_true",
        help="also bump token_version, signing out every existing web session",
    )
    args = parser.parse_args()

    if not args.telegram_id or not str(args.telegram_id).strip().isdigit():
        sys.exit(
            "ERROR: --telegram-id is required and must be numeric "
            "(or set TELEGRAM_OWNER_ID)"
        )
    telegram_id = int(str(args.telegram_id).strip())

    username = args.username.strip()
    password = _read_password(args)
    _validate(username, password)

    async with SessionLocal() as db:
        admin = (
            await db.execute(select(Admin).where(Admin.telegram_user_id == telegram_id))
        ).scalar_one_or_none()

        if admin is None:
            sys.exit(
                f"ERROR: no admin with telegram_user_id={telegram_id}.\n"
                "Create the admin first (bot: /admin → افزودن ادمین), then run this again."
            )

        # Username uniqueness is enforced by the database, but a clear message
        # beats a raw IntegrityError for the one case an operator will actually
        # hit: reusing a name that belongs to someone else.
        clash = (
            await db.execute(
                select(Admin).where(Admin.web_username == username, Admin.id != admin.id)
            )
        ).scalar_one_or_none()
        if clash is not None:
            sys.exit(f"ERROR: username {username!r} is already used by another admin")

        had_login = bool(admin.web_username)
        admin.web_username = username
        admin.web_password_hash = hash_password(password)

        if args.rotate_sessions:
            # Invalidates every cookie already issued to this admin, including
            # ones copied out of a browser. Bumped explicitly rather than on
            # every password change, so a routine rotation does not silently
            # sign the operator out of the session they are working in.
            admin.token_version = (admin.token_version or 1) + 1

        await db.commit()

        await audit(
            db,
            "admin.web_credentials_set",
            actor_type="system",
            actor_id=None,
            target_type="admin",
            target_id=admin.id,
            details={
                "username": username,
                "role": admin.role,
                "created_login": not had_login,
                "sessions_rotated": bool(args.rotate_sessions),
            },
        )

    # Never print the password, and never print the hash. The username and the
    # admin's identity are enough to confirm the right row was updated.
    print(f"OK — web login set for admin telegram_user_id={telegram_id} (role from the DB)")
    print(f"     username: {username}")
    print(f"     password: set ({len(password)} characters)")
    if args.rotate_sessions:
        print("     all existing web sessions for this admin are now invalid")
    print("\nSign in at: <your-subscription-base-url>/admin/login")


if __name__ == "__main__":
    asyncio.run(main())

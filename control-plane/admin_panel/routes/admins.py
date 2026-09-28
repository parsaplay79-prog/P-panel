"""Admins — who can sign in, what they may do, and how to cut them off.

Gated on `admin.manage`, which only OWNER holds (`ROLE_ADMIN` deliberately
excludes it). That single fact is what makes it safe for this page to include
password setting, which `scripts/set_web_password.py` deliberately refuses to do
from a web surface: the script's concern was an *unauthenticated* bootstrap page
("anyone who reached it before the real owner would become OWNER"), and this is
the opposite — an authenticated page that only the OWNER can open.

The panel manages web credentials now because the alternative was a Railway SSH
session for every routine admin change. The bootstrap case is unchanged: the
first OWNER still has to be created by someone with shell access, because there
is no way to reach this page before one exists.

**Revoking sessions** is `token_version`. Every cookie carries the version it
was issued at, `require_admin` compares it against the row on every request, and
bumping the integer invalidates every outstanding cookie for that admin on their
next request. It is the only lever that exists for "this person's laptop was
stolen" and it has to be one click, not a database edit.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import Admin
from domain import rbac
from domain.audit import audit

logger = logging.getLogger("verdent.admin_panel.admins")

router = APIRouter()

MIN_PASSWORD_LENGTH = 12

SORT_COLUMNS = {
    "created": Admin.created_at,
    "role": Admin.role,
    "telegram": Admin.telegram_user_id,
}


def _validate_web_credentials(
    username: str, password: str, confirm: str
) -> tuple[str, str, str]:
    """(username, password, error_code). Mirrors scripts/set_web_password.py.

    The username rules are the script's, not invented here: `$` is a hazard in
    shell heredocs and some .env loaders, and a space makes the value unquotable
    wherever it gets pasted. Two surfaces writing the same column must agree on
    what a legal value is.
    """
    username = username.strip()
    if not username:
        return "", "", "username_required"
    if " " in username or "$" in username:
        return "", "", "username_invalid"
    if len(username) > 64:
        return "", "", "username_too_long"

    if password != confirm:
        return "", "", "password_mismatch"
    if len(password) < MIN_PASSWORD_LENGTH:
        return "", "", "password_too_short"
    if len(password) > 512:
        return "", "", "password_too_long"

    return username, password, ""


@router.get("/admins")
async def admins_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("role",),
    )

    stmt = select(Admin)
    count_stmt = select(func.count()).select_from(Admin)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        from sqlalchemy import Text, or_

        conditions.append(
            or_(
                func.lower(func.cast(Admin.telegram_user_id, Text)).like(pattern),
                func.lower(func.coalesce(Admin.web_username, "")).like(pattern),
            )
        )
    if query.filters.get("role") in rbac.ALL_ROLES:
        conditions.append(Admin.role == query.filters["role"])

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    admins = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).scalars().all()

    context = {
        "title": "ادمین‌ها",
        "admins": admins,
        "page": page,
        "query": query,
        "base_path": "/admin/admins",
        "ROLE_PERMISSIONS": rbac.ROLE_PERMISSIONS,
        "ALL_ROLES": rbac.ALL_ROLES,
        "signed_in_id": admin.id,
        "active_nav": "/admin/admins",
    }
    if is_htmx(request):
        return render(request, "admins/_rows.html", **context)
    return render(request, "admins/list.html", **context)


@router.get("/admins/new")
async def admin_new_form(
    request: Request,
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    return render(
        request,
        "admins/form.html",
        title="افزودن ادمین",
        ALL_ROLES=rbac.ALL_ROLES,
        ROLE_PERMISSIONS=rbac.ROLE_PERMISSIONS,
        active_nav="/admin/admins",
    )


@router.post("/admins/new")
async def admin_create(
    telegram_user_id: str = Form(""),
    role: str = Form(""),
    web_username: str = Form(""),
    password: str = Form(""),
    confirm: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    """Create an admin, optionally with a web login in the same step.

    The Telegram id is required and the web login is optional, which is the
    reverse of what a generic user form would do — and it is deliberate.
    `Admin.telegram_user_id` is NOT NULL and unique, and it is the identity the
    bot gates on: an admin who exists only as a web login could not be reached
    by the bot and could not be created from it. The web login is an *addition*
    to a Telegram identity, never a substitute.

    Both parts are validated before anything is written, so a bad password does
    not leave behind an admin row the operator has to notice and clean up.
    """
    telegram_user_id = telegram_user_id.strip()
    web_username = web_username.strip()

    def _fail(code: str):
        return redirect("/admin/admins/new", err=code, tid=telegram_user_id, role=role)

    if not telegram_user_id.isdigit():
        return _fail("bad_telegram_id")

    if role not in rbac.ALL_ROLES:
        return _fail("bad_role")

    existing = (
        await db.execute(
            select(Admin).where(Admin.telegram_user_id == int(telegram_user_id))
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _fail("telegram_exists")

    password_hash = None
    if web_username or password:
        # Either both or neither. A username with no password is an account
        # nobody can sign into; a password with no username is unreachable.
        if not web_username or not password:
            return _fail("credentials_incomplete")

        web_username, password, error = _validate_web_credentials(
            web_username, password, confirm
        )
        if error:
            return _fail(error)

        clash = (
            await db.execute(
                select(Admin).where(func.lower(Admin.web_username) == web_username.lower())
            )
        ).scalar_one_or_none()
        if clash is not None:
            return _fail("username_taken")

        password_hash = auth.hash_password(password)

    new_admin = Admin(
        telegram_user_id=int(telegram_user_id),
        role=role,
        created_by=admin.id,
        web_username=web_username or None,
        web_password_hash=password_hash,
    )
    db.add(new_admin)
    await db.commit()

    # target_id is the new admin's UUID, not the Telegram id: audit_log.target_id
    # is a uuid column and audit() swallows its own failures, so passing the
    # digit string would not raise anywhere visible — it would simply never
    # write the row.
    await audit(
        db,
        "admin.create",
        actor_id=admin.id,
        target_type="admin",
        target_id=new_admin.id,
        details={
            "role": role,
            "telegram_user_id": int(telegram_user_id),
            "has_web_login": bool(password_hash),
        },
    )

    return redirect("/admin/admins", ok="created")


@router.post("/admins/{admin_id}/role")
async def admin_set_role(
    admin_id: str,
    role: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    """Change an admin's role. Refuses to demote the last OWNER.

    `admin.manage` is held by OWNER alone, so demoting the final OWNER would
    leave nobody able to administer admins — an unrecoverable lockout that no
    amount of access elsewhere in the panel can undo. The count is taken inside
    the same statement that would perform the change.
    """
    target = (await db.execute(select(Admin).where(Admin.id == admin_id))).scalar_one_or_none()
    if target is None:
        return redirect("/admin/admins", err="notfound")

    if role not in rbac.ALL_ROLES:
        return redirect("/admin/admins", err="bad_role")

    if target.role == role:
        return redirect("/admin/admins", ok="role_unchanged")

    if target.role == rbac.ROLE_OWNER:
        owners = int(
            (
                await db.execute(
                    select(func.count()).select_from(Admin).where(Admin.role == rbac.ROLE_OWNER)
                )
            ).scalar_one()
        )
        if owners <= 1:
            return redirect("/admin/admins", err="last_owner")

    previous = target.role
    target.role = role
    # A role change must take effect on the very next request, not when the
    # cookie expires: the admin's permission set is derived from the row, and
    # `require_admin` re-reads it, but bumping the version also forces a fresh
    # sign-in so a demoted admin's cached page state cannot be acted on.
    target.token_version = (target.token_version or 1) + 1
    await db.commit()

    await audit(
        db,
        "admin.role_change",
        actor_id=admin.id,
        target_type="admin",
        target_id=target.id,
        details={"from": previous, "to": role},
    )
    return redirect("/admin/admins", ok="role_changed")


@router.post("/admins/{admin_id}/credentials")
async def admin_set_credentials(
    admin_id: str,
    web_username: str = Form(""),
    password: str = Form(""),
    confirm: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    """Set or rotate an admin's web login. Bumps `token_version`.

    The bump is not optional and not a side effect: a password change that left
    the old session working would be a password change that did not take effect
    for the one person who already had access. Every other cookie for this admin
    dies on its next request.

    An empty username clears the web login entirely — the admin keeps their
    Telegram identity and loses the web one. That is a real operation (someone
    leaving the web-facing team) and it is why the username field is allowed to
    be blank here but not on the create form.
    """
    target = (await db.execute(select(Admin).where(Admin.id == admin_id))).scalar_one_or_none()
    if target is None:
        return redirect("/admin/admins", err="notfound")

    web_username = web_username.strip()

    if not web_username:
        # Clearing the login. `require_admin` refuses any session whose admin
        # has no web_username, so bumping the version is belt and braces.
        target.web_username = None
        target.web_password_hash = None
        target.token_version = (target.token_version or 1) + 1
        await db.commit()

        await audit(
            db,
            "admin.web_login_removed",
            actor_id=admin.id,
            target_type="admin",
            target_id=target.id,
            details={},
        )
        return redirect("/admin/admins", ok="login_removed")

    web_username, password, error = _validate_web_credentials(web_username, password, confirm)
    if error:
        return redirect("/admin/admins", err=error)

    clash = (
        await db.execute(
            select(Admin).where(
                func.lower(Admin.web_username) == web_username.lower(),
                Admin.id != target.id,
            )
        )
    ).scalar_one_or_none()
    if clash is not None:
        return redirect("/admin/admins", err="username_taken")

    target.web_username = web_username
    target.web_password_hash = auth.hash_password(password)
    target.token_version = (target.token_version or 1) + 1
    await db.commit()

    # The password is never audited, not even its length. An audit row is read
    # by more people than the secret is.
    await audit(
        db,
        "admin.credentials_set",
        actor_id=admin.id,
        target_type="admin",
        target_id=target.id,
        details={"username": web_username},
    )
    return redirect("/admin/admins", ok="credentials_set")


@router.post("/admins/{admin_id}/revoke-sessions")
async def admin_revoke_sessions(
    admin_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    """Invalidate every outstanding cookie for one admin, without a password change.

    Separate from the credentials button because the situations differ: a lost
    laptop needs the sessions killed *now*, and forcing a password rotation on
    the admin at the same moment is a second problem to solve. Bumping the
    version alone achieves the revoke.
    """
    target = (await db.execute(select(Admin).where(Admin.id == admin_id))).scalar_one_or_none()
    if target is None:
        return redirect("/admin/admins", err="notfound")

    target.token_version = (target.token_version or 1) + 1
    await db.commit()

    await audit(
        db,
        "admin.sessions_revoked",
        actor_id=admin.id,
        target_type="admin",
        target_id=target.id,
        details={"token_version": target.token_version},
    )

    if target.id == admin.id:
        # The admin just revoked their own session. Sending them to the login
        # page is honest — their next request would 401 otherwise, with no
        # explanation.
        response = redirect("/admin/login", ok="sessions_revoked")
        auth.clear_session_cookie(response)
        return response

    return redirect("/admin/admins", ok="sessions_revoked")


@router.post("/admins/{admin_id}/delete")
async def admin_delete(
    admin_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    """Remove an admin. Refuses self-deletion and the last OWNER.

    Both refusals are lockouts. Deleting yourself mid-session is recoverable
    only if another OWNER exists; deleting the last OWNER is not recoverable at
    all from inside the product.

    Rows this admin authored are NOT deleted — `orders`, `audit_log`,
    `payment_attempts.reviewed_by` and `jobs.requested_by` all reference admins,
    and a deletion that cascaded would erase the record of who approved what.
    `audit_log.actor_id` is a bare uuid with no FK precisely so history survives.
    """
    target = (await db.execute(select(Admin).where(Admin.id == admin_id))).scalar_one_or_none()
    if target is None:
        return redirect("/admin/admins", err="notfound")

    if target.id == admin.id:
        return redirect("/admin/admins", err="self_delete")

    if target.role == rbac.ROLE_OWNER:
        owners = int(
            (
                await db.execute(
                    select(func.count()).select_from(Admin).where(Admin.role == rbac.ROLE_OWNER)
                )
            ).scalar_one()
        )
        if owners <= 1:
            return redirect("/admin/admins", err="last_owner")

    role = target.role
    telegram_user_id = target.telegram_user_id
    username = target.web_username
    await db.delete(target)
    await db.commit()

    await audit(
        db,
        "admin.delete",
        actor_id=admin.id,
        target_type="admin",
        target_id=admin_id,
        details={"role": role, "telegram_user_id": telegram_user_id, "username": username},
    )
    return redirect("/admin/admins", ok="deleted")

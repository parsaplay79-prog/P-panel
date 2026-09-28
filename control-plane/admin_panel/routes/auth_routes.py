"""Login and logout. The only routes in the panel reachable without a session."""

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.helpers import render
from db.base import get_db
from db.models import Admin

logger = logging.getLogger("verdent.admin_panel.auth")

router = APIRouter()


@router.get("/login")
async def login_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Login page — or the dashboard, if the visitor is already signed in.

    The cookie is VALIDATED here rather than merely checked for presence. A
    presence check would create a redirect loop the moment anyone arrived with
    a stale or revoked cookie: login sees a cookie and redirects to /admin,
    /admin rejects it and redirects back to login, forever. A bad cookie is
    cleared instead so the form is actually reachable.
    """
    token = request.cookies.get(auth.COOKIE_NAME)
    if token:
        claims = auth.read_session_token(token)
        if claims is not None:
            admin_id, token_version = claims
            admin = (
                await db.execute(select(Admin).where(Admin.id == admin_id))
            ).scalar_one_or_none()
            if (
                admin is not None
                and admin.token_version == token_version
                and admin.web_username
            ):
                return RedirectResponse("/admin/", status_code=303)

    return render(request, "login.html", title="ورود")


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    username = username.strip()

    failures = await auth.login_failure_count(username)
    if failures >= auth.LOGIN_MAX_FAILURES:
        return render(
            request,
            "login.html",
            title="ورود",
            error=(
                "تلاش‌های ناموفق بیش از حد مجاز. "
                f"{auth.LOGIN_FAILURE_WINDOW_SECONDS // 60} دقیقه دیگر دوباره امتحان کنید."
            ),
            username=username,
        )

    admin = (
        await db.execute(select(Admin).where(Admin.web_username == username))
    ).scalar_one_or_none()

    # Verify against a dummy hash when the username is unknown, so a failed
    # login costs the same time either way. Returning early here would let an
    # attacker enumerate valid usernames by response time alone.
    stored = admin.web_password_hash if admin is not None else auth.dummy_password_hash()
    if not auth.verify_password(password, stored) or admin is None:
        await auth.record_login_failure(username)
        return render(
            request,
            "login.html",
            title="ورود",
            error="نام کاربری یا رمز عبور نادرست است.",
            username=username,
        )

    await auth.clear_login_failures(username)

    response = RedirectResponse("/admin/", status_code=303)
    auth.set_session_cookie(response, admin)
    logger.info("admin %s signed in to the web panel", admin.id)
    return response


@router.post("/logout")
async def logout(request: Request, admin: Admin = Depends(auth.require_admin)):
    response = RedirectResponse("/admin/login", status_code=303)
    auth.clear_session_cookie(response)
    logger.info("admin %s signed out of the web panel", admin.id)
    return response

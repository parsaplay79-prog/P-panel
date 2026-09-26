"""Verdent Platform — Jinja environment and shared template context.

One place where templates get the things every admin page needs: the signed-in
admin, their permission set (so the nav can hide what they cannot use), the
Persian formatters, and the status dictionaries.

The formatters and dictionaries are IMPORTED from `bot/texts.py` rather than
copied. The bot and the panel show the same customer the same numbers and the
same statuses; a second copy of `format_price` is a second chance for the two
surfaces to disagree, and the customer sees both.
"""

from pathlib import Path

from fastapi import Request
from starlette.templating import Jinja2Templates

from bot import texts as bot_texts
from domain import rbac

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _static_url(path: str) -> str:
    # No cache-busting hash: the panel is small and the CSS changes with the
    # templates it styles, so a stale stylesheet after a deploy is a real
    # possibility. A short max-age (set by the StaticFiles mount) plus an
    # explicit version query keeps a redeploy visible without a build step.
    return f"/admin/static/{path}"


def _nav_items(perms: set[str]) -> list[dict[str, str]]:
    """The sidebar, filtered by permission.

    The same permission set the bot's `keyboards.admin_panel` gates its buttons
    with, so a SUPPORT admin sees the same four things in both places. Hiding a
    link is not the access control — every route re-checks its own permission —
    but a visible link that 403s is a bug report waiting to happen.
    """
    items: list[dict[str, str]] = []

    def add(href: str, label: str, icon: str, permission: str | None = None) -> None:
        if permission is None or permission in perms:
            items.append({"href": href, "label": label, "icon": icon})

    add("/admin", "وضعیت سیستم", "📊", rbac.PERM_STATS_VIEW)
    add("/admin/orders", "سفارش‌های در انتظار", "🧾", rbac.PERM_PAYMENT_REVIEW)
    add("/admin/tickets", "تیکت‌های پشتیبانی", "🆘", rbac.PERM_SUPPORT_MANAGE)
    add("/admin/nodes", "نودها", "🖥", rbac.PERM_NODE_MANAGE)
    add("/admin/nodes/new", "ساخت نود جدید", "➕", rbac.PERM_NODE_MANAGE)
    add("/admin/test", "کانفیگ تستی", "🧪", rbac.PERM_TEST_CONFIG)
    add("/admin/admins", "ادمین‌ها", "👑", rbac.PERM_ADMIN_MANAGE)
    return items


def _context(request: Request) -> dict:
    admin = getattr(request.state, "admin", None)
    perms = rbac.permissions_for(admin.role) if admin is not None else set()
    return {
        "admin": admin,
        "perms": perms,
        "nav": _nav_items(perms),
        "app_name": bot_texts.APP_NAME,
        # Persian rendering of every status a page can show. Imported, not
        # duplicated — see the module docstring.
        "STATUS_FA": bot_texts.STATUS_FA,
        "SUPPORT_STATUS_FA": bot_texts.SUPPORT_STATUS_FA,
        "format_price": bot_texts.format_price,
        "format_traffic": bot_texts.format_traffic,
        "format_duration": bot_texts.format_duration,
        "ROLES": rbac.ALL_ROLES,
        "MSG_ADMIN_FORBIDDEN": bot_texts.MSG_ADMIN_FORBIDDEN,
    }


templates = Jinja2Templates(directory=str(TEMPLATES_DIR), context_processors=[_context])

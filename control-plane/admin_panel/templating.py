"""Verdent Platform — Jinja environment and shared template context.

One place where templates get the things every admin page needs: the signed-in
admin, their permission set (so the nav can hide what they cannot use), the
Persian formatters, the status dictionaries, and the flash message.

The formatters and dictionaries are IMPORTED from `bot/texts.py` rather than
copied. The bot and the panel show the same customer the same numbers and the
same statuses; a second copy of `format_price` is a second chance for the two
surfaces to disagree, and the customer sees both.

**The nav is grouped, and that is the point.** The previous panel had seven flat
links and no structure — the same seven the bot's inline keyboard had. A panel
with twenty-one pages needs a sidebar an operator can scan by area of
responsibility, which is also how the roles are cut: SUPPORT sees the customer
group, FINANCE the money group, INFRASTRUCTURE the hardware group. Grouping by
permission set rather than by page type means a role sees one contiguous block
of the sidebar, not a scattered handful.

**Flash messages are a dictionary, not a template branch.** Every route in the
panel redirects with `?ok=<code>` or `?err=<code>` (see
`admin_panel.helpers.redirect`), and there are ~100 distinct codes. Resolving
them here means the wording lives in one file instead of being re-invented as an
`{% if code == %}` ladder in every template, and a route that adds a code
without adding a sentence gets a visible placeholder rather than a silent
nothing.
"""

from pathlib import Path
from urllib.parse import parse_qsl

from fastapi import Request
from starlette.templating import Jinja2Templates

from bot import texts as bot_texts
from domain import rbac

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# Bumped whenever admin.css or admin.js changes. The panel has no build step, so
# this query string is the only cache-buster there is; a redeploy that changes
# the stylesheet without changing this ships a stale one.
ASSET_VERSION = "3"


# ---------------------------------------------------------------------------
# Flash messages
# ---------------------------------------------------------------------------

# Success codes. Kept short: the page the admin lands on already shows the new
# state, so the message confirms rather than explains.
FLASH_OK: dict[str, str] = {
    "activated": "فعال شد.",
    "already_closed": "این تیکت از قبل بسته بود.",
    "already_decommissioned": "این نود از قبل برچیده شده بود.",
    "already_fulfilled": "این سفارش از قبل تکمیل شده بود.",
    "already_refunded": "این پرداخت از قبل بازپرداخت شده بود.",
    "approved": "پرداخت تأیید و اشتراک ساخته شد.",
    "banned": "مشتری مسدود شد — {n} کانفیگ از {of} کانفیگ فعال متوقف شد.",
    "cancelled": "لغو شد.",
    "capacity_changed": "ظرفیت نود به‌روزرسانی شد.",
    "closed": "تیکت بسته شد.",
    "created": "ساخته شد.",
    "credential_rotated": "کلید جدید ساخته شد. مشتری باید کانفیگ را دوباره وارد کند.",
    "credentials_set": "نام کاربری و رمز عبور ذخیره شد؛ همه‌ی نشست‌های قبلی این ادمین باطل شد.",
    "deactivated": "غیرفعال شد.",
    "deleted": "حذف شد.",
    "disabled": "غیرفعال شد.",
    "enabled": "فعال شد.",
    "extended": "تاریخ انقضا تمدید شد.",
    "link_rotated": "لینک اشتراک جدید ساخته شد. اتصال فعلی مشتری قطع نمی‌شود.",
    "login_removed": "ورود وب این ادمین حذف شد.",
    "node_added": "نود به استخر اضافه شد.",
    "node_removed": "نود از استخر حذف شد.",
    "notified": "پیام برای مشتری ارسال شد.",
    "pools_repaired": "اتصال استخرها بررسی شد — {n} استخر اضافه شد.",
    "published": "نسخه‌ی {v} منتشر شد و از این پس اعمال می‌شود.",
    "queued": "در صف کارها قرار گرفت. نتیجه در همین صفحه قابل پیگیری است.",
    "reactivated": "کانفیگ دوباره فعال شد.",
    "reconciled": "بازبینی انجام شد — {repaired} ردیف اصلاح شد.",
    "refunded": "بازپرداخت ثبت شد و اشتراک مربوطه غیرفعال شد.",
    "rename_failed": "تغییر نام انجام نشد.",
    "refunded_no_revoke": "بازپرداخت ثبت شد ولی اشتراک غیرفعال نشد — مشتری همچنان آنلاین است.",
    "rejected": "پرداخت رد شد و به مشتری اطلاع داده شد.",
    "renamed": "نام کانفیگ تغییر کرد.",
    "replied": "پاسخ ارسال شد.",
    "requeued": "کار دوباره در صف قرار گرفت.",
    "restored": "تنظیمات نسخه‌ی قبلی به‌عنوان نسخه‌ی {v} منتشر شد.",
    "retried": "فعال‌سازی با موفقیت تکمیل شد.",
    "revoked": "کانفیگ برای همیشه لغو شد.",
    "role_changed": "نقش تغییر کرد و نشست‌های قبلی آن ادمین باطل شد.",
    "role_unchanged": "نقش تغییری نکرد.",
    "sessions_revoked": "همه‌ی نشست‌های فعال باطل شد. برای ادامه دوباره وارد شوید.",
    "state_changed": "وضعیت نود به {to} تغییر کرد.",
    "suspended": "کانفیگ معلق شد.",
    "test_created": "کانفیگ تستی ساخته و لینک آن برای مشتری ارسال شد.",
    "unbanned": "رفع مسدودی انجام شد. کانفیگ‌های معلق به‌صورت خودکار فعال نشدند.",
    "updated": "تغییرات ذخیره شد.",
}

# Failure codes. These explain *why*, because the operator's next action depends
# on it — "the name is taken" and "the name is invalid" need different fixes.
FLASH_ERR: dict[str, str] = {
    "account_ambiguous": "این توکن به چند حساب دسترسی دارد. شناسه‌ی حساب را دستی وارد کنید: {detail}",
    "account_busy": "این حساب {n} نود فعال دارد. ابتدا آن‌ها را برچینید یا منتقل کنید.",
    "account_exists": "این حساب از قبل ثبت شده است ({detail}).",
    "already": "این مورد از قبل بررسی شده است.",
    "already_active": "این مشتری یک کانفیگ تستی فعال دارد؛ تا پایان آن صبر کنید.",
    "already_current": "این نسخه همین حالا فعال است.",
    "already_finished": "این کار تمام شده و قابل لغو نیست.",
    "bad_account": "حساب Cloudflare انتخاب‌شده معتبر نیست.",
    "bad_backups": "تعداد نود پشتیبان باید عددی بین ۰ و ۱۰ باشد.",
    "bad_cap": "سقف مشتری هر نود باید عددی بین ۱ و ۱۰۰۰ باشد.",
    "bad_capacity": "ظرفیت باید عددی بین ۱ و ۱۰۰۰ باشد.",
    "bad_days": "تعداد روز باید بین ۱ و ۳۶۵ باشد.",
    "bad_devices": "تعداد دستگاه باید عددی بین ۱ و ۱۰۰ باشد.",
    "bad_duration": "مدت اشتراک باید عددی بین ۱ و ۳۶۵۰ روز باشد.",
    "bad_health": "حد سلامت باید عددی بین ۰ و ۱۰۰ باشد.",
    "bad_id": "شناسه‌ی عددی تلگرام معتبر نیست.",
    "bad_name": "نام نود باید با حرف کوچک یا رقم شروع شود و فقط شامل حرف کوچک، رقم و خط تیره باشد.",
    "bad_node": "نود انتخاب‌شده معتبر نیست.",
    "bad_pool": "استخر انتخاب‌شده معتبر نیست.",
    "bad_price": "قیمت باید عددی بزرگ‌تر از صفر باشد.",
    "bad_quota": "حجم باید عدد باشد (خالی = نامحدود).",
    "bad_role": "نقش انتخاب‌شده معتبر نیست.",
    "bad_state": "این وضعیت از پنل قابل تنظیم نیست.",
    "bad_strategy": "روش انتخاب نود معتبر نیست.",
    "bad_telegram_id": "شناسه‌ی تلگرام باید فقط رقم باشد.",
    "code": "خطای اعتبارسنجی. مقادیر را بررسی کنید.",
    "config_deleted": "کانفیگ حذف‌شده قابل تغییر نیست.",
    "config_no_live_assignment": "این کانفیگ اتصال فعالی روی نود ندارد، پس چیزی برای چرخاندن نیست.",
    "config_not_reactivatable": "کانفیگ منقضی یا حذف‌شده دوباره فعال نمی‌شود. برای کانفیگ منقضی از «تمدید» استفاده کنید.",
    "credentials_incomplete": "برای ساخت ورود وب، نام کاربری و رمز عبور هر دو لازم است.",
    "decommissioned": "این نود برچیده شده و قابل تغییر نیست.",
    "empty": "متن پیام خالی است.",
    "empty_message": "متن پیام خالی است.",
    "error": "درخواست انجام نشد. مقادیر را بررسی کنید.",
    "failed": "عملیات با خطا مواجه شد: {detail}",
    "fulfillment": "فعال‌سازی کامل نشد: {detail} — کار در صف قرار گرفت و به‌صورت خودکار تلاش می‌شود.",
    "has_nodes": "این مورد {n} نود دارد؛ ابتدا آن‌ها را جابه‌جا یا برچینید.",
    "has_orders": "این پلن {n} سفارش ثبت‌شده دارد و قابل حذف نیست. به‌جای حذف، آن را غیرفعال کنید.",
    "has_plans": "این استخر {n} پلن دارد و قابل حذف نیست.",
    "honesty": "این تنظیمات قابلیتی را فعال می‌کند که Cloudflare Workers از آن پشتیبانی نمی‌کند: {keys}",
    "is_deleted": "کانفیگ حذف‌شده قابل تمدید نیست.",
    "is_running": "کار در حال اجراست و لغو نمی‌شود. اجازه دهید تمام شود، سپس نتیجه را برگردانید.",
    "label_required": "برچسب حساب الزامی است.",
    "last_in_pool": "این آخرین پلن فعال این استخر است؛ غیرفعال کردن آن منوی خرید را خالی می‌کند.",
    "last_owner": "این تنها OWNER باقی‌مانده است؛ این کار شما را از پنل بیرون می‌اندازد.",
    "limit": "سقف کانفیگ تستی این مشتری پر شده ({n} از {cap}).",
    "missing_scopes": "توکن این دسترسی‌ها را ندارد: {detail}",
    "name_required": "نام الزامی است.",
    "name_invalid": "نام کانفیگ نامعتبر است: فقط حروف، رقم و خط تیره؛ نباید با رقم شروع شود.",
    "name_taken": "این نام قبلاً استفاده شده است.",
    "notify_failed": "ارسال پیام به مشتری ناموفق بود. ممکن است ربات را بلاک کرده باشد؛ رویداد در گزارش ثبت شد.",
    "name_too_long": "نام بیش از حد بلند است (حداکثر ۶۰ کاراکتر).",
    "no_account_scope": "این توکن به هیچ حسابی دسترسی ندارد. توکنی با دسترسی Workers بسازید یا شناسه‌ی حساب را دستی وارد کنید.",
    "no_encryption_key": "کلید رمزنگاری توکن‌های Cloudflare تنظیم نشده است (CLOUDFLARE_TOKEN_ENCRYPTION_KEY).",
    "no_node": "هیچ نود واجد شرایطی برای ساخت کانفیگ تستی وجود ندارد.",
    "node_busy": "این نود {n} مشتری فعال دارد. ابتدا وضعیت آن را تعمیرات کنید تا تخلیه شود.",
    "not_cancellable": "این سفارش پرداخت شده و لغو نمی‌شود؛ برای بازگرداندن وجه از بخش پرداخت‌ها استفاده کنید.",
    "not_failed": "فقط کارهای ناموفق قابل تلاش دوباره هستند.",
    "not_provisioning": "این سفارش در وضعیت فعال‌سازی نیست.",
    "not_refundable": "فقط پرداخت‌های تأییدشده قابل بازپرداخت هستند.",
    "notfound": "موردی با این شناسه پیدا نشد.",
    "password_mismatch": "رمز عبور و تکرار آن یکسان نیستند.",
    "password_too_long": "رمز عبور بیش از حد بلند است.",
    "password_too_short": "رمز عبور باید حداقل ۱۲ کاراکتر باشد.",
    "self_delete": "نمی‌توانید حساب خودتان را حذف کنید.",
    "settings_not_object": "تنظیمات باید یک شیء JSON باشد ({...}).",
    "settings_required": "تنظیمات الزامی است.",
    "telegram_exists": "ادمینی با این شناسه‌ی تلگرام از قبل وجود دارد.",
    "token_invalid": "توکن Cloudflare معتبر نیست: {detail}",
    "token_required": "توکن API الزامی است.",
    "username_invalid": "نام کاربری نباید فاصله یا $ داشته باشد.",
    "username_required": "نام کاربری الزامی است.",
    "username_taken": "این نام کاربری قبلاً انتخاب شده است.",
    "username_too_long": "نام کاربری بیش از حد بلند است.",
    "verify_error": "بررسی توکن با Cloudflare ممکن نشد: {detail}",
}

# Error codes that carry a JSON parse position, e.g. `bad_json:3:14`.
_BAD_JSON_PREFIX = "bad_json:"


def _resolve_flash(params: dict[str, str]) -> dict | None:
    """Turn a redirect's query parameters into one flash message.

    `err` wins over `ok`: a redirect never carries both, but if one ever did,
    showing the failure is the safe choice.

    Extra parameters (`n`, `of`, `v`, `detail`, `keys`, `to`, `cap`, `repaired`)
    are substituted into the sentence. A code that is not in either dictionary
    renders as itself in a muted style rather than vanishing — a new route whose
    message was forgotten should be visible to whoever added it.
    """
    code = params.get("err") or ""
    level = "bad"
    if not code:
        code = params.get("ok") or ""
        level = "ok"
    if not code:
        return None

    if code.startswith(_BAD_JSON_PREFIX):
        _, line, column = (code.split(":") + ["", ""])[:3]
        return {
            "level": "bad",
            "code": code,
            "text": f"JSON نامعتبر است — خط {line}، ستون {column}.",
        }

    table = FLASH_ERR if level == "bad" else FLASH_OK
    template = table.get(code)
    if template is None:
        return {"level": "info", "code": code, "text": code}

    # `str.format_map` with a defaulting dict: a placeholder with no matching
    # query parameter renders as "—" instead of raising KeyError, which would
    # turn a flash message into a 500 on the page it was redirecting to.
    class _Default(dict):
        def __missing__(self, key):  # noqa: D105
            return "—"

    try:
        text = template.format_map(_Default(params))
    except (ValueError, IndexError):
        text = template
    return {"level": level, "code": code, "text": text}


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------

# Grouped by area of responsibility, which is also how the roles are cut. A
# group with nothing visible to this admin is dropped entirely (the template
# skips empty groups) so a SUPPORT admin does not see three empty headings.
NAV_GROUPS: list[dict] = [
    {
        "label": "عملیات",
        "icon": "🛰",
        "items": [
            # Trailing slash is required: the dashboard's path is literally
            # "/admin/" because FastAPI cannot include an empty child path under
            # a prefix, and "/admin" only reaches it via a 307 redirect.
            {"href": "/admin/", "label": "وضعیت سیستم", "icon": "📊", "perm": rbac.PERM_STATS_VIEW},
            {"href": "/admin/orders", "label": "صف بررسی پرداخت", "icon": "🧾", "perm": rbac.PERM_PAYMENT_REVIEW},
            {"href": "/admin/orders/all", "label": "همه‌ی سفارش‌ها", "icon": "📦", "perm": rbac.PERM_PAYMENT_REVIEW},
            {"href": "/admin/tickets", "label": "تیکت‌های پشتیبانی", "icon": "🆘", "perm": rbac.PERM_SUPPORT_MANAGE},
            {"href": "/admin/notifications", "label": "گزارش اطلاع‌رسانی", "icon": "🔔", "perm": rbac.PERM_SUPPORT_MANAGE},
        ],
    },
    {
        "label": "مشتریان",
        "icon": "👥",
        "items": [
            {"href": "/admin/customers", "label": "مشتریان", "icon": "👤", "perm": rbac.PERM_USER_BAN},
            {"href": "/admin/configurations", "label": "کانفیگ‌ها", "icon": "🔑", "perm": rbac.PERM_CONFIG_MANAGE},
            {"href": "/admin/test", "label": "کانفیگ تستی", "icon": "🧪", "perm": rbac.PERM_TEST_CONFIG},
        ],
    },
    {
        "label": "مالی",
        "icon": "💳",
        "items": [
            {"href": "/admin/payments", "label": "پرداخت و بازپرداخت", "icon": "💸", "perm": rbac.PERM_REFUND_MARK},
            {"href": "/admin/plans", "label": "پلن‌ها", "icon": "🏷", "perm": rbac.PERM_PLAN_MANAGE},
        ],
    },
    {
        "label": "زیرساخت",
        "icon": "🖥",
        "items": [
            {"href": "/admin/nodes", "label": "نودها", "icon": "🖥", "perm": rbac.PERM_NODE_MANAGE},
            {"href": "/admin/pools", "label": "استخرها", "icon": "🗂", "perm": rbac.PERM_NODE_MANAGE},
            {"href": "/admin/cloudflare", "label": "حساب‌های Cloudflare", "icon": "☁️", "perm": rbac.PERM_NODE_MANAGE},
            {"href": "/admin/gaming", "label": "پروفایل‌های گیمینگ", "icon": "🎮", "perm": rbac.PERM_GAMING_PROFILE},
            {"href": "/admin/jobs", "label": "صف کارها", "icon": "⚙️", "perm": rbac.PERM_NODE_MANAGE},
        ],
    },
    {
        "label": "پایش",
        "icon": "📈",
        "items": [
            {"href": "/admin/usage", "label": "مصرف", "icon": "📶", "perm": rbac.PERM_STATS_VIEW},
            {"href": "/admin/reconcile", "label": "بازبینی مصرف", "icon": "🧮", "perm": rbac.PERM_STATS_VIEW},
            {"href": "/admin/health", "label": "سلامت نودها", "icon": "❤️", "perm": rbac.PERM_STATS_VIEW},
        ],
    },
    {
        "label": "مدیریت",
        "icon": "👑",
        "items": [
            {"href": "/admin/admins", "label": "ادمین‌ها", "icon": "👑", "perm": rbac.PERM_ADMIN_MANAGE},
            {"href": "/admin/audit", "label": "گزارش رویدادها", "icon": "📜", "perm": rbac.PERM_ADMIN_MANAGE},
        ],
    },
]


PERM_LABELS: dict[str, str] = {
    rbac.PERM_PAYMENT_REVIEW: "بررسی پرداخت‌های دستی",
    rbac.PERM_REFUND_MARK: "ثبت بازپرداخت",
    rbac.PERM_CONFIG_MANAGE: "مدیریت کانفیگ مشتری (تعلیق، لغو، تغییر)",
    rbac.PERM_TEST_CONFIG: "صدور کانفیگ تست",
    rbac.PERM_PLAN_MANAGE: "مدیریت پلن‌ها و قیمت‌ها",
    rbac.PERM_USER_BAN: "مسدودسازی مشتری",
    rbac.PERM_NODE_MANAGE: "مدیریت نودها، استخرها و حساب‌های Cloudflare",
    rbac.PERM_GAMING_PROFILE: "انتشار پروفایل گیمینگ",
    rbac.PERM_ADMIN_MANAGE: "مدیریت ادمین‌ها و دسترسی‌ها",
    rbac.PERM_SUPPORT_MANAGE: "پاسخ به تیکت‌های پشتیبانی",
    rbac.PERM_STATS_VIEW: "مشاهده‌ی آمار و گزارش‌ها",
}


def _nav_groups(perms: set[str]) -> list[dict]:
    """The sidebar, filtered by permission, empty groups removed.

    Hiding a link is not the access control — every route re-checks its own
    permission — but a visible link that 403s is a bug report waiting to happen,
    and an empty group heading is worse: it tells the admin a whole area exists
    that they cannot see into.
    """
    groups: list[dict] = []
    for group in NAV_GROUPS:
        items = [i for i in group["items"] if i["perm"] in perms]
        if items:
            groups.append({"label": group["label"], "icon": group["icon"], "items": items})
    return groups


def _static_url(path: str) -> str:
    return f"/admin/static/{path}?v={ASSET_VERSION}"


def fmt_dt(value, *, with_time: bool = True) -> str:
    """Persian-friendly timestamp, UTC. "—" for None.

    Lives here rather than in `helpers` because templates need it directly and
    `helpers` imports this module — putting it in helpers would be a circular
    import. Deliberately UTC: the server has no reliable notion of the
    operator's timezone, and a timestamp rendered in a zone nobody can verify
    is worse than one that is honestly UTC.
    """
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M" if with_time else "%Y-%m-%d")


def _context(request: Request) -> dict:
    """Shared context for every render.

    **Every route in this package passes `active_nav`, and this processor must
    never return that key.** Starlette applies context processors *after* the
    route's own context (`context.update(processor(request))`), so a processor
    that returns `active_nav` overwrites the route's value on every page — the
    sidebar highlight would silently vanish everywhere. The key is therefore
    absent here and templates read it with `| default("")`.

    Same reason the per-page status dictionaries (`CONFIG_STATUS_FA`,
    `ORDER_STATUS_FA`, …) are NOT here: they are route-owned, and a default in a
    shared processor is a second source of truth that drifts.
    """
    admin = getattr(request.state, "admin", None)
    perms = rbac.permissions_for(admin.role) if admin is not None else set()
    params = dict(parse_qsl(str(request.query_params), keep_blank_values=True))

    return {
        "admin": admin,
        "perms": perms,
        "nav_groups": _nav_groups(perms),
        "app_name": bot_texts.APP_NAME,
        "flash": _resolve_flash(params),
        # Persian rendering of every status a page can show. Imported, not
        # duplicated — see the module docstring.
        "STATUS_FA": bot_texts.STATUS_FA,
        "SUPPORT_STATUS_FA": bot_texts.SUPPORT_STATUS_FA,
        "format_price": bot_texts.format_price,
        "format_traffic": bot_texts.format_traffic,
        "format_duration": bot_texts.format_duration,
        # Exposed because templates call it directly (`{{ fmt_dt(x.created_at) }}`);
        # defined in this module so `helpers` can import it without a cycle.
        "fmt_dt": fmt_dt,
        "ROLES": rbac.ALL_ROLES,
        "ROLE_LABELS": {
            rbac.ROLE_OWNER: "مالک",
            rbac.ROLE_ADMIN: "مدیر",
            rbac.ROLE_SUPPORT: "پشتیبانی",
            rbac.ROLE_FINANCE: "مالی",
            rbac.ROLE_INFRASTRUCTURE: "زیرساخت",
        },
        # What each permission actually lets a person do, in the operator's
        # language. The admins page renders these next to a role so "what does
        # FINANCE get" is answerable without reading `domain/rbac.py` — and
        # granting a role you cannot describe is how people over-grant.
        "PERM_LABELS": PERM_LABELS,
        "MSG_ADMIN_FORBIDDEN": bot_texts.MSG_ADMIN_FORBIDDEN,
    }


templates = Jinja2Templates(directory=str(TEMPLATES_DIR), context_processors=[_context])

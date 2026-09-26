"""Verdent Platform — FastAPI application entrypoint.

Railway service: `web`  (start: uvicorn api.main:app --host 0.0.0.0 --port $PORT)

On startup:
  1. run pending Alembic migrations (advisory-locked; see db/migrate.py)
  2. bootstrap OWNER admin (TELEGRAM_OWNER_ID, read exactly once)
  3. seed default plans (only when the plans table is empty)
  4. seed the default gaming profile (Tier A/B honest settings)
  5. register the Telegram webhook (only when token + base URL are set)

The app boots even when Telegram/Cloudflare are unconfigured — the control
plane never depends on the bot to run.

Routes:
  /health, /s/{token}, /webhook/{secret}, /internal/nodes/* — the API surface
  /admin/* — the HTML admin panel (see api/routes/admin_panel.py)
"""

import contextlib
import logging

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from admin_panel import auth as admin_auth
from admin_panel.bootstrap_admin import ensure_bootstrap_owner
from admin_panel.templating import STATIC_DIR, templates
from db.migrate import run_migrations
from api.routes import admin_panel as admin_panel_routes
from api.routes import health as health_routes
from api.routes import nodes as node_routes
from api.routes import subscription as subscription_routes
from api.routes import telegram as telegram_routes
from domain import plans as plans_domain
from domain import gaming as gaming_domain
from domain import provisioning as provisioning_domain
from domain.config import settings
from domain import __version_platform__

# bot.texts holds only strings and formatters (no dispatcher, no router), so
# importing it here is safe and lets the panel's 403 page reuse the same
# Persian copy the bot shows for the identical refusal.
from bot import texts as bot_texts  # noqa: E402

# Importing bot.router is what attaches the Telegram handlers to the webhook
# dispatcher (its last line calls dp.include_router). Without this import the
# webhook route accepts updates but no handler is ever registered, so /start
# and every command silently do nothing. Imported here — after bot.webhook is
# importable — and never from bot.webhook itself (see that module's docstring).
import bot.router  # noqa: E402, F401

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("verdent.platform")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("verdent-platform %s starting (env=%s)", __version_platform__, settings.environment)

    # Migrations run first and are deliberately NOT in the tolerant block below.
    # Every startup step after this one reads or writes the schema, and a
    # half-migrated database would fail them in ways that look like bugs in
    # those steps rather than like a missing migration. A crash-loop that names
    # the migration is the honest failure.
    await run_migrations()

    startup_errors: list[str] = []

    for name, coro_factory in [
        ("bootstrap owner", ensure_bootstrap_owner),
        ("gaming profile", gaming_domain.seed_default_gaming_profile),  # before plans (gaming plan links to it)
        ("default plans", plans_domain.seed_default_plans),
        # Last: a node can only be linked once the pools it belongs to exist,
        # and a pool can only be matched by tag once the node's tags are set.
        ("pool link repair", provisioning_domain.repair_pool_links_at_startup),
    ]:
        try:
            await coro_factory()
            logger.info("%s: ok", name)
        except Exception:  # noqa: BLE001
            logger.exception("%s FAILED", name)
            startup_errors.append(name)

    try:
        from bot.webhook import register_webhook

        await register_webhook()
    except Exception:  # noqa: BLE001
        logger.exception("webhook registration failed")
        startup_errors.append("webhook")

    if startup_errors:
        logger.warning("startup had failures: %s (continuing — Railway restarts on crash)", startup_errors)

    yield

    logger.info("verdent-platform shutting down")


app = FastAPI(
    title="Verdent Platform",
    version=__version_platform__,
    lifespan=lifespan,
)

app.include_router(health_routes.router)
app.include_router(node_routes.router)
app.include_router(subscription_routes.router)
app.include_router(telegram_routes.router)
app.include_router(admin_panel_routes.router)


# ---------------------------------------------------------------------------
# Admin panel: static files and the two auth exceptions
# ---------------------------------------------------------------------------

# Mounted at /admin/static so the panel's CSS is served by the same app with no
# build step and no second deploy target. The Dockerfile copies control-plane/
# wholesale, so admin_panel/static/ ships with the image automatically.
app.mount("/admin/static", StaticFiles(directory=str(STATIC_DIR)), name="admin-static")


@app.exception_handler(admin_auth.NotAuthenticated)
async def _not_authenticated(request: Request, exc: admin_auth.NotAuthenticated):
    """No session (or a revoked one) → the login page.

    A redirect rather than a 401 because these are HTML pages a human navigates
    to: a browser showing raw JSON is a dead end, and the login form is where
    they need to be anyway.
    """
    return RedirectResponse("/admin/login", status_code=303)


@app.exception_handler(admin_auth.Forbidden)
async def _forbidden(request: Request, exc: admin_auth.Forbidden):
    """Signed in, wrong role → a 403 page that names the missing permission.

    403 and not 404: the admin is legitimately authenticated and already knows
    the panel exists — hiding the route's existence from them buys nothing and
    makes a role mistake look like a broken link. The permission name is shown
    because "ask an OWNER for node.manage" is actionable.
    """
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "title": "دسترسی مجاز نیست",
            "message": f"{bot_texts.MSG_ADMIN_FORBIDDEN} (نیاز به مجوز: {exc.permission})",
        },
        status_code=403,
    )

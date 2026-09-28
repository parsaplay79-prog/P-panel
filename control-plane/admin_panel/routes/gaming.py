"""Gaming profiles — the `gaming.manage` surface.

`gaming.manage` was declared in RBAC, granted to OWNER, ADMIN and
INFRASTRUCTURE, and used by nothing. A gaming profile is a versioned tuning
bundle (MTU hint, DoH endpoint, stability thresholds, DNS mode) whose *current*
row is read by two consumers: `domain.health.thresholds_for_node` (only for
nodes tagged `gaming`) and the subscription renderer's DNS delivery. Publishing
was `domain.gaming.publish_profile` — a function with no caller.

Publishing here is immutable by construction: `publish_profile` inserts a new
row with `version + 1` and flips `is_current`. Nothing edits a published row.
That is not incidental tidiness — the version is what lets an operator answer
"what was in effect when this customer's node started flapping" weeks later, and
an in-place edit would erase exactly that answer.

The honesty guard (Document 2 Tier A/B) is the other half. `validate_settings`
rejects keys implying capabilities Cloudflare Workers do not have — UDP relay,
ping reduction, packet-loss fixes. This page surfaces the rejection as a
readable list rather than a 500, because the person typing `udp_enabled` is
trying to ship a feature the platform cannot honour, and the refusal is the
product working correctly.
"""

import json
import logging

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import Configuration, GamingProfile, Node, Plan
from domain import rbac
from domain.audit import audit
from domain.gaming import (
    DEFAULT_SETTINGS,
    FORBIDDEN_KEYS,
    publish_profile,
    validate_settings,
)

logger = logging.getLogger("verdent.admin_panel.gaming")

router = APIRouter()

SORT_COLUMNS = {
    "name": GamingProfile.name,
    "version": GamingProfile.version,
    "created": GamingProfile.created_at,
}


def _parse_settings_json(raw: str) -> tuple[dict | None, str]:
    """Parse the settings textarea. (settings, error_code).

    The form takes raw JSON rather than a field-per-setting grid on purpose:
    the setting set is open-ended (the profile is a JSONB blob consumed by two
    different readers), and a form that hard-codes four fields would silently
    drop any fifth a future profile needs. The trade is that malformed JSON is
    a real possibility, so it is caught here and reported as a form error
    instead of a 500 from `json.loads` inside the route.
    """
    raw = (raw or "").strip()
    if not raw:
        return None, "settings_required"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"bad_json:{exc.lineno}:{exc.colno}"
    if not isinstance(parsed, dict):
        return None, "settings_not_object"
    return parsed, ""


@router.get("/gaming")
async def gaming_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_GAMING_PROFILE)),
):
    """Every profile name with its current version, plus the full history.

    Grouped by name rather than listed flat: a profile is a version *series*,
    and a flat list of thirty rows sorted by creation date makes "what is
    current for Gaming Profile" a question you answer by eye.
    """
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="name",
        filter_keys=("current",),
    )

    stmt = select(GamingProfile)
    count_stmt = select(func.count()).select_from(GamingProfile)

    conditions = []
    if query.q:
        conditions.append(func.lower(GamingProfile.name).like(f"%{query.q.lower()}%"))
    if query.filters.get("current") == "1":
        conditions.append(GamingProfile.is_current.is_(True))
    elif query.filters.get("current") == "0":
        conditions.append(GamingProfile.is_current.is_(False))

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    profiles = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).scalars().all()

    # How many plans and configs actually reference a profile — the number that
    # decides whether publishing a new version changes anything for anyone.
    plan_counts = dict(
        (
            await db.execute(
                select(Plan.gaming_profile_id, func.count(Plan.id))
                .where(Plan.gaming_profile_id.isnot(None))
                .group_by(Plan.gaming_profile_id)
            )
        ).all()
    )
    config_counts = dict(
        (
            await db.execute(
                select(Configuration.gaming_profile_id, func.count(Configuration.id))
                .where(Configuration.gaming_profile_id.isnot(None))
                .group_by(Configuration.gaming_profile_id)
            )
        ).all()
    )

    context = {
        "title": "پروفایل‌های گیمینگ",
        "profiles": profiles,
        "plan_counts": {k: int(v) for k, v in plan_counts.items()},
        "config_counts": {k: int(v) for k, v in config_counts.items()},
        "page": page,
        "query": query,
        "base_path": "/admin/gaming",
        "active_nav": "/admin/gaming",
    }
    if is_htmx(request):
        return render(request, "gaming/_rows.html", **context)
    return render(request, "gaming/list.html", **context)


@router.get("/gaming/new")
async def gaming_new_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_GAMING_PROFILE)),
):
    """The publish form, pre-filled with the current profile's settings.

    Pre-filling from current rather than from DEFAULT_SETTINGS is the difference
    between "publish a tweak" and "publish a version that silently reverts every
    tuning made since the defaults shipped". The starting point is the thing
    running in production.
    """
    current = (
        await db.execute(
            select(GamingProfile).where(GamingProfile.is_current.is_(True)).limit(1)
        )
    ).scalar_one_or_none()

    seed = current.settings_json if current is not None else DEFAULT_SETTINGS

    return render(
        request,
        "gaming/form.html",
        title="انتشار نسخه‌ی جدید پروفایل",
        profile=current,
        settings_text=json.dumps(seed, ensure_ascii=False, indent=2),
        name=current.name if current is not None else "Gaming Profile",
        FORBIDDEN_KEYS=sorted(FORBIDDEN_KEYS),
        active_nav="/admin/gaming",
    )


@router.post("/gaming/publish")
async def gaming_publish(
    name: str = Form(""),
    settings_json: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_GAMING_PROFILE)),
):
    """Publish a new immutable version of a named profile.

    Two refusals, reported separately because they mean different things:

      * malformed JSON — the operator made a typo;
      * an honesty violation — the operator is trying to configure something
        the data plane cannot do (`validate_settings`). The violating keys are
        echoed back so the fix is obvious; "invalid settings" would send them
        looking for a syntax error that is not there.
    """
    name = name.strip()
    if not name:
        return redirect("/admin/gaming/new", err="name_required")

    settings, error = _parse_settings_json(settings_json)
    if settings is None:
        return redirect("/admin/gaming/new", err=error)

    violations = validate_settings(settings)
    if violations:
        return redirect(
            "/admin/gaming/new",
            err="honesty",
            keys=",".join(sorted(violations)),
        )

    try:
        profile = await publish_profile(db, name, settings)
    except ValueError as exc:
        # publish_profile re-checks and raises ValueError with the key list.
        # Reachable only if validate_settings and publish_profile ever disagree
        # — belt and braces, but the route must not 500 on it.
        logger.error("publish_profile refused %r: %s", name, exc)
        return redirect("/admin/gaming/new", err="honesty", keys="")

    await audit(
        db,
        "gaming.publish",
        actor_id=admin.id,
        target_type="gaming_profile",
        target_id=profile.id,
        details={"name": profile.name, "version": profile.version},
    )

    # The thresholds this version carries are what the health loop will apply
    # to gaming-tagged nodes on its next pass. Telling the operator the version
    # number makes the change traceable to the health samples that follow it.
    return redirect("/admin/gaming", ok="published", v=profile.version)


@router.get("/gaming/{profile_id}")
async def gaming_detail(
    profile_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_GAMING_PROFILE)),
):
    """One version's exact settings, and the siblings it sits among.

    Reading a past version is the whole reason versions are immutable: when a
    node starts flapping, "what thresholds were in effect" is answerable here
    rather than by reconstructing from memory.
    """
    profile = (
        await db.execute(select(GamingProfile).where(GamingProfile.id == profile_id))
    ).scalar_one_or_none()
    if profile is None:
        return redirect("/admin/gaming", err="notfound")

    siblings = (
        await db.execute(
            select(GamingProfile)
            .where(GamingProfile.name == profile.name)
            .order_by(GamingProfile.version.desc())
        )
    ).scalars().all()

    plans = (
        await db.execute(select(Plan).where(Plan.gaming_profile_id == profile.id))
    ).scalars().all()

    gaming_nodes = (
        await db.execute(
            select(Node).where(Node.capability_tags.any("gaming"))
        )
    ).scalars().all()

    return render(
        request,
        "gaming/detail.html",
        title=f"{profile.name} v{profile.version}",
        profile=profile,
        siblings=siblings,
        plans=plans,
        gaming_nodes=gaming_nodes,
        settings_text=json.dumps(profile.settings_json, ensure_ascii=False, indent=2),
        active_nav="/admin/gaming",
    )


@router.post("/gaming/{profile_id}/restore")
async def gaming_restore(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_GAMING_PROFILE)),
):
    """Re-publish an old version's settings as a NEW version.

    Not a rollback. The old row is never made current again — flipping
    `is_current` back would erase the record that the intermediate version was
    ever live, and a health investigation needs that. The restored settings
    become `version + 1`, so the series reads as what actually happened:
    v4 was live, v5 changed something, v6 put v4's values back.
    """
    profile = (
        await db.execute(select(GamingProfile).where(GamingProfile.id == profile_id))
    ).scalar_one_or_none()
    if profile is None:
        return redirect("/admin/gaming", err="notfound")

    if profile.is_current:
        return redirect(f"/admin/gaming/{profile_id}", err="already_current")

    restored = await publish_profile(db, profile.name, profile.settings_json)

    await audit(
        db,
        "gaming.restore",
        actor_id=admin.id,
        target_type="gaming_profile",
        target_id=restored.id,
        details={"name": restored.name, "from_version": profile.version, "new_version": restored.version},
    )
    return redirect(f"/admin/gaming/{restored.id}", ok="restored", v=restored.version)

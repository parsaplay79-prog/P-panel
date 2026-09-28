"""Cloudflare accounts — the form that did not exist.

Until this page, a `CloudflareAccount` row could only be created by pasting a
`python -c` snippet into the Railway web shell (`docs/SETUP-GUIDE.md` §6 step 1).
That is not a product feature; it is a workaround for a missing one, and it puts
an encrypted-at-rest secret through a shell history on the way in.

The order of operations here is the whole design, and it is Document 1 §M's
instruction made concrete: *"Check permissions actually granted match what's
required; reject early with a clear reason."*

  1. **Verify the token** (`/user/tokens/verify`). Needs no account scope, so a
     provisioning-scoped token can answer it. An expired or revoked token is
     refused here, with Cloudflare's own message.
  2. **Discover the account id** if the operator did not paste one, from
     `/accounts`. A token with Workers/KV scope but no account-read scope
     verifies as `active` and then fails *mid-provisioning* — after a KV
     namespace may already exist — with an opaque 403. Asking now turns that
     into a clear refusal before anything is created.
  3. **Probe the two write scopes** (`Workers Scripts:Edit`, `Workers KV
     Storage:Edit`) with read-only LIST calls. A token that cannot list
     certainly cannot create.
  4. Only then encrypt and store.

Steps 1–3 happen against the plaintext token, which is held in a local variable
inside the request and never logged, never returned, and never written anywhere.
`CloudflareClient.from_plaintext_token` exists solely for this path.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import CloudflareAccount, Node
from domain import rbac
from domain.audit import audit
from domain.cloudflare import CloudflareClient, CloudflareError
from domain.config import settings
from domain.crypto import encrypt_secret
from domain.jobs import JOB_VERIFY_CF_ACCOUNT, enqueue

logger = logging.getLogger("verdent.admin_panel.cloudflare_accounts")

router = APIRouter()

ACCOUNT_STATUS_FA = {
    "active": "فعال",
    "error": "خطا",
    "disabled": "غیرفعال",
}

ACCOUNT_STATUS_TAG = {
    "active": "tag-ok",
    "error": "tag-bad",
    "disabled": "tag-warn",
}

SORT_COLUMNS = {
    "added": CloudflareAccount.added_at,
    "label": CloudflareAccount.label,
    "status": CloudflareAccount.status,
}


@router.get("/cloudflare")
async def cloudflare_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="added",
        filter_keys=("status",),
    )

    stmt = select(CloudflareAccount)
    count_stmt = select(func.count()).select_from(CloudflareAccount)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(CloudflareAccount.label).like(pattern),
                func.lower(func.cast(CloudflareAccount.cf_account_id, Text)).like(pattern),
            )
        )
    if query.filters.get("status") in ACCOUNT_STATUS_FA:
        conditions.append(CloudflareAccount.status == query.filters["status"])

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    accounts = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).scalars().all()

    node_counts = dict(
        (
            await db.execute(
                select(Node.cloudflare_account_id, func.count(Node.id)).group_by(
                    Node.cloudflare_account_id
                )
            )
        ).all()
    )

    context = {
        "title": "حساب‌های Cloudflare",
        "accounts": accounts,
        "node_counts": {k: int(v) for k, v in node_counts.items()},
        "page": page,
        "query": query,
        "base_path": "/admin/cloudflare",
        "ACCOUNT_STATUS_FA": ACCOUNT_STATUS_FA,
        "ACCOUNT_STATUS_TAG": ACCOUNT_STATUS_TAG,
        "active_nav": "/admin/cloudflare",
    }
    if is_htmx(request):
        return render(request, "cloudflare/_rows.html", **context)
    return render(request, "cloudflare/list.html", **context)


@router.get("/cloudflare/new")
async def cloudflare_new_form(
    request: Request,
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    return render(
        request,
        "cloudflare/form.html",
        title="افزودن حساب Cloudflare",
        active_nav="/admin/cloudflare",
    )


@router.post("/cloudflare/new")
async def cloudflare_create(
    request: Request,
    label: str = Form(""),
    api_token: str = Form(""),
    cf_account_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Verify a token against Cloudflare, then store it encrypted.

    Every refusal below is a specific, actionable sentence, because the failure
    this replaces was an opaque 403 in the middle of node provisioning — after a
    KV namespace had already been created — with nothing to connect it back to
    the token that caused it.
    """
    label = label.strip()
    api_token = api_token.strip()
    cf_account_id = cf_account_id.strip()

    def _fail(code: str, detail: str = ""):
        # `label` and `cf_account_id` come back so a refusal does not blank the
        # form. `api_token` deliberately does NOT: it is a secret, and putting
        # it in a query string would write it into browser history, the
        # reverse-proxy access log, and the `Referer` header of the next
        # request. Losing a pasted token costs one paste; leaking it costs the
        # account.
        return redirect(
            "/admin/cloudflare/new",
            err=code,
            detail=detail,
            label=label,
            cf_account_id=cf_account_id,
        )

    if not label:
        return _fail("label_required")
    if not api_token:
        return _fail("token_required")

    if not settings.cloudflare_token_encryption_key:
        # Storing without the key would fail at encrypt time anyway; refusing
        # here names the missing configuration instead of raising a ValueError
        # from deep inside `_load_key`.
        return _fail("no_encryption_key")

    # --- 1. is the token alive? -------------------------------------------
    client = CloudflareClient.from_plaintext_token(api_token, cf_account_id)
    try:
        await client.verify_token()
    except CloudflareError as exc:
        logger.warning("cloudflare token verification failed: %s", exc)
        return _fail("token_invalid", str(exc)[:200])
    except Exception as exc:  # noqa: BLE001 — a network failure is not a bad token
        logger.exception("cloudflare token verification errored")
        return _fail("verify_error", str(exc)[:200])

    # --- 2. which account does it see? -------------------------------------
    accounts: list[dict] = []
    try:
        accounts = await client.list_accounts()
    except Exception as exc:  # noqa: BLE001
        logger.exception("cloudflare account listing errored")
        return _fail("verify_error", str(exc)[:200])

    if not cf_account_id:
        if not accounts:
            return _fail("no_account_scope")
        if len(accounts) > 1:
            # Ambiguous on purpose: picking the first would put nodes in an
            # account the operator did not choose, and nothing downstream would
            # report the mistake.
            return _fail(
                "account_ambiguous",
                "، ".join(f"{a.get('name')} ({a.get('id')})" for a in accounts[:5]),
            )
        cf_account_id = str(accounts[0].get("id") or "")
        if not cf_account_id:
            return _fail("no_account_scope")

    duplicate = (
        await db.execute(
            select(CloudflareAccount).where(CloudflareAccount.cf_account_id == cf_account_id)
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        return _fail("account_exists", duplicate.label)

    # --- 3. can it actually provision? -------------------------------------
    scoped = CloudflareClient.from_plaintext_token(api_token, cf_account_id)
    try:
        missing = await scoped.probe_provisioning_permissions()
    except Exception as exc:  # noqa: BLE001
        logger.exception("cloudflare permission probe errored")
        return _fail("verify_error", str(exc)[:200])

    if missing:
        return _fail("missing_scopes", "، ".join(missing))

    # --- 4. store it -------------------------------------------------------
    account = CloudflareAccount(
        label=label,
        cf_account_id=cf_account_id,
        # Stored the way every reader expects it: the ASCII bytes of the base64
        # ciphertext. `_auth_headers` does `api_token_encrypted.decode("ascii")`
        # then `decrypt_secret`, so storing the plain base64 str here would put
        # a str in a LargeBinary column and break decryption at first use.
        api_token_encrypted=encrypt_secret(
            api_token, settings.cloudflare_token_encryption_key
        ).encode("ascii"),
        status="active",
    )
    db.add(account)
    await db.commit()

    # The audit row records that a token was added and which account it opens —
    # never the token, not even a prefix. An audit log is read by more people
    # than the secret is.
    await audit(
        db,
        "cloudflare_account.create",
        actor_id=admin.id,
        target_type="cloudflare_account",
        target_id=account.id,
        details={"label": label, "cf_account_id": cf_account_id, "verified": True},
    )

    return redirect("/admin/cloudflare", ok="created")


@router.post("/cloudflare/{account_id}/verify")
async def cloudflare_verify(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Re-check a stored account's token, out of band.

    Enqueued rather than awaited: a Cloudflare round trip in a request makes the
    button hang, and a token that has been revoked should be discovered by a
    worker that can retry rather than by an operator watching a spinner.

    The job only re-verifies and stamps the status. It never disables the
    account: an account with nodes still serving customers must not be taken out
    of rotation by a transient Cloudflare API failure, and a human decides that.
    """
    account = (
        await db.execute(select(CloudflareAccount).where(CloudflareAccount.id == account_id))
    ).scalar_one_or_none()
    if account is None:
        return redirect("/admin/cloudflare", err="notfound")

    job = await enqueue(
        db,
        JOB_VERIFY_CF_ACCOUNT,
        {"account_id": account.id},
        requested_by=admin.id,
    )

    await audit(
        db,
        "cloudflare_account.verify_requested",
        actor_id=admin.id,
        target_type="job",
        target_id=job.id,
        details={"account_id": account.id},
    )
    return redirect(f"/admin/jobs/{job.id}", ok="queued")


@router.post("/cloudflare/{account_id}/disable")
async def cloudflare_disable(
    account_id: str,
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Mark an account disabled. Refuses while it still has live nodes.

    This is bookkeeping, not a kill switch: it stops the account being chosen
    for *new* nodes and records that a human has taken it out of service. The
    nodes already in it keep running, because their credentials live in their
    own KV namespaces and do not depend on this row.
    """
    account = (
        await db.execute(select(CloudflareAccount).where(CloudflareAccount.id == account_id))
    ).scalar_one_or_none()
    if account is None:
        return redirect("/admin/cloudflare", err="notfound")

    live_nodes = int(
        (
            await db.execute(
                select(func.count())
                .select_from(Node)
                .where(
                    Node.cloudflare_account_id == account.id,
                    Node.state != "DECOMMISSIONED",
                )
            )
        ).scalar_one()
    )
    if live_nodes:
        return redirect("/admin/cloudflare", err="account_busy", n=live_nodes)

    account.status = "disabled"
    await db.commit()

    await audit(
        db,
        "cloudflare_account.disable",
        actor_id=admin.id,
        target_type="cloudflare_account",
        target_id=account.id,
        details={"reason": reason},
    )
    return redirect("/admin/cloudflare", ok="disabled")


@router.post("/cloudflare/{account_id}/enable")
async def cloudflare_enable(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Put an account back in service. The token is NOT re-verified here.

    Re-enabling is the operator saying "I have fixed whatever was wrong" — and
    the fix may have been at Cloudflare, not in the token. Verifying
    synchronously would refuse the re-enable on a transient API failure, so the
    separate verify button exists and this one just flips the status.
    """
    account = (
        await db.execute(select(CloudflareAccount).where(CloudflareAccount.id == account_id))
    ).scalar_one_or_none()
    if account is None:
        return redirect("/admin/cloudflare", err="notfound")

    account.status = "active"
    await db.commit()

    await audit(
        db,
        "cloudflare_account.enable",
        actor_id=admin.id,
        target_type="cloudflare_account",
        target_id=account.id,
        details={},
    )
    return redirect("/admin/cloudflare", ok="enabled")


@router.post("/cloudflare/{account_id}/delete")
async def cloudflare_delete(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Delete an account that owns no nodes. Refuses otherwise.

    `nodes.cloudflare_account_id` is NOT NULL with a FK here, so an account with
    any node — decommissioned or not — cannot be removed without destroying the
    node rows that record which hardware existed and where its credentials
    lived. The refusal names the count rather than surfacing a FK violation.
    """
    account = (
        await db.execute(select(CloudflareAccount).where(CloudflareAccount.id == account_id))
    ).scalar_one_or_none()
    if account is None:
        return redirect("/admin/cloudflare", err="notfound")

    node_count = int(
        (
            await db.execute(
                select(func.count()).select_from(Node).where(Node.cloudflare_account_id == account.id)
            )
        ).scalar_one()
    )
    if node_count:
        return redirect("/admin/cloudflare", err="has_nodes", n=node_count)

    label = account.label
    await db.delete(account)
    await db.commit()

    await audit(
        db,
        "cloudflare_account.delete",
        actor_id=admin.id,
        target_type="cloudflare_account",
        target_id=account_id,
        details={"label": label},
    )
    return redirect("/admin/cloudflare", ok="deleted")

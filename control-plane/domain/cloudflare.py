"""Verdent Platform — Cloudflare API client (Phase 2).

Minimal, scoped to exactly what provisioning needs:
- create a KV namespace
- upload the forked worker bundle (multipart module upload)
- enable the workers.dev subdomain
- read/write KV values (proxyUsers map, nodeSecret)

Auth: the account's API token, stored AES-256-GCM-encrypted at rest
(cloudflare_accounts.api_token_encrypted) — never in the data plane.
Deliberately NO zone-level operations: workers.dev subdomains need no DNS
control, which keeps the required token scope minimal.
"""

import base64
import logging
from typing import Any

import httpx

from domain.crypto import decrypt_secret

logger = logging.getLogger("verdent.cloudflare")

CF_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareError(Exception):
    pass


def _auth_headers(api_token_encrypted: bytes, key_b64: str) -> dict[str, str]:
    # api_token_encrypted is the ASCII of the base64 ciphertext (LargeBinary)
    token = decrypt_secret(api_token_encrypted.decode("ascii"), key_b64)
    return {"Authorization": f"Bearer {token}"}


def _check(resp_json: dict[str, Any], what: str) -> dict[str, Any]:
    if not resp_json.get("success"):
        errors = "; ".join(str(e.get("message", e)) for e in resp_json.get("errors", []))
        raise CloudflareError(f"{what} failed: {errors}")
    return resp_json.get("result", {})


class CloudflareClient:
    def __init__(self, api_token_encrypted: bytes, encryption_key_b64: str, account_id: str):
        self._headers = _auth_headers(api_token_encrypted, encryption_key_b64)
        self._account_id = account_id

    @classmethod
    def from_plaintext_token(cls, api_token: str, account_id: str = "") -> "CloudflareClient":
        """Build a client from a token that has not been stored yet.

        The add-account form has to verify a token BEFORE there is a
        `cloudflare_accounts` row to encrypt it into — otherwise an invalid
        token is only discovered after it has been written to the database, and
        the operator is left with a row that looks configured and fails at
        provisioning time. This constructor is the only path that holds a
        plaintext token, it lives entirely inside the verification call, and
        nothing logs or returns it.

        `account_id` may be empty for the `/user/tokens/verify` call, which
        needs no account scope. It is required before any account-scoped call.
        """
        client = cls.__new__(cls)
        client._headers = {"Authorization": f"Bearer {api_token}"}
        client._account_id = account_id
        return client

    async def _request(self, method: str, path: str, *, json_body: Any = None, content: Any = None, data: Any = None, files: Any = None, headers: dict | None = None) -> dict[str, Any]:
        url = f"{CF_API_BASE}{path}"
        merged = {**self._headers, **(headers or {})}
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.request(method, url, json=json_body, content=content, data=data, files=files, headers=merged)
        if resp.status_code >= 400:
            raise CloudflareError(f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    # -- KV ---------------------------------------------------------------

    async def create_kv_namespace(self, title: str) -> str:
        result = _check(
            await self._request(
                "POST", f"/accounts/{self._account_id}/storage/kv/namespaces",
                json_body={"title": title},
            ),
            "create KV namespace",
        )
        return result["id"]

    async def put_kv_value(self, namespace_id: str, key: str, value: str) -> None:
        await self._request(
            "PUT",
            f"/accounts/{self._account_id}/storage/kv/namespaces/{namespace_id}/values/{key}",
            content=value.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
        )

    # -- Workers -----------------------------------------------------------

    async def upload_worker_script(
        self,
        script_name: str,
        worker_js: str,
        provisioned_json: str,
        kv_namespace_id: str,
        enable_durable_objects: bool,
    ) -> None:
        """Multipart module upload (Document 5: settings as a plain_text
        binding, KV binding for the credential map)."""
        metadata: dict[str, Any] = {
            "main_module": "worker.js",
            "compatibility_date": "2025-01-01",
            "compatibility_flags": ["nodejs_compat"],
            "bindings": [
                {"type": "plain_text", "name": "provisioned", "text": provisioned_json},
                {"type": "kv_namespace", "name": "kv", "namespace_id": kv_namespace_id},
            ],
        }

        if enable_durable_objects:
            # Requires Workers Paid. On free plans this binding is omitted and
            # the Node degrades to fail-open session checks.
            metadata["bindings"].append(
                {"type": "durable_object_namespace", "name": "SESSION_COUNTER", "class_name": "SessionCounter"}
            )
            metadata["migrations"] = {"new_tag": "v1", "new_classes": ["SessionCounter"]}

        import json as _json

        files = {
            "metadata": (None, _json.dumps(metadata), "application/json"),
            "worker.js": ("worker.js", worker_js, "application/javascript+module"),
        }

        result = await self._request(
            "PUT",
            f"/accounts/{self._account_id}/workers/scripts/{script_name}",
            files=files,
        )
        _check(result, "upload worker script")

    async def enable_workers_dev(self, script_name: str) -> str:
        """Enable the workers.dev subdomain and return the public URL."""
        # The POST response only confirms the toggle — it returns
        # {"enabled": true, "previews_enabled": false} and never the
        # subdomain name. The name lives on the account-level endpoint.
        _check(
            await self._request(
                "POST",
                f"/accounts/{self._account_id}/workers/scripts/{script_name}/subdomain",
                json_body={"enabled": True, "previews_enabled": False},
            ),
            "enable workers.dev subdomain",
        )
        subdomain = _check(
            await self._request("GET", f"/accounts/{self._account_id}/workers/subdomain"),
            "get workers.dev subdomain",
        ).get("subdomain")
        if not subdomain:
            raise CloudflareError("workers.dev subdomain missing from response")
        return f"https://{script_name}.{subdomain}.workers.dev"

    async def delete_worker_script(self, script_name: str) -> None:
        await self._request("DELETE", f"/accounts/{self._account_id}/workers/scripts/{script_name}")

    # -- Account verification (Document 1 §M) ------------------------------

    async def verify_token(self) -> dict[str, Any]:
        """Confirm the token is live and report its status.

        Document 1 §M: "Validate token + fetch account details" then "Check
        permissions actually granted match what's required; reject early with a
        clear reason if not". This is the first half.

        `/user/tokens/verify` is the only endpoint that works with a token
        scoped as narrowly as ours — it needs no account permission at all, so a
        token that can provision a Node can also answer "am I valid". It returns
        `{"id", "status": "active"|"disabled"|"expired"}`.

        Raises CloudflareError with Cloudflare's own message on an invalid or
        expired token, so the operator sees "Invalid API Token" rather than a
        generic failure they have to guess at.
        """
        result = _check(await self._request("GET", "/user/tokens/verify"), "verify API token")
        status = result.get("status")
        if status != "active":
            raise CloudflareError(
                f"the API token is not active (status: {status!r}) — create a new token "
                "with Workers Scripts:Edit, Workers KV Storage:Edit and Account Settings:Read"
            )
        return result

    async def list_accounts(self) -> list[dict[str, Any]]:
        """Accounts this token can see. Empty list means the token is scoped to
        nothing useful, which is the second half of Document 1 §M's early check.

        A token with Workers/KV permissions but no account read scope verifies
        as `active` and then fails at provisioning time with an opaque 403
        somewhere in the middle of the KV-namespace call — after a namespace may
        already have been created. Asking for the account list up front turns
        that into a clear refusal before anything is made.
        """
        result = await self._request("GET", "/accounts?per_page=50")
        if not result.get("success"):
            return []
        return list(result.get("result") or [])

    async def probe_provisioning_permissions(self) -> list[str]:
        """Which required capabilities are missing. Empty list = ready.

        Checked by listing KV namespaces and worker scripts, both read-only:
        the token must hold Edit on each to be able to provision, and a token
        that cannot even LIST is certainly not going to be able to CREATE. Doing
        this before any write is what makes "reject early with a clear reason"
        real rather than aspirational.
        """
        missing: list[str] = []

        kv = await self._request("GET", f"/accounts/{self._account_id}/storage/kv/namespaces?per_page=1")
        if not kv.get("success"):
            missing.append("Workers KV Storage:Edit")

        scripts = await self._request("GET", f"/accounts/{self._account_id}/workers/scripts")
        if not scripts.get("success"):
            missing.append("Workers Scripts:Edit")

        return missing

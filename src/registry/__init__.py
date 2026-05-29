"""
Public Trust Registry Client + Audit Log Reader
Contributes anonymised verdicts to the community registry and
reads prior quorum history from the Google Sheets audit log
for the historical reputation modifier.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from datetime import datetime, timezone

import httpx

log = logging.getLogger(__name__)


# ── Public Trust Registry ─────────────────────────────────────────────────────

class PublicTrustRegistry:
    def __init__(self, cfg: dict) -> None:
        self.enabled         = cfg.get("enabled", False)
        self.endpoint        = cfg.get("endpoint", "https://api.oss-trust.dev/registry")
        self.api_key         = os.environ.get(
            cfg.get("api_key_env", "PUBLIC_REGISTRY_API_KEY"), ""
        )
        self.contribute_verdicts = cfg.get("contribute_verdicts", True)
        self.contribute_flags    = cfg.get("contribute_signal_flags", True)
        self.consume_scores      = cfg.get("consume_community_scores", True)

    async def get_score(
        self, package: str, version: str, ecosystem: str
    ) -> dict:
        """Fetch community-aggregated score band for this package."""
        if not self.enabled or not self.api_key:
            return {}

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{self.endpoint}/scores/{ecosystem}/{package}/{version}",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                if r.status_code == 404:
                    return {"band": "", "sample_size": 0}
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            log.debug(f"[registry] Community score fetch failed: {exc}")
            return {}

    async def contribute(self, result) -> None:  # result: TrustResult
        """Contribute anonymised signal data for this evaluation."""
        if not self.enabled or not self.api_key or not self.contribute_verdicts:
            return

        payload = {
            "package":   result.package,
            "version":   result.version,
            "ecosystem": result.ecosystem,
            # Score band only — not the raw numeric score
            "trust_level_band": result.trust_level,
            "outcome":          result.outcome,
            # Signal flags but not their specific values
            "signal_flags": {
                k: bool(v) for k, v in result.flags.items()
            } if self.contribute_flags else {},
            "slsa_level":   result.slsa.get("level", 0),
            "evaluated_at": result.evaluated_at,
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.endpoint}/contribute",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                if r.status_code not in (200, 201, 202):
                    log.debug(f"[registry] Contribution rejected: {r.status_code}")
        except Exception as exc:
            log.debug(f"[registry] Contribution failed: {exc}")


# ── Audit Log Client (Google Sheets) ─────────────────────────────────────────

class AuditLogClient:
    """
    Reads prior quorum events from the Google Sheets audit log
    to compute the historical reputation modifier.
    """

    def __init__(self) -> None:
        self.credentials      = os.environ.get("SHEETS_CREDENTIALS", "")
        self.spreadsheet_id   = os.environ.get("SHEETS_SPREADSHEET_ID", "")
        self.sheet_name       = os.environ.get("SHEETS_SHEET_NAME", "QuorumAuditLog")

    async def get_package_history(self, package: str, version: str) -> dict:
        """
        Query the audit log sheet for all prior quorum events for this package.
        Returns:
          prior_denials:   int  — number of DENIED or EXPIRED verdicts
          prior_approvals: int  — number of APPROVED verdicts
          last_verdict:    str  — most recent verdict or ""
          last_decided_at: str  — ISO timestamp of most recent event or ""
        """
        if not self.credentials or not self.spreadsheet_id:
            return {"prior_denials": 0, "prior_approvals": 0}

        try:
            token  = await self._get_token()
            rows   = await self._fetch_rows(token)
            return self._parse_history(rows, package)
        except Exception as exc:
            log.warning(f"[audit_log] History query failed for {package}: {exc}")
            return {"prior_denials": 0, "prior_approvals": 0}

    async def _fetch_rows(self, token: str) -> list[list[str]]:
        range_name = f"{self.sheet_name}!A:AH"   # Wide enough for all 33+ columns
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://sheets.googleapis.com/v4/spreadsheets"
                f"/{self.spreadsheet_id}/values/{range_name}",
                headers={"Authorization": f"Bearer {token}"},
            )
            r.raise_for_status()
            return r.json().get("values", [])

    def _parse_history(self, rows: list[list[str]], package: str) -> dict:
        if len(rows) < 2:
            return {"prior_denials": 0, "prior_approvals": 0}

        headers = [h.strip().lower() for h in rows[0]]
        try:
            pkg_col     = headers.index("package")
            verdict_col = headers.index("final_verdict")
            decided_col = headers.index("decided_at")
        except ValueError:
            return {"prior_denials": 0, "prior_approvals": 0}

        denials   = 0
        approvals = 0
        dates: list[str] = []

        for row in rows[1:]:
            if len(row) <= max(pkg_col, verdict_col):
                continue
            if row[pkg_col].strip().lower() != package.lower():
                continue
            verdict = row[verdict_col].strip().upper() if len(row) > verdict_col else ""
            if verdict in ("DENIED", "EXPIRED"):
                denials += 1
            elif verdict == "APPROVED":
                approvals += 1
            if len(row) > decided_col:
                dates.append(row[decided_col])

        last_verdict     = ""
        last_decided_at  = ""
        if dates:
            last_decided_at = max(dates)
            # Find the verdict corresponding to the most recent date
            for row in rows[1:]:
                if (
                    len(row) > max(pkg_col, decided_col, verdict_col)
                    and row[pkg_col].strip().lower() == package.lower()
                    and row[decided_col] == last_decided_at
                ):
                    last_verdict = row[verdict_col]
                    break

        return {
            "prior_denials":   denials,
            "prior_approvals": approvals,
            "last_verdict":    last_verdict,
            "last_decided_at": last_decided_at,
        }

    async def _get_token(self) -> str:
        """Obtain a Google OAuth2 access token from the service account credentials."""
        import time
        import hashlib
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        sa = json.loads(base64.b64decode(self.credentials).decode())
        now = int(time.time())

        header  = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}))
        payload = _b64url(json.dumps({
            "iss":   sa["client_email"],
            "scope": "https://www.googleapis.com/auth/spreadsheets.readonly",
            "aud":   "https://oauth2.googleapis.com/token",
            "iat":   now,
            "exp":   now + 3600,
        }))

        signing_input = f"{header}.{payload}".encode()

        private_key = serialization.load_pem_private_key(
            sa["private_key"].encode(), password=None
        )
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        jwt = f"{header}.{payload}.{sig_b64}"

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion":  jwt,
                },
            )
            r.raise_for_status()
            return r.json()["access_token"]


def _b64url(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

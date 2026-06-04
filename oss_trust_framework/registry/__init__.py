"""
Public Trust Registry Client — GitHub-native implementation
────────────────────────────────────────────────────────────
Reads from and contributes to the registry/ directory in the
chrisgillham/oss-trust-framework GitHub repository.

Read path  (no auth required):
  GitHub raw content API → registry/index.json → registry/packages/{eco}/{pkg}.json

Write path (GitHub token required):
  Opens a GitHub Issue titled "[registry-contribution] {eco}/{pkg}@{version}"
  with the anonymised payload as the issue body (JSON fenced code block).
  The registry-ingest.yml workflow picks this up, validates it, merges it
  into the registry files, and closes the issue.

Audit log read path (Google Sheets):
  Unchanged — AuditLogClient still reads the Sheets audit log for the
  historical reputation modifier.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

# ── Registry location ─────────────────────────────────────────────────────────

DEFAULT_REPO   = "chrisgillham/oss-trust-framework"
DEFAULT_BRANCH = "main"
RAW_BASE       = "https://raw.githubusercontent.com/{repo}/{branch}"
API_BASE       = "https://api.github.com"

# Local disk cache for index and package files (avoids redundant HTTP calls
# within the same pipeline run)
_CACHE_DIR  = Path(".oss-trust-cache/registry")
_CACHE_TTL  = 3600   # seconds — refresh cache if older than 1 hour


# ── Public Trust Registry ─────────────────────────────────────────────────────

class PublicTrustRegistry:
    """
    GitHub-native public trust registry client.

    Reads:  raw GitHub content API (no auth; public repo)
    Writes: GitHub Issues API (uses GITHUB_TOKEN from env)
    """

    def __init__(self, cfg: dict) -> None:
        self.enabled         = cfg.get("enabled", False)
        self.repo            = cfg.get("repo", DEFAULT_REPO)
        self.branch          = cfg.get("branch", DEFAULT_BRANCH)
        self.token           = os.environ.get("GITHUB_TOKEN", "")
        self.contribute      = cfg.get("contribute_verdicts", True)
        self.contribute_flags = cfg.get("contribute_signal_flags", True)
        self.consume_scores  = cfg.get("consume_community_scores", True)
        self._raw_base       = RAW_BASE.format(repo=self.repo, branch=self.branch)
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Read path ─────────────────────────────────────────────────────────────

    async def get_score(
        self, package: str, version: str, ecosystem: str
    ) -> dict:
        """
        Return the community score band and contribution count for this package.
        Returns {} if the package has no registry entries yet.
        """
        if not self.enabled or not self.consume_scores:
            return {}

        try:
            index = await self._fetch_index()
            key   = f"{ecosystem}/{package}"
            entry = index.get("entries", {}).get(key)
            if not entry:
                return {"band": "", "contribution_count": 0}

            # Fetch full package file for version-specific score
            pkg_data = await self._fetch_package_file(ecosystem, package)
            if not pkg_data:
                return {
                    "band":               entry.get("community_band", ""),
                    "contribution_count": entry.get("contribution_count", 0),
                }

            ver_data = pkg_data.get("versions", {}).get(version, {})
            band = (
                ver_data.get("community_band")
                or pkg_data.get("aggregate", {}).get("community_band", "")
            )
            return {
                "band":               band,
                "contribution_count": entry.get("contribution_count", 0),
                "version_count":      ver_data.get("contribution_count", 0),
                "version_denied":     ver_data.get("denied_count", 0),
                "signal_fire_counts": ver_data.get("signal_fire_counts", {}),
            }

        except Exception as exc:
            log.debug(f"[registry] Score fetch failed for {package}: {exc}")
            return {}

    async def _fetch_index(self) -> dict:
        cache_path = _CACHE_DIR / "index.json"
        if _is_fresh(cache_path):
            return json.loads(cache_path.read_text())

        url = f"{self._raw_base}/registry/index.json"
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 404:
                return {"entries": {}}
            r.raise_for_status()
            data = r.json()

        cache_path.write_text(json.dumps(data))
        return data

    async def _fetch_package_file(self, ecosystem: str, package: str) -> dict | None:
        filename  = _package_filename(package)
        cache_key = f"{ecosystem}__{filename}"
        cache_path = _CACHE_DIR / cache_key

        if _is_fresh(cache_path):
            return json.loads(cache_path.read_text())

        url = f"{self._raw_base}/registry/packages/{ecosystem}/{filename}"
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()

        cache_path.write_text(json.dumps(data))
        return data

    # ── Write path ────────────────────────────────────────────────────────────

    async def contribute(self, result) -> None:  # result: TrustResult
        """
        Contribute anonymised verdict data by opening a GitHub Issue.
        The registry-ingest.yml workflow handles validation and merge.
        """
        if not self.enabled or not self.contribute:
            return
        if not self.token:
            log.debug("[registry] No GITHUB_TOKEN — skipping contribution")
            return

        payload = self._build_payload(result)

        # Issue title format that the ingest workflow matches on
        title = (
            f"[registry-contribution] "
            f"{result.ecosystem}/{result.package}@{result.version}"
        )

        body = (
            "<!-- OSS Trust Framework automated registry contribution -->\n"
            "<!-- Do not edit this issue manually -->\n\n"
            "```json\n"
            + json.dumps(payload, indent=2)
            + "\n```\n"
        )

        owner, repo = self.repo.split("/", 1)
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    f"{API_BASE}/repos/{owner}/{repo}/issues",
                    headers={
                        "Authorization":        f"Bearer {self.token}",
                        "Accept":               "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    json={
                        "title":  title,
                        "body":   body,
                        "labels": ["registry-contribution"],
                    },
                )
                if r.status_code in (200, 201):
                    issue_num = r.json().get("number")
                    log.info(
                        f"[registry] Contribution submitted as issue #{issue_num}: "
                        f"{result.ecosystem}/{result.package}@{result.version}"
                    )
                elif r.status_code == 422:
                    log.debug("[registry] Contribution issue already exists (rate-limited)")
                else:
                    log.warning(f"[registry] Issue creation returned {r.status_code}")
        except Exception as exc:
            log.debug(f"[registry] Contribution failed: {exc}")

    def _build_payload(self, result) -> dict:
        """Build the anonymised contribution payload from a TrustResult."""
        sig   = result.signature or {}
        chk   = result.checksum  or {}
        flags = result.flags     or {}

        signals_fired = {
            "typosquatting":       bool(flags.get("typosquatting")),
            "behavior_change":     bool(flags.get("behavior_change")),
            "author_reputation":   bool(flags.get("author_reputation")),
            "provenance_activity": bool(flags.get("provenance_activity")),
            "ai_hallucination":    bool(flags.get("ai_hallucination")),
            "no_signature":        not sig.get("present", False),
            "weak_signature":      sig.get("strength") == "weak",
            "no_checksum":         not chk.get("present", False),
        }

        # Contribution ID: deterministic hash of quorum_id + evaluated_at
        # Prevents the same evaluation being submitted twice but is not
        # traceable back to any individual or organization
        raw_id = f"{result.package}:{result.version}:{result.ecosystem}:{result.evaluated_at}"
        contrib_id = hashlib.sha256(raw_id.encode()).hexdigest()

        return {
            "schema_version":   "1.0",
            "package":          result.package,
            "version":          result.version,
            "ecosystem":        result.ecosystem,
            "evaluated_at":     result.evaluated_at,
            "trust_band":       result.trust_level,    # HIGH / MEDIUM / LOW only
            "slsa_level":       result.slsa.get("level", 0),
            "verdict":          result.outcome.upper() if result.outcome in
                                ("approved", "denied", "expired")
                                else "EXPIRED",
            "signals_fired":    signals_fired if self.contribute_flags else
                                {k: False for k in signals_fired},
            "contribution_id":  contrib_id,
            "framework_version": result.pipeline_version,
        }


# ── Audit Log Client (Google Sheets) — unchanged ──────────────────────────────

class AuditLogClient:
    """
    Reads prior quorum events from the Google Sheets audit log
    to compute the historical reputation modifier.
    """

    def __init__(self) -> None:
        self.credentials    = os.environ.get("SHEETS_CREDENTIALS", "")
        self.spreadsheet_id = os.environ.get("SHEETS_SPREADSHEET_ID", "")
        self.sheet_name     = os.environ.get("SHEETS_SHEET_NAME", "QuorumAuditLog")

    async def get_package_history(self, package: str, version: str) -> dict:
        """
        Query the audit log for prior quorum events for this package.
        Returns prior_denials, prior_approvals, last_verdict, last_decided_at.
        """
        if not self.credentials or not self.spreadsheet_id:
            return {"prior_denials": 0, "prior_approvals": 0}

        try:
            token = await self._get_token()
            rows  = await self._fetch_rows(token)
            return self._parse_history(rows, package)
        except Exception as exc:
            log.warning(f"[audit_log] History query failed for {package}: {exc}")
            return {"prior_denials": 0, "prior_approvals": 0}

    async def _fetch_rows(self, token: str) -> list[list[str]]:
        range_name = f"{self.sheet_name}!A:AH"
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

        denials = approvals = 0
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

        last_verdict    = ""
        last_decided_at = ""
        if dates:
            last_decided_at = max(dates)
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
        import time
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        sa      = json.loads(base64.b64decode(self.credentials).decode())
        now     = int(time.time())
        header  = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}))
        payload = _b64url(json.dumps({
            "iss":   sa["client_email"],
            "scope": "https://www.googleapis.com/auth/spreadsheets.readonly",
            "aud":   "https://oauth2.googleapis.com/token",
            "iat":   now,
            "exp":   now + 3600,
        }))
        signing_input = f"{header}.{payload}".encode()
        private_key   = serialization.load_pem_private_key(
            sa["private_key"].encode(), password=None
        )
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        sig_b64   = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        jwt       = f"{header}.{payload}.{sig_b64}"

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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _package_filename(package: str) -> str:
    """Sanitize package name to a safe filename."""
    import re
    return re.sub(r"[/@]", "__", package).strip("_") + ".json"


def _is_fresh(path: Path) -> bool:
    """Return True if the cache file exists and is younger than _CACHE_TTL."""
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < _CACHE_TTL


def _b64url(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

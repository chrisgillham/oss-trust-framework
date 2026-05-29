"""
Gate 8 — AI Hallucination Detection
Detects package names that LLMs are known to fabricate, which attackers
then squat on. Checks against a community-maintained hallucination registry,
name similarity to popular packages, and new-package age heuristics.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import httpx
from rapidfuzz import fuzz, process as fuzz_process

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)

CACHE_PATH = Path(".oss-trust-cache/hallucinations.json")


class AIHallucinationGate:
    def __init__(self, cfg: dict) -> None:
        self.enabled             = cfg.get("enabled", True)
        self.registry_url        = cfg.get(
            "hallucination_registry_url",
            "https://api.oss-trust.dev/hallucinations"
        )
        self.cache_ttl           = cfg.get("registry_cache_ttl_hours", 6) * 3600
        self.similarity_thresh   = cfg.get("similarity_threshold", 0.85)
        self.new_package_days    = cfg.get("new_package_age_days", 90)
        self.min_downloads       = cfg.get("min_download_count", 100)
        self.on_confirmed        = cfg.get("on_confirmed_hallucination", "block")
        self.on_suspected        = cfg.get("on_suspected", "quarantine")

        # Top-N popular packages per ecosystem (seed list; registry supplements)
        self._popular_seed = {
            "pypi": [
                "requests", "numpy", "pandas", "flask", "django", "fastapi",
                "sqlalchemy", "pydantic", "httpx", "click", "pytest", "boto3",
                "pillow", "scipy", "matplotlib", "scikit-learn", "tensorflow",
                "torch", "transformers", "celery", "redis", "cryptography",
            ],
            "npm": [
                "react", "lodash", "express", "axios", "moment", "webpack",
                "babel", "typescript", "eslint", "jest", "mocha", "next",
                "vue", "angular", "gatsby", "prettier", "chalk", "commander",
                "dotenv", "uuid", "cors", "body-parser", "socket.io",
            ],
            "cargo": [
                "serde", "tokio", "rand", "clap", "log", "anyhow", "thiserror",
                "reqwest", "hyper", "axum", "actix-web", "diesel", "sqlx",
                "chrono", "regex", "uuid", "tracing", "bytes", "futures",
            ],
        }

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        if not self.enabled:
            return GateResult(
                gate="Gate 8: AI Hallucination",
                outcome=Outcome.APPROVED,
                message="AI hallucination gate disabled",
                details={"hallucination_detected": False, "skipped": True},
            )

        confirmed_list = await self._load_registry(ecosystem)
        indicators: list[str] = []
        confirmed = False

        # ── Check 1: Direct registry match ────────────────────────────────
        if package.lower() in confirmed_list:
            indicators.append(f"exact match in hallucination registry: '{package}'")
            confirmed = True

        # ── Check 2: Similarity to known popular packages ─────────────────
        popular = self._popular_seed.get(ecosystem.lower(), []) + [
            p for p in confirmed_list if p not in self._popular_seed.get(ecosystem.lower(), [])
        ]

        if not confirmed and popular:
            match = fuzz_process.extractOne(
                package.lower(),
                [p.lower() for p in popular if p.lower() != package.lower()],
                scorer=fuzz.token_sort_ratio,
            )
            if match and match[1] >= self.similarity_thresh * 100:
                matched_name = match[0]
                indicators.append(
                    f"name '{package}' is {match[1]:.0f}% similar to known package '{matched_name}'"
                )

        # ── Check 3: New package with no download history ─────────────────
        pkg_stats = await self._fetch_package_stats(package, version, ecosystem)
        if pkg_stats:
            age_days     = pkg_stats.get("age_days", 999)
            download_cnt = pkg_stats.get("total_downloads", 999)

            if age_days < self.new_package_days and download_cnt < self.min_downloads:
                indicators.append(
                    f"package is {age_days:.0f} days old with only "
                    f"{download_cnt} downloads — consistent with hallucination squat"
                )

        # ── Check 4: Hallucination suffix patterns ─────────────────────────
        HALLUCINATION_SUFFIXES = [
            "-utils", "-helper", "-helpers", "-lib", "-core",
            "-tools", "-sdk", "-client", "-api", "py-", "node-",
        ]
        for popular_name in popular[:50]:
            for suffix in HALLUCINATION_SUFFIXES:
                candidate = popular_name + suffix
                if package.lower() == candidate.lower():
                    indicators.append(
                        f"name '{package}' matches hallucination pattern "
                        f"'{popular_name}' + '{suffix}'"
                    )
                    break

        # ── Determine outcome ─────────────────────────────────────────────
        if confirmed:
            return GateResult(
                gate="Gate 8: AI Hallucination",
                outcome=self._outcome(self.on_confirmed),
                message=(
                    f"CONFIRMED hallucination: '{package}' is in the known "
                    f"AI-fabricated package registry"
                ),
                details={
                    "hallucination_detected": True,
                    "confirmed":   True,
                    "indicators":  indicators,
                    "pkg_stats":   pkg_stats or {},
                },
            )

        if indicators:
            return GateResult(
                gate="Gate 8: AI Hallucination",
                outcome=self._outcome(self.on_suspected),
                message=(
                    f"Suspected AI hallucination for '{package}': "
                    + "; ".join(indicators[:2])
                ),
                details={
                    "hallucination_detected": True,
                    "confirmed":   False,
                    "indicators":  indicators,
                    "pkg_stats":   pkg_stats or {},
                },
            )

        return GateResult(
            gate="Gate 8: AI Hallucination",
            outcome=Outcome.APPROVED,
            message=f"No hallucination indicators for '{package}'",
            details={
                "hallucination_detected": False,
                "confirmed":   False,
                "indicators":  [],
                "pkg_stats":   pkg_stats or {},
            },
        )

    async def _load_registry(self, ecosystem: str) -> list[str]:
        """Load hallucination registry from cache or fetch fresh."""
        import json

        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)

        if CACHE_PATH.exists():
            stat = CACHE_PATH.stat()
            if time.time() - stat.st_mtime < self.cache_ttl:
                data = json.loads(CACHE_PATH.read_text())
                return data.get(ecosystem.lower(), [])

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    self.registry_url,
                    params={"ecosystem": ecosystem.lower()},
                )
                r.raise_for_status()
                data = r.json()
            CACHE_PATH.write_text(json.dumps(data))
            return data.get(ecosystem.lower(), [])
        except Exception as exc:
            log.warning(f"[ai_hallucination] Registry fetch failed: {exc}")
            # Return empty list on failure; other checks still run
            return []

    async def _fetch_package_stats(
        self, package: str, version: str, ecosystem: str
    ) -> dict | None:
        """Fetch basic package metadata (age, downloads) from registry."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                eco = ecosystem.lower()
                if eco == "pypi":
                    r = await client.get(f"https://pypi.org/pypi/{package}/json")
                    r.raise_for_status()
                    info = r.json()
                    from datetime import datetime, timezone
                    releases = info.get("releases", {})
                    all_dates = [
                        u["upload_time_iso_8601"]
                        for v_list in releases.values()
                        for u in v_list
                    ]
                    if all_dates:
                        first = datetime.fromisoformat(
                            min(all_dates).replace("Z", "+00:00")
                        )
                        age = (datetime.now(timezone.utc) - first).days
                    else:
                        age = 0
                    return {"age_days": age, "total_downloads": None}

                if eco == "npm":
                    r = await client.get(f"https://registry.npmjs.org/{package}")
                    r.raise_for_status()
                    data = r.json()
                    created = data.get("time", {}).get("created", "")
                    if created:
                        from datetime import datetime, timezone
                        first = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        age = (datetime.now(timezone.utc) - first).days
                    else:
                        age = 0
                    return {"age_days": age, "total_downloads": None}
        except Exception as exc:
            log.debug(f"[ai_hallucination] Stats fetch failed for {package}: {exc}")
        return None

    def _outcome(self, action: str) -> str:
        return {
            "block":      Outcome.BLOCKED,
            "quarantine": Outcome.QUARANTINE,
            "hold":       Outcome.HOLD,
        }.get(action, Outcome.QUARANTINE)

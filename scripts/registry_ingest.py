#!/usr/bin/env python3
"""
registry_ingest.py
──────────────────
Processes a single registry contribution payload and merges it into the
appropriate package file in registry/packages/{ecosystem}/{package}.json.
Rebuilds registry/index.json after every successful merge.

Called by .github/workflows/registry-ingest.yml with:
  python scripts/registry_ingest.py --payload '<json>' --issue-number 42

Exits 0 on success, 1 on validation failure (workflow then labels and
closes the issue with a rejection comment).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

REGISTRY_ROOT   = Path("registry/packages")
INDEX_PATH      = Path("registry/index.json")
SCHEMA_VERSION  = "1.0"
VALID_ECOSYSTEMS = frozenset(
    {"npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"}
)
VALID_BANDS     = frozenset({"HIGH", "MEDIUM", "LOW"})
VALID_VERDICTS  = frozenset({"APPROVED", "DENIED", "EXPIRED"})
VALID_SIGNALS   = frozenset({
    "typosquatting", "behavior_change", "author_reputation",
    "provenance_activity", "ai_hallucination",
    "no_signature", "weak_signature", "no_checksum",
})
# Regex patterns that indicate PII — reject any field matching these
PII_PATTERNS = [
    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),  # email
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                          # IPv4
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),  # UUID/GUID
]
PACKAGE_NAME_RE = re.compile(r"^[@a-zA-Z0-9/_.\-]{1,200}$")
VERSION_RE      = re.compile(r"^[a-zA-Z0-9._+\-]{1,50}$")
SHA256_RE       = re.compile(r"^[0-9a-f]{64}$")


# ── Validation ────────────────────────────────────────────────────────────────

def validate(payload: dict) -> list[str]:
    """Return list of error strings. Empty = valid."""
    errors: list[str] = []

    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be '{SCHEMA_VERSION}'")

    pkg = payload.get("package", "")
    if not PACKAGE_NAME_RE.match(pkg):
        errors.append(f"Invalid package name: {pkg!r}")

    ver = payload.get("version", "")
    if not VERSION_RE.match(ver):
        errors.append(f"Invalid version: {ver!r}")

    eco = payload.get("ecosystem", "")
    if eco not in VALID_ECOSYSTEMS:
        errors.append(f"ecosystem must be one of {sorted(VALID_ECOSYSTEMS)}")

    band = payload.get("trust_band", "")
    if band not in VALID_BANDS:
        errors.append(f"trust_band must be one of {sorted(VALID_BANDS)}")

    verdict = payload.get("verdict", "")
    if verdict not in VALID_VERDICTS:
        errors.append(f"verdict must be one of {sorted(VALID_VERDICTS)}")

    slsa = payload.get("slsa_level")
    if not isinstance(slsa, int) or slsa < 0 or slsa > 4:
        errors.append("slsa_level must be integer 0–4")

    signals = payload.get("signals_fired", {})
    if not isinstance(signals, dict):
        errors.append("signals_fired must be an object")
    else:
        extra = set(signals.keys()) - VALID_SIGNALS
        if extra:
            errors.append(f"Unknown signal keys: {sorted(extra)}")
        non_bool = {k: v for k, v in signals.items() if not isinstance(v, bool)}
        if non_bool:
            errors.append(f"signals_fired values must be boolean: {non_bool}")

    contrib_id = payload.get("contribution_id", "")
    if not SHA256_RE.match(contrib_id):
        errors.append("contribution_id must be a SHA-256 hex string (64 chars)")

    # PII scan across all string values
    def scan_pii(obj, path=""):
        if isinstance(obj, str):
            for pat in PII_PATTERNS:
                if pat.search(obj):
                    errors.append(f"PII detected in field '{path}': {obj[:40]!r}")
                    break
        elif isinstance(obj, dict):
            for k, v in obj.items():
                scan_pii(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                scan_pii(v, f"{path}[{i}]")

    scan_pii(payload)

    return errors


# ── Package file management ───────────────────────────────────────────────────

def package_filename(package: str) -> str:
    """Sanitize package name to a safe filename. Handles scoped npm packages."""
    return re.sub(r"[/@]", "__", package).strip("_") + ".json"


def load_package_file(eco: str, package: str) -> dict:
    path = REGISTRY_ROOT / eco / package_filename(package)
    if path.exists():
        return json.loads(path.read_text())
    return {
        "package":   package,
        "ecosystem": eco,
        "updated_at": "",
        "contribution_count": 0,
        "aggregate": {
            "approved_count":   0,
            "denied_count":     0,
            "expired_count":    0,
            "band_votes":       {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "community_band":   "",
            "slsa_levels_observed": [],
            "signal_fire_counts": {s: 0 for s in VALID_SIGNALS},
        },
        "versions": {},
    }


def merge_contribution(pkg_data: dict, payload: dict) -> dict:
    """Merge one contribution into the package aggregate and version record."""
    now     = datetime.now(timezone.utc).isoformat()
    verdict = payload["verdict"]
    band    = payload["trust_band"]
    version = payload["version"]
    slsa    = payload["slsa_level"]
    signals = payload.get("signals_fired", {})

    # ── Package-level aggregate ───────────────────────────────────────────────
    agg = pkg_data["aggregate"]
    pkg_data["contribution_count"] = pkg_data.get("contribution_count", 0) + 1
    pkg_data["updated_at"] = now

    if verdict == "APPROVED":
        agg["approved_count"] += 1
    elif verdict == "DENIED":
        agg["denied_count"] += 1
    elif verdict == "EXPIRED":
        agg["expired_count"] += 1

    agg["band_votes"][band] = agg["band_votes"].get(band, 0) + 1

    if slsa not in agg["slsa_levels_observed"]:
        agg["slsa_levels_observed"].append(slsa)
        agg["slsa_levels_observed"].sort()

    for signal, fired in signals.items():
        if fired:
            agg["signal_fire_counts"][signal] = (
                agg["signal_fire_counts"].get(signal, 0) + 1
            )

    agg["community_band"] = compute_community_band(
        agg["approved_count"] + agg["denied_count"] + agg["expired_count"],
        agg["denied_count"],
        agg["band_votes"],
    )

    # ── Version-level record ──────────────────────────────────────────────────
    versions = pkg_data.setdefault("versions", {})
    if version not in versions:
        versions[version] = {
            "contribution_count":   0,
            "approved_count":       0,
            "denied_count":         0,
            "expired_count":        0,
            "community_band":       "",
            "slsa_levels_observed": [],
            "signal_fire_counts":   {s: 0 for s in VALID_SIGNALS},
            "first_seen":           now,
            "last_updated":         now,
        }

    vr = versions[version]
    vr["contribution_count"] += 1
    vr["last_updated"] = now

    if verdict == "APPROVED":
        vr["approved_count"] += 1
    elif verdict == "DENIED":
        vr["denied_count"] += 1
    elif verdict == "EXPIRED":
        vr["expired_count"] += 1

    if slsa not in vr["slsa_levels_observed"]:
        vr["slsa_levels_observed"].append(slsa)
        vr["slsa_levels_observed"].sort()

    for signal, fired in signals.items():
        if fired:
            vr["signal_fire_counts"][signal] = (
                vr["signal_fire_counts"].get(signal, 0) + 1
            )

    vr["community_band"] = compute_community_band(
        vr["approved_count"] + vr["denied_count"] + vr["expired_count"],
        vr["denied_count"],
        {  # version doesn't track band_votes separately; infer from denied ratio
            "HIGH": vr["approved_count"],
            "MEDIUM": 0,
            "LOW": vr["denied_count"],
        },
    )

    return pkg_data


def compute_community_band(total: int, denied: int, band_votes: dict) -> str:
    """
    Compute the community band from aggregate counts.
      LOW    if >50% denied verdicts
      LOW    if >50% LOW band votes
      MEDIUM if >25% LOW band votes
      HIGH   otherwise
    """
    if total == 0:
        return ""
    low_votes = band_votes.get("LOW", 0)
    if denied / total > 0.5:
        return "LOW"
    if low_votes / total > 0.5:
        return "LOW"
    if low_votes / total > 0.25:
        return "MEDIUM"
    return "HIGH"


def save_package_file(eco: str, package: str, data: dict) -> Path:
    path = REGISTRY_ROOT / eco / package_filename(package)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
    return path


# ── Index rebuild ─────────────────────────────────────────────────────────────

def rebuild_index() -> None:
    entries: dict[str, dict] = {}

    for pkg_file in sorted(REGISTRY_ROOT.rglob("*.json")):
        try:
            data = json.loads(pkg_file.read_text())
            if "_comment" in data:
                continue   # Skip example/seed files
            eco  = data.get("ecosystem", "")
            pkg  = data.get("package", "")
            band = data.get("aggregate", {}).get("community_band", "")
            count = data.get("contribution_count", 0)
            updated = data.get("updated_at", "")

            if eco and pkg:
                key = f"{eco}/{pkg}"
                entries[key] = {
                    "path":               str(pkg_file),
                    "community_band":     band,
                    "contribution_count": count,
                    "last_updated":       updated,
                }
        except (json.JSONDecodeError, KeyError):
            pass

    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entry_count":  len(entries),
        "entries":      entries,
    }
    INDEX_PATH.write_text(json.dumps(index, indent=2) + "\n")
    print(f"[ingest] Index rebuilt — {len(entries)} entries")


# ── Deduplication ─────────────────────────────────────────────────────────────

SEEN_IDS_PATH = Path("registry/.seen_contribution_ids.json")

def load_seen_ids() -> set[str]:
    if SEEN_IDS_PATH.exists():
        return set(json.loads(SEEN_IDS_PATH.read_text()))
    return set()

def record_seen_id(contrib_id: str) -> None:
    seen = load_seen_ids()
    seen.add(contrib_id)
    # Keep only the last 10,000 IDs to bound file size
    ids_list = sorted(seen)[-10_000:]
    SEEN_IDS_PATH.write_text(json.dumps(ids_list, indent=2) + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload",      required=True, help="JSON contribution payload")
    parser.add_argument("--issue-number", required=True, help="GitHub issue number (for logging)")
    args = parser.parse_args()

    print(f"[ingest] Processing contribution from issue #{args.issue_number}")

    # Parse
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        print(f"[ingest] ERROR: Invalid JSON — {exc}", file=sys.stderr)
        sys.exit(1)

    # Validate
    errors = validate(payload)
    if errors:
        print("[ingest] VALIDATION FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    # Deduplication
    contrib_id = payload["contribution_id"]
    seen = load_seen_ids()
    if contrib_id in seen:
        print(f"[ingest] DUPLICATE contribution_id {contrib_id} — skipping", file=sys.stderr)
        sys.exit(1)

    eco     = payload["ecosystem"]
    package = payload["package"]
    version = payload["version"]

    # Load, merge, save
    pkg_data = load_package_file(eco, package)
    pkg_data = merge_contribution(pkg_data, payload)
    saved_path = save_package_file(eco, package, pkg_data)
    print(f"[ingest] Merged into {saved_path}")

    # Record dedup ID
    record_seen_id(contrib_id)

    # Rebuild index
    rebuild_index()

    print(f"[ingest] ✅ Contribution accepted: {eco}/{package}@{version} ({payload['verdict']})")


if __name__ == "__main__":
    main()

"""
Gate 9 — CI/CD Pipeline Self-Audit
Scans .github/workflows/*.yml for supply-chain vulnerabilities in the
CI/CD pipeline itself: mutable action tags, new third-party actions,
pull_request_target privilege escalation, and script injection patterns.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import yaml

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)

# SHA pattern: exactly 40 hex chars
SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

# Detects ${{ github.event.* }} interpolation in run: blocks (script injection)
INJECTION_RE = re.compile(r"\$\{\{\s*github\.event\.", re.IGNORECASE)

# pull_request_target with write-level permissions is a known escalation pattern
PRT_WRITE_PERMS = {"contents": "write", "pull-requests": "write", "issues": "write"}


class CICDAuditGate:
    def __init__(self, cfg: dict) -> None:
        self.enabled           = cfg.get("enabled", True)
        self.require_sha       = cfg.get("require_sha_pinning", True)
        self.new_action_action = cfg.get("new_action_action", "hold")
        self.inventory_path    = Path(cfg.get(
            "approved_action_inventory", ".github/approved-actions.json"
        ))
        self.flag_prt          = cfg.get("flag_pull_request_target", True)
        self.flag_injection    = cfg.get("flag_script_injection", True)

    async def evaluate(self) -> GateResult:
        if not self.enabled:
            return GateResult(
                gate="Gate 9: CI/CD Audit",
                outcome=Outcome.APPROVED,
                message="CI/CD audit disabled",
                details={"skipped": True},
            )

        workflow_dir = Path(".github/workflows")
        if not workflow_dir.exists():
            return GateResult(
                gate="Gate 9: CI/CD Audit",
                outcome=Outcome.APPROVED,
                message="No .github/workflows directory found",
                details={"workflow_count": 0},
            )

        approved = self._load_inventory()
        findings: list[dict] = []

        for wf_path in sorted(workflow_dir.glob("*.yml")):
            try:
                wf_findings = self._audit_workflow(wf_path, approved)
                findings.extend(wf_findings)
            except Exception as exc:
                log.warning(f"[cicd] Failed to parse {wf_path}: {exc}")
                findings.append({
                    "file":     str(wf_path),
                    "severity": "hold",
                    "message":  f"Parse error: {exc}",
                })

        blocked_findings    = [f for f in findings if f["severity"] == "block"]
        quarantine_findings = [f for f in findings if f["severity"] == "quarantine"]
        hold_findings       = [f for f in findings if f["severity"] == "hold"]

        if blocked_findings:
            return GateResult(
                gate="Gate 9: CI/CD Audit",
                outcome=Outcome.BLOCKED,
                message=(
                    f"{len(blocked_findings)} critical CI/CD security issue(s): "
                    + "; ".join(f["message"] for f in blocked_findings[:2])
                ),
                details={"findings": findings},
            )

        if quarantine_findings:
            return GateResult(
                gate="Gate 9: CI/CD Audit",
                outcome=Outcome.QUARANTINE,
                message=(
                    f"{len(quarantine_findings)} CI/CD security issue(s): "
                    + "; ".join(f["message"] for f in quarantine_findings[:2])
                ),
                details={"findings": findings},
            )

        if hold_findings:
            return GateResult(
                gate="Gate 9: CI/CD Audit",
                outcome=Outcome.HOLD,
                message=(
                    f"{len(hold_findings)} CI/CD advisory finding(s): "
                    + "; ".join(f["message"] for f in hold_findings[:2])
                ),
                details={"findings": findings},
            )

        return GateResult(
            gate="Gate 9: CI/CD Audit",
            outcome=Outcome.APPROVED,
            message=(
                f"CI/CD pipeline audit passed "
                f"({len(list(workflow_dir.glob('*.yml')))} workflow(s) scanned)"
            ),
            details={"findings": [], "workflow_count": len(list(workflow_dir.glob("*.yml")))},
        )

    def _audit_workflow(self, path: Path, approved: dict) -> list[dict]:
        findings: list[dict] = []
        text = path.read_text()
        data = yaml.safe_load(text) or {}

        triggers = data.get("on", data.get(True, {}))   # 'on' is parsed as True in YAML
        is_prt   = isinstance(triggers, dict) and "pull_request_target" in triggers

        # ── pull_request_target with write permissions ─────────────────────
        if self.flag_prt and is_prt:
            perms = data.get("permissions", {})
            if isinstance(perms, dict):
                write_perms = [
                    k for k, v in perms.items()
                    if isinstance(v, str) and v.lower() == "write"
                ]
                if write_perms:
                    findings.append({
                        "file":     str(path),
                        "severity": "block",
                        "message":  (
                            f"{path.name}: pull_request_target with write "
                            f"permissions ({', '.join(write_perms)}) — "
                            f"privilege escalation risk"
                        ),
                    })

        # ── Script injection ───────────────────────────────────────────────
        if self.flag_injection:
            for match in INJECTION_RE.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                findings.append({
                    "file":     str(path),
                    "severity": "quarantine",
                    "message":  (
                        f"{path.name}:{line_num}: github.event.* interpolation "
                        f"in run step — script injection risk"
                    ),
                })

        # ── Action pin auditing ────────────────────────────────────────────
        for job_name, job in (data.get("jobs") or {}).items():
            for step in (job.get("steps") or []):
                uses = step.get("uses", "")
                if not uses or uses.startswith("./"):
                    continue   # Local action — not third-party

                action, _, ref = uses.partition("@")
                if not ref:
                    continue

                # Check SHA pinning
                if self.require_sha and not SHA_RE.match(ref):
                    severity = "quarantine"
                    findings.append({
                        "file":     str(path),
                        "severity": severity,
                        "message":  (
                            f"{path.name} / {job_name}: action '{uses}' is not "
                            f"pinned to a commit SHA — use a full 40-char SHA instead of '{ref}'"
                        ),
                        "action":   action,
                        "ref":      ref,
                    })

                # Check approved inventory
                action_key = f"{action}@{ref}"
                if action_key not in approved:
                    out = self._outcome(self.new_action_action)
                    findings.append({
                        "file":     str(path),
                        "severity": out,
                        "message":  (
                            f"{path.name} / {job_name}: new/unapproved action "
                            f"'{uses}' — add to .github/approved-actions.json after review"
                        ),
                        "action":   action,
                        "ref":      ref,
                    })

        return findings

    def _load_inventory(self) -> dict[str, dict]:
        """Load approved-actions.json. Keys are 'action@sha'."""
        if not self.inventory_path.exists():
            return {}
        data = json.loads(self.inventory_path.read_text())
        return {
            f"{entry['action']}@{entry['sha']}": entry
            for entry in data.get("approved", [])
        }

    def _outcome(self, action: str) -> str:
        return {"quarantine": "quarantine", "hold": "hold", "block": "block"}.get(
            action, "hold"
        )

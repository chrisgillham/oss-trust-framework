"""
Runtime Telemetry — Post-Merge SIEM Integration
Emits structured events to a Splunk HEC endpoint (or compatible) throughout
the 30-day monitoring window. Handles anomaly webhook callbacks that re-open
the Discord quorum with elevated requirements.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import httpx

log = logging.getLogger(__name__)

# ── Event type constants ──────────────────────────────────────────────────────

class Event:
    GATE_EVALUATED          = "OSS_TRUST_GATE_EVALUATED"
    PACKAGE_APPROVED        = "OSS_TRUST_PACKAGE_APPROVED"
    PACKAGE_DENIED          = "OSS_TRUST_PACKAGE_DENIED"
    PACKAGE_DEPLOYED        = "OSS_TRUST_PACKAGE_DEPLOYED"
    MONITORING_WINDOW_OPEN  = "OSS_TRUST_MONITORING_WINDOW_OPEN"
    MONITORING_WINDOW_CLOSE = "OSS_TRUST_MONITORING_WINDOW_CLOSE"
    RUNTIME_ANOMALY         = "OSS_TRUST_RUNTIME_ANOMALY"
    QUORUM_REOPENED         = "OSS_TRUST_QUORUM_REOPENED"
    ZERO_DAY_EXCEPTION      = "OSS_TRUST_ZERO_DAY_EXCEPTION"


class RuntimeTelemetry:
    def __init__(self, cfg: dict) -> None:
        self.hec_endpoint    = cfg.get("siem_hec_endpoint", "").strip("${}")
        self.hec_token       = cfg.get("siem_hec_token", "").strip("${}")
        self.anomaly_webhook = cfg.get("anomaly_webhook", "").strip("${}")
        self.window_days     = cfg.get("monitoring_window_days", 30)
        self.elevated_hours  = cfg.get("elevated_alert_hours", 48)
        self.rollback_cfg    = cfg.get("rollback", {})

        # Resolve env vars if the config contains variable references
        self.hec_endpoint    = os.environ.get("SIEM_HEC_ENDPOINT",    self.hec_endpoint)
        self.hec_token       = os.environ.get("SIEM_HEC_TOKEN",       self.hec_token)
        self.anomaly_webhook = os.environ.get("ANOMALY_WEBHOOK_URL",  self.anomaly_webhook)

    # ── Public API ────────────────────────────────────────────────────────────

    async def emit_gate_event(self, result) -> None:  # result: TrustResult
        """Emit a structured telemetry event for a completed pipeline evaluation."""
        event = {
            "event_type":    Event.GATE_EVALUATED,
            "package":       result.package,
            "version":       result.version,
            "ecosystem":     result.ecosystem,
            "outcome":       result.outcome,
            "trust_score":   result.trust_score,
            "trust_level":   result.trust_level,
            "slsa_level":    result.slsa.get("level", 0),
            "sig_present":   result.signature.get("present", False),
            "sig_verified":  result.signature.get("verified"),
            "flags":         result.flags,
            "policy_applied": result.policy_applied,
            "gate_count":    len(result.gate_results),
            "evaluated_at":  result.evaluated_at,
            "pipeline_version": result.pipeline_version,
        }
        await self._emit(event)

    async def emit_quorum_event(
        self,
        result,
        verdict: str,
        quorum_id: str,
        tally: dict,
    ) -> None:
        """Emit telemetry when a quorum vote resolves."""
        event_type = (
            Event.PACKAGE_APPROVED if verdict == "APPROVED"
            else Event.PACKAGE_DENIED
        )
        window_expires = (
            (datetime.now(timezone.utc) + timedelta(days=self.window_days)).isoformat()
            if verdict == "APPROVED"
            else None
        )
        event = {
            "event_type":               event_type,
            "quorum_id":                quorum_id,
            "package":                  result.package,
            "version":                  result.version,
            "ecosystem":                result.ecosystem,
            "verdict":                  verdict,
            "trust_score":              result.trust_score,
            "trust_level":              result.trust_level,
            "approve_count":            tally.get("approve", 0),
            "deny_count":               tally.get("deny", 0),
            "abstain_count":            tally.get("abstain", 0),
            "policy_applied":           result.policy_applied,
            "effective_threshold":      result.effective_threshold,
            "runtime_monitoring_expires": window_expires,
            "decided_at":               datetime.now(timezone.utc).isoformat(),
        }
        await self._emit(event)

    async def open_monitoring_window(
        self,
        package: str,
        version: str,
        ecosystem: str,
        quorum_id: str,
        deploy_id: str = "",
        environment: str = "production",
    ) -> str:
        """Called on merge/deploy. Returns the window expiry ISO timestamp."""
        expires = (
            datetime.now(timezone.utc) + timedelta(days=self.window_days)
        ).isoformat()

        event = {
            "event_type":    Event.MONITORING_WINDOW_OPEN,
            "package":       package,
            "version":       version,
            "ecosystem":     ecosystem,
            "quorum_id":     quorum_id,
            "deploy_id":     deploy_id,
            "environment":   environment,
            "window_expires_at": expires,
            "elevated_alert_until": (
                datetime.now(timezone.utc) + timedelta(hours=self.elevated_hours)
            ).isoformat(),
            "opened_at":     datetime.now(timezone.utc).isoformat(),
        }
        await self._emit(event)
        return expires

    async def close_monitoring_window(
        self,
        package: str,
        version: str,
        quorum_id: str,
        anomaly_count: int = 0,
    ) -> None:
        event = {
            "event_type":    Event.MONITORING_WINDOW_CLOSE,
            "package":       package,
            "version":       version,
            "quorum_id":     quorum_id,
            "anomaly_count": anomaly_count,
            "clean":         anomaly_count == 0,
            "closed_at":     datetime.now(timezone.utc).isoformat(),
        }
        await self._emit(event)

    async def handle_anomaly(self, payload: dict) -> dict:
        """
        Called by the anomaly webhook endpoint when your SIEM fires an alert.
        Emits a RUNTIME_ANOMALY event and triggers quorum re-open if configured.

        Expected payload fields:
          package, version, quorum_id, anomaly_type, severity,
          days_since_approval, environment
        """
        package          = payload.get("package", "")
        version          = payload.get("version", "")
        quorum_id        = payload.get("quorum_id", "")
        anomaly_type     = payload.get("anomaly_type", "unknown")
        severity         = payload.get("severity", "medium")
        days_since       = payload.get("days_since_approval", 0)

        log.warning(
            f"[runtime] Anomaly detected: {package}@{version} "
            f"({anomaly_type}, severity={severity}, day {days_since} of window)"
        )

        anomaly_event = {
            "event_type":          Event.RUNTIME_ANOMALY,
            "package":             package,
            "version":             version,
            "quorum_id":           quorum_id,
            "anomaly_type":        anomaly_type,
            "severity":            severity,
            "days_since_approval": days_since,
            "environment":         payload.get("environment", "unknown"),
            "detected_at":         datetime.now(timezone.utc).isoformat(),
        }
        await self._emit(anomaly_event)

        # Re-open quorum if within monitoring window
        if days_since <= self.window_days:
            reopen_event = {
                "event_type":          Event.QUORUM_REOPENED,
                "package":             package,
                "version":             version,
                "original_quorum_id":  quorum_id,
                "escalation_reason":   f"Runtime anomaly: {anomaly_type}",
                "severity":            severity,
                "reopened_at":         datetime.now(timezone.utc).isoformat(),
            }
            await self._emit(reopen_event)
            return {
                "action":  "quorum_reopened",
                "reason":  f"Runtime anomaly within {self.window_days}-day window",
                "payload": reopen_event,
            }

        return {"action": "logged", "reason": "Outside monitoring window"}

    async def trigger_rollback(
        self,
        package: str,
        version: str,
        quorum_id: str,
    ) -> dict:
        """
        Invoke the configured rollback adapter when unanimous revocation quorum passes.
        Supports: helm, ansible, kubectl, terraform, custom webhook.
        """
        adapter    = self.rollback_cfg.get("adapter", "none")
        dry_run    = self.rollback_cfg.get("dry_run", True)
        timeout_m  = self.rollback_cfg.get("rollback_timeout_minutes", 15)

        log.warning(
            f"[runtime] Triggering rollback for {package}@{version} "
            f"via {adapter} (dry_run={dry_run})"
        )

        result = {"adapter": adapter, "dry_run": dry_run, "status": "not_run"}

        if dry_run:
            result["status"] = "dry_run_skipped"
            return result

        if adapter == "helm":
            result["status"] = await self._helm_rollback(package, version, timeout_m)
        elif adapter == "kubectl":
            result["status"] = await self._kubectl_rollback(package, version, timeout_m)
        elif adapter == "custom":
            result["status"] = await self._custom_rollback(package, version, quorum_id)
        else:
            result["status"] = f"adapter '{adapter}' not implemented"

        await self._emit({
            "event_type": "OSS_TRUST_ROLLBACK_TRIGGERED",
            "package":    package,
            "version":    version,
            "quorum_id":  quorum_id,
            "adapter":    adapter,
            "status":     result["status"],
            "triggered_at": datetime.now(timezone.utc).isoformat(),
        })

        return result

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _emit(self, event: dict) -> None:
        """POST a structured event to the Splunk HEC endpoint."""
        if not self.hec_endpoint or not self.hec_token:
            log.debug(f"[runtime] SIEM not configured — event dropped: {event.get('event_type')}")
            return

        # Ensure event has a timestamp
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        event.setdefault("source",    "oss-trust-framework")
        event.setdefault("sourcetype", "oss_trust:pipeline")

        payload = json.dumps({"event": event})

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    self.hec_endpoint,
                    content=payload,
                    headers={
                        "Authorization": f"Splunk {self.hec_token}",
                        "Content-Type":  "application/json",
                    },
                )
                if r.status_code not in (200, 201):
                    log.warning(
                        f"[runtime] HEC returned {r.status_code}: {r.text[:200]}"
                    )
        except Exception as exc:
            log.warning(f"[runtime] SIEM emit failed: {exc}")

    async def _helm_rollback(self, package: str, version: str, timeout_m: int) -> str:
        import asyncio
        # Derive release name from package name (convention: org-package)
        release = package.replace("_", "-").lower()
        proc = await asyncio.create_subprocess_exec(
            "helm", "rollback", release, "0",
            "--wait", f"--timeout={timeout_m}m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            log.error(f"[runtime] Helm rollback failed: {stderr.decode()}")
            return f"failed: {stderr.decode()[:200]}"
        return "success"

    async def _kubectl_rollback(self, package: str, version: str, timeout_m: int) -> str:
        import asyncio
        deployment = package.replace("_", "-").replace(".", "-").lower()
        proc = await asyncio.create_subprocess_exec(
            "kubectl", "rollout", "undo", f"deployment/{deployment}",
            "--timeout", f"{timeout_m}m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        return "success" if proc.returncode == 0 else f"failed: {stderr.decode()[:200]}"

    async def _custom_rollback(self, package: str, version: str, quorum_id: str) -> str:
        webhook_url = os.environ.get("ROLLBACK_WEBHOOK_URL", "")
        if not webhook_url:
            return "custom_webhook_not_configured"
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                webhook_url,
                json={"package": package, "version": version, "quorum_id": quorum_id},
            )
            return "success" if r.status_code < 300 else f"failed: {r.status_code}"

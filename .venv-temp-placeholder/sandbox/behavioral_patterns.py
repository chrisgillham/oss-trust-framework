"""
Gate 5 enhancement — Miasma-class behavioral pattern matching.

Miasma v2 (the Red Hat / Shai-Hulud variant) changed two things that make
simple hash-based detection ineffective:

  1. Unique per-infection encrypted payloads — hash IOCs are version-specific.
  2. Focus on cloud identity theft (GCP, Azure IMDS) rather than static secrets.

This module defines behavioral signatures that detect the *pattern* of what
Miasma does, regardless of how the payload is encrypted or obfuscated.

These patterns are fed to the behavioral sandbox (Gate 5) as alert rules.
The sandbox runner (src/sandbox/runner.py) is responsible for executing the
package install in an isolated environment and reporting which of these
patterns fired.

Pattern categories:
  - CLOUD_METADATA_ACCESS   — requests to instance metadata endpoints
  - OIDC_TOKEN_REQUEST      — requests to GitHub/Google/Azure OIDC token endpoints
  - CREDENTIAL_FILE_READ    — access to well-known credential file paths
  - REGISTRY_PUBLISH        — outbound PUT to a package registry during install
  - ENCRYPTED_EXFIL         — encrypted outbound connection from install context
  - PROCESS_INJECTION       — subprocess spawn with obfuscated arguments
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class PatternCategory(str, Enum):
    CLOUD_METADATA_ACCESS = "cloud_metadata_access"
    OIDC_TOKEN_REQUEST = "oidc_token_request"
    CREDENTIAL_FILE_READ = "credential_file_read"
    REGISTRY_PUBLISH = "registry_publish"
    ENCRYPTED_EXFIL = "encrypted_exfil"
    PROCESS_INJECTION = "process_injection"
    ENV_VAR_HARVEST = "env_var_harvest"


@dataclass
class BehavioralPattern:
    id: str
    category: PatternCategory
    description: str
    severity: str           # CRITICAL | HIGH | MEDIUM
    # For network patterns: destination match (substring or regex)
    network_destination: str | None = None
    # For file patterns: path prefix match
    file_path_prefix: str | None = None
    # For process patterns: command fragment match
    process_command_fragment: str | None = None
    # For env var patterns: variable name pattern
    env_var_pattern: str | None = None
    miasma_specific: bool = False   # True = directly observed in Miasma/Shai-Hulud


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

BEHAVIORAL_PATTERNS: list[BehavioralPattern] = [

    # --- Cloud metadata endpoint access (Miasma primary exfil target) ---
    BehavioralPattern(
        id="MIASMA-001",
        category=PatternCategory.CLOUD_METADATA_ACCESS,
        description="Request to AWS/Azure/GCP instance metadata service (IMDS)",
        severity="CRITICAL",
        network_destination="169.254.169.254",
        miasma_specific=True,
    ),
    BehavioralPattern(
        id="MIASMA-002",
        category=PatternCategory.CLOUD_METADATA_ACCESS,
        description="Request to GCP metadata server",
        severity="CRITICAL",
        network_destination="metadata.google.internal",
        miasma_specific=True,
    ),
    BehavioralPattern(
        id="MIASMA-003",
        category=PatternCategory.CLOUD_METADATA_ACCESS,
        description="Request to Azure IMDS endpoint",
        severity="CRITICAL",
        network_destination="169.254.169.254/metadata",
        miasma_specific=True,
    ),
    BehavioralPattern(
        id="MIASMA-004",
        category=PatternCategory.CLOUD_METADATA_ACCESS,
        description="Request to EKS/GKE/AKS cluster API from install context",
        severity="HIGH",
        network_destination="kubernetes.default.svc",
        miasma_specific=True,
    ),

    # --- OIDC token requests (Miasma uses these for npm trusted publishing) ---
    BehavioralPattern(
        id="MIASMA-010",
        category=PatternCategory.OIDC_TOKEN_REQUEST,
        description="Request to GitHub Actions OIDC token endpoint",
        severity="CRITICAL",
        network_destination="token.actions.githubusercontent.com",
        miasma_specific=True,
    ),
    BehavioralPattern(
        id="MIASMA-011",
        category=PatternCategory.OIDC_TOKEN_REQUEST,
        description="Request to Google Cloud OIDC token endpoint",
        severity="HIGH",
        network_destination="oauth2.googleapis.com/token",
        miasma_specific=True,
    ),
    BehavioralPattern(
        id="MIASMA-012",
        category=PatternCategory.OIDC_TOKEN_REQUEST,
        description="Request to Azure AD OIDC token endpoint",
        severity="HIGH",
        network_destination="login.microsoftonline.com",
        miasma_specific=False,  # Also used in legitimate auth flows
    ),

    # --- Credential file access ---
    BehavioralPattern(
        id="CRED-001",
        category=PatternCategory.CREDENTIAL_FILE_READ,
        description="Read from Kubernetes service account token path",
        severity="CRITICAL",
        file_path_prefix="/var/run/secrets/kubernetes.io",
    ),
    BehavioralPattern(
        id="CRED-002",
        category=PatternCategory.CREDENTIAL_FILE_READ,
        description="Read from GCP application default credentials",
        severity="HIGH",
        file_path_prefix="/root/.config/gcloud",
    ),
    BehavioralPattern(
        id="CRED-003",
        category=PatternCategory.CREDENTIAL_FILE_READ,
        description="Read from AWS credentials file",
        severity="HIGH",
        file_path_prefix="/root/.aws/credentials",
    ),
    BehavioralPattern(
        id="CRED-004",
        category=PatternCategory.CREDENTIAL_FILE_READ,
        description="Read from Azure CLI credentials",
        severity="HIGH",
        file_path_prefix="/root/.azure",
    ),
    BehavioralPattern(
        id="CRED-005",
        category=PatternCategory.CREDENTIAL_FILE_READ,
        description="Read from SSH private key directory",
        severity="HIGH",
        file_path_prefix="/root/.ssh",
    ),

    # --- Registry publish from install context ---
    BehavioralPattern(
        id="PUBLISH-001",
        category=PatternCategory.REGISTRY_PUBLISH,
        description="HTTP PUT to npm registry during package install (re-publish attack)",
        severity="CRITICAL",
        network_destination="registry.npmjs.org",
        miasma_specific=True,
    ),
    BehavioralPattern(
        id="PUBLISH-002",
        category=PatternCategory.REGISTRY_PUBLISH,
        description="HTTP POST to PyPI upload endpoint during package install",
        severity="CRITICAL",
        network_destination="upload.pypi.org",
    ),

    # --- Environment variable harvesting ---
    BehavioralPattern(
        id="ENV-001",
        category=PatternCategory.ENV_VAR_HARVEST,
        description="Enumeration of all environment variables (os.environ / process.env)",
        severity="HIGH",
        env_var_pattern=r"(os\.environ|process\.env)\b",
    ),
    BehavioralPattern(
        id="ENV-002",
        category=PatternCategory.ENV_VAR_HARVEST,
        description="Access to OIDC_PACKAGES or similar CI-injected env vars",
        severity="CRITICAL",
        env_var_pattern=r"OIDC_PACKAGES|GITHUB_TOKEN|CI_TOKEN|NPM_TOKEN",
        miasma_specific=True,
    ),

    # --- Process injection / obfuscated subprocess ---
    BehavioralPattern(
        id="PROC-001",
        category=PatternCategory.PROCESS_INJECTION,
        description="Base64-encoded command execution via shell",
        severity="HIGH",
        process_command_fragment="base64",
    ),
    BehavioralPattern(
        id="PROC-002",
        category=PatternCategory.PROCESS_INJECTION,
        description="curl/wget piped to shell from install script",
        severity="CRITICAL",
        process_command_fragment="curl.*|.*sh",
    ),
    BehavioralPattern(
        id="PROC-003",
        category=PatternCategory.PROCESS_INJECTION,
        description="Python eval/exec with encoded payload",
        severity="HIGH",
        process_command_fragment=r"exec\(.*decode|eval\(.*b64",
    ),
]


# ---------------------------------------------------------------------------
# Pattern evaluation utilities
# ---------------------------------------------------------------------------

def evaluate_sandbox_events(events: list[dict]) -> list[dict]:
    """
    Match a list of sandbox observation events against the behavioral patterns
    and return a list of triggered findings.

    Each event dict should have at minimum:
        {
            "type": "network" | "file_read" | "process" | "env_access",
            "value": "<destination or path or command or var_name>"
        }

    Returns a list of finding dicts with pattern ID, severity, and detail.
    """
    findings = []
    for event in events:
        event_type = event.get("type", "")
        value = event.get("value", "")

        for pattern in BEHAVIORAL_PATTERNS:
            matched = False

            if event_type == "network" and pattern.network_destination:
                matched = pattern.network_destination in value

            elif event_type == "file_read" and pattern.file_path_prefix:
                matched = value.startswith(pattern.file_path_prefix)

            elif event_type == "process" and pattern.process_command_fragment:
                matched = bool(re.search(pattern.process_command_fragment, value, re.IGNORECASE))

            elif event_type == "env_access" and pattern.env_var_pattern:
                matched = bool(re.search(pattern.env_var_pattern, value, re.IGNORECASE))

            if matched:
                findings.append({
                    "pattern_id": pattern.id,
                    "category": pattern.category.value,
                    "severity": pattern.severity,
                    "description": pattern.description,
                    "miasma_specific": pattern.miasma_specific,
                    "triggered_by": {"type": event_type, "value": value},
                })

    return findings


def has_critical_findings(findings: list[dict]) -> bool:
    return any(f["severity"] == "CRITICAL" for f in findings)


def summarise_findings(findings: list[dict]) -> str:
    if not findings:
        return "No behavioral indicators matched."
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    miasma = [f for f in findings if f.get("miasma_specific")]
    parts = []
    if critical:
        parts.append(f"{len(critical)} CRITICAL")
    if high:
        parts.append(f"{len(high)} HIGH")
    if miasma:
        parts.append(f"{len(miasma)} Miasma-class indicator(s)")
    return f"Behavioral findings: {', '.join(parts)}. " + "; ".join(
        f["description"] for f in findings[:3]
    ) + ("..." if len(findings) > 3 else "")


def get_attack_family(findings: list[dict]) -> list[str]:
    """Return which attack families are indicated by the findings."""
    families = set()
    for f in findings:
        if f.get("miasma_specific"):
            families.add("Miasma/Shai-Hulud")
        if f.get("ironworm_specific"):
            families.add("IronWorm")
    return sorted(families)
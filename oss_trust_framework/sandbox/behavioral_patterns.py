"""
Gate 5 — Behavioral pattern matching.

Covers two confirmed attack families:

Miasma / Shai-Hulud (Red Hat Insights, TanStack, Bitwarden — 2026):
  - Unique per-infection encrypted payloads defeat hash-based IOCs.
  - Cloud identity theft via GCP/Azure IMDS.
  - OIDC token abuse for npm trusted publishing self-propagation.

IronWorm (asteroiddao / Arweave ecosystem — identified JFrog, 2026-06-03):
  - Rust ELF binary dropped via npm preinstall hook, UPX-packed.
  - eBPF kernel rootkit for process/socket hiding and anti-debugging.
  - Harvests 86 environment variables and 20+ credential file paths.
  - Targets AI API keys (OpenAI, Anthropic), cloud credentials, SSH keys,
    Exodus cryptocurrency wallet files, Vault/K8s secrets.
  - C2 over Tor hidden service (.onion) with temp.sh fallback exfil.
  - Self-propagates via npm OIDC Trusted Publishing using stolen credentials.
  - Backdates commits to obscure forensic timeline.

Both families are defeated by behavioral matching — patterns fire on what
the payload *does* (network destinations, file paths, syscalls, env vars),
not what it looks like. Encryption and obfuscation are irrelevant.

Pattern categories:
  - CLOUD_METADATA_ACCESS  — requests to instance metadata endpoints
  - OIDC_TOKEN_REQUEST     — requests to GitHub/Google/Azure OIDC endpoints
  - CREDENTIAL_FILE_READ   — access to well-known credential file paths
  - REGISTRY_PUBLISH       — outbound PUT/POST to a package registry
  - ENCRYPTED_EXFIL        — encrypted/anonymised outbound connection
  - PROCESS_INJECTION      — subprocess spawn with obfuscated arguments
  - ENV_VAR_HARVEST        — enumeration of secrets from environment
  - KERNEL_EXPLOIT         — eBPF/rootkit syscall patterns (IronWorm)
  - CRYPTO_WALLET          — cryptocurrency wallet credential access
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class PatternCategory(str, Enum):
    CLOUD_METADATA_ACCESS = "cloud_metadata_access"
    OIDC_TOKEN_REQUEST = "oidc_token_request"
    CREDENTIAL_FILE_READ = "credential_file_read"
    REGISTRY_PUBLISH = "registry_publish"
    ENCRYPTED_EXFIL = "encrypted_exfil"
    PROCESS_INJECTION = "process_injection"
    ENV_VAR_HARVEST = "env_var_harvest"
    KERNEL_EXPLOIT = "kernel_exploit"        # IronWorm eBPF rootkit
    CRYPTO_WALLET = "crypto_wallet"          # IronWorm Exodus wallet theft


@dataclass
class BehavioralPattern:
    id: str
    category: PatternCategory
    description: str
    severity: str                    # CRITICAL | HIGH | MEDIUM
    network_destination: str | None = None
    file_path_prefix: str | None = None
    process_command_fragment: str | None = None
    env_var_pattern: str | None = None
    miasma_specific: bool = False    # Directly observed in Miasma/Shai-Hulud
    ironworm_specific: bool = False  # Directly observed in IronWorm


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

BEHAVIORAL_PATTERNS: list[BehavioralPattern] = [

    # =========================================================================
    # MIASMA / SHAI-HULUD patterns
    # =========================================================================

    # --- Cloud metadata endpoint access ---
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

    # --- OIDC token requests ---
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
        miasma_specific=False,
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
        ironworm_specific=True,
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
        description="Access to OIDC_PACKAGES or CI-injected publish tokens",
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

    # =========================================================================
    # IRONWORM patterns (identified JFrog Security Research, 2026-06-03)
    # Reference: https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    # =========================================================================

    # --- Tor C2 communication ---
    BehavioralPattern(
        id="IRONWORM-001",
        category=PatternCategory.ENCRYPTED_EXFIL,
        description="Outbound connection to Tor network (.onion address or Tor SOCKS port)",
        severity="CRITICAL",
        network_destination=".onion",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-001b",
        category=PatternCategory.ENCRYPTED_EXFIL,
        description="Outbound connection on Tor SOCKS port 9050 or 9150",
        severity="CRITICAL",
        network_destination=":9050",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-001c",
        category=PatternCategory.ENCRYPTED_EXFIL,
        description="Exfil fallback to temp.sh file sharing service (IronWorm fallback C2)",
        severity="CRITICAL",
        network_destination="temp.sh",
        ironworm_specific=True,
    ),

    # --- eBPF kernel rootkit ---
    BehavioralPattern(
        id="IRONWORM-002",
        category=PatternCategory.KERNEL_EXPLOIT,
        description="eBPF program load attempt via bpf() syscall from install context — rootkit indicator",
        severity="CRITICAL",
        process_command_fragment=r"bpf\(|BPF_PROG_LOAD|bpf_prog_load",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-002b",
        category=PatternCategory.KERNEL_EXPLOIT,
        description="UPX-packed or magic-overwritten binary execution from tools/ directory",
        severity="CRITICAL",
        process_command_fragment=r"tools/setup|tools\\setup",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-002c",
        category=PatternCategory.KERNEL_EXPLOIT,
        description="Rust ELF binary dropped and executed from package tools directory",
        severity="CRITICAL",
        file_path_prefix="/tmp/tools/",
        ironworm_specific=True,
    ),

    # --- AI API key harvesting ---
    BehavioralPattern(
        id="IRONWORM-003",
        category=PatternCategory.ENV_VAR_HARVEST,
        description="Access to AI provider API keys (OpenAI, Anthropic, Claude, Cohere, etc.)",
        severity="CRITICAL",
        env_var_pattern=r"OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|COHERE_API_KEY|AI_API_KEY|GEMINI_API_KEY",
        ironworm_specific=True,
    ),

    # --- Vault / secrets manager credential access ---
    BehavioralPattern(
        id="IRONWORM-004",
        category=PatternCategory.CREDENTIAL_FILE_READ,
        description="Read from HashiCorp Vault token or config files",
        severity="CRITICAL",
        file_path_prefix="/root/.vault-token",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-004b",
        category=PatternCategory.ENV_VAR_HARVEST,
        description="Access to Vault environment variables",
        severity="CRITICAL",
        env_var_pattern=r"VAULT_TOKEN|VAULT_ADDR|VAULT_NAMESPACE",
        ironworm_specific=True,
    ),

    # --- Exodus cryptocurrency wallet ---
    BehavioralPattern(
        id="IRONWORM-005",
        category=PatternCategory.CRYPTO_WALLET,
        description="Access to Exodus desktop wallet data directory (seed phrase theft)",
        severity="CRITICAL",
        file_path_prefix="/home/.config/Exodus",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-005b",
        category=PatternCategory.CRYPTO_WALLET,
        description="Access to Exodus wallet on Linux alternate path",
        severity="CRITICAL",
        file_path_prefix="/root/.config/Exodus",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-005c",
        category=PatternCategory.CRYPTO_WALLET,
        description="Access to broader cryptocurrency wallet directories",
        severity="HIGH",
        file_path_prefix="/root/.config/atomic",   # Atomic wallet — also targeted
        ironworm_specific=False,
    ),

    # --- npm / registry credential theft ---
    BehavioralPattern(
        id="IRONWORM-006",
        category=PatternCategory.CREDENTIAL_FILE_READ,
        description="Read from .npmrc file — may contain npm auth tokens",
        severity="HIGH",
        file_path_prefix="/root/.npmrc",
        ironworm_specific=True,
    ),
    BehavioralPattern(
        id="IRONWORM-006b",
        category=PatternCategory.ENV_VAR_HARVEST,
        description="Access to npm auth token or registry credentials in environment",
        severity="CRITICAL",
        env_var_pattern=r"NPM_AUTH_TOKEN|NODE_AUTH_TOKEN|NPM_TOKEN",
        ironworm_specific=True,
    ),

    # --- GitHub Actions workflow overwrite (IronWorm propagation vector) ---
    BehavioralPattern(
        id="IRONWORM-007",
        category=PatternCategory.PROCESS_INJECTION,
        description="Write to .github/workflows directory from install context — workflow hijack",
        severity="CRITICAL",
        file_path_prefix=".github/workflows",
        ironworm_specific=True,
    ),
]


# ---------------------------------------------------------------------------
# Pattern evaluation utilities
# ---------------------------------------------------------------------------

def evaluate_sandbox_events(events: list[dict]) -> list[dict]:
    """
    Match a list of sandbox observation events against all behavioral patterns
    and return a list of triggered findings.

    Each event dict should have at minimum:
        {
            "type": "network" | "file_read" | "process" | "env_access",
            "value": "<destination or path or command or var_name>"
        }

    Returns a list of finding dicts with pattern ID, severity, and attribution.
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
                    "ironworm_specific": pattern.ironworm_specific,
                    "triggered_by": {"type": event_type, "value": value},
                })

    return findings


def has_critical_findings(findings: list[dict]) -> bool:
    return any(f["severity"] == "CRITICAL" for f in findings)


def get_attack_family(findings: list[dict]) -> list[str]:
    """Return which attack families are indicated by the findings."""
    families = set()
    for f in findings:
        if f.get("miasma_specific"):
            families.add("Miasma/Shai-Hulud")
        if f.get("ironworm_specific"):
            families.add("IronWorm")
    return sorted(families)


def summarise_findings(findings: list[dict]) -> str:
    if not findings:
        return "No behavioral indicators matched."
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    families = get_attack_family(findings)
    parts = []
    if critical:
        parts.append(f"{len(critical)} CRITICAL")
    if high:
        parts.append(f"{len(high)} HIGH")
    if families:
        parts.append(f"attack families: {', '.join(families)}")
    return f"Behavioral findings: {', '.join(parts)}. " + "; ".join(
        f["description"] for f in findings[:3]
    ) + ("..." if len(findings) > 3 else "")

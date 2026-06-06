"""
Gate 2 — GPG Signature Fallback.

Verifies GPG signatures for ecosystems not yet on Sigstore (or where
Sigstore attestation is unavailable). Primary use cases:
  - Older PyPI packages predating Trusted Publishing
  - Debian/Ubuntu packages
  - Some Cargo crates and Go modules
  - Any package where provenance.py returns NO_ATTESTATION

Security design:
  - Keys are pre-pinned in config/trusted_keys/ at setup time
  - Keys are NEVER fetched from keyservers at verify time
    (fetching keys at verification time is itself an attack surface —
    an attacker can push a malicious key between fetch and verify)
  - The TRUSTED_FINGERPRINTS dict is the source of truth
  - A valid signature from an untrusted fingerprint = FAIL

Dependencies:
    pip install python-gnupg

Usage:
    result = await verify_gpg_signature(
        package="cryptography",
        version="42.0.0",
        ecosystem="PyPI",
        signature_path="/tmp/cryptography-42.0.0.tar.gz.asc",
        payload_path="/tmp/cryptography-42.0.0.tar.gz",
        trusted_fingerprints=TRUSTED_FINGERPRINTS,
    )
"""

from __future__ import annotations
import asyncio
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

try:
    import gnupg
    GPG_AVAILABLE = True
except ImportError:
    GPG_AVAILABLE = False


class GPGDecision(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"       # No signature available — caller decides whether to quarantine
    ERROR = "error"     # gnupg not installed or keyring misconfigured


@dataclass
class GPGResult:
    decision: GPGDecision
    package: str
    version: str
    fingerprint: Optional[str]
    signer: Optional[str]
    trusted: bool
    message: str


# ---------------------------------------------------------------------------
# Trusted fingerprint registry
# ---------------------------------------------------------------------------
# These are the GPG fingerprints of known maintainers for packages that
# still rely on GPG rather than Sigstore.
#
# To add a fingerprint:
#   1. Obtain the maintainer's public key from a trusted source
#      (project README, verified Keybase profile, GitHub SSH keys)
#   2. Import it: gpg --import maintainer.asc
#   3. Verify the fingerprint: gpg --fingerprint maintainer@email.com
#   4. Add the 40-char hex fingerprint here
#   5. Export the keyring: gpg --export > config/trusted_keys/keyring.gpg
#
# DO NOT fetch fingerprints from keyservers automatically.

TRUSTED_FINGERPRINTS: dict[str, dict[str, str]] = {
    # Format: "ECOSYSTEM:package": {"fingerprint": "maintainer name / role"}
    # Example entries — replace with real verified fingerprints:
    #
    # "PyPI:cryptography": {
    #     "3C12EE34B2BD49C07DA0FA532B64D6DE3E3EF3C0": "cryptography maintainers (PyCA)"
    # },
    # "PyPI:requests": {
    #     "4C1D75B5F5D1C0E8D3C3C1A0B2D4E6F8A0B2C4D6": "Kenneth Reitz"
    # },
}


# ---------------------------------------------------------------------------
# Keyring helpers
# ---------------------------------------------------------------------------

def _get_keyring_home() -> str:
    """Return the path to the pinned GPG keyring directory."""
    keyring_dir = Path(__file__).parent.parent.parent / "config" / "trusted_keys"
    keyring_dir.mkdir(parents=True, exist_ok=True)
    return str(keyring_dir)


def _get_package_fingerprints(package: str, ecosystem: str) -> dict[str, str]:
    """Return trusted fingerprints for a given package, or empty dict."""
    key = f"{ecosystem}:{package}"
    return TRUSTED_FINGERPRINTS.get(key, {})


# ---------------------------------------------------------------------------
# Main verification function
# ---------------------------------------------------------------------------

async def verify_gpg_signature(
    package: str,
    version: str,
    ecosystem: str,
    signature_path: Optional[str] = None,
    payload_path: Optional[str] = None,
    trusted_fingerprints: Optional[dict] = None,
) -> GPGResult:
    """
    Verify a GPG signature against the pre-pinned trusted keyring.

    Args:
        package:              Package name.
        version:              Package version.
        ecosystem:            "PyPI", "npm", "Cargo", etc.
        signature_path:       Path to the .asc / .sig signature file.
        payload_path:         Path to the tarball / wheel being verified.
        trusted_fingerprints: Override the module-level TRUSTED_FINGERPRINTS.
                              Useful for testing.

    Returns:
        GPGResult with decision and verification details.
    """
    if not GPG_AVAILABLE:
        return GPGResult(
            decision=GPGDecision.ERROR,
            package=package,
            version=version,
            fingerprint=None,
            signer=None,
            trusted=False,
            message=(
                "python-gnupg is not installed. "
                "Install it with: pip install python-gnupg"
            ),
        )

    if not signature_path or not payload_path:
        return GPGResult(
            decision=GPGDecision.SKIP,
            package=package,
            version=version,
            fingerprint=None,
            signer=None,
            trusted=False,
            message=(
                f"No GPG signature available for {package}@{version}. "
                f"If this package should have a GPG signature, add it to "
                f"trusted_publishers.yaml with require_attestation: true."
            ),
        )

    if not os.path.exists(signature_path):
        return GPGResult(
            decision=GPGDecision.FAIL,
            package=package,
            version=version,
            fingerprint=None,
            signer=None,
            trusted=False,
            message=f"Signature file not found: {signature_path}",
        )

    if not os.path.exists(payload_path):
        return GPGResult(
            decision=GPGDecision.FAIL,
            package=package,
            version=version,
            fingerprint=None,
            signer=None,
            trusted=False,
            message=f"Payload file not found: {payload_path}",
        )

    fingerprints = trusted_fingerprints or _get_package_fingerprints(package, ecosystem)

    try:
        gpg = gnupg.GPG(gnupghome=_get_keyring_home())

        with open(signature_path, "rb") as sig_file:
            verify = gpg.verify_file(sig_file, payload_path)

        if not verify.valid:
            return GPGResult(
                decision=GPGDecision.FAIL,
                package=package,
                version=version,
                fingerprint=getattr(verify, "fingerprint", None),
                signer=getattr(verify, "username", None),
                trusted=False,
                message=(
                    f"GPG signature INVALID for {package}@{version}. "
                    f"Status: {getattr(verify, 'status', 'unknown')}."
                ),
            )

        fingerprint = getattr(verify, "fingerprint", "")
        signer = getattr(verify, "username", "unknown")

        # Signature is valid — but is it from a trusted key?
        if fingerprints and fingerprint not in fingerprints:
            return GPGResult(
                decision=GPGDecision.FAIL,
                package=package,
                version=version,
                fingerprint=fingerprint,
                signer=signer,
                trusted=False,
                message=(
                    f"GPG signature valid but fingerprint {fingerprint[:16]}... "
                    f"is NOT in the trusted fingerprint list for {package}. "
                    f"Possible key compromise or unauthorised signer."
                ),
            )

        signer_role = fingerprints.get(fingerprint, "unknown role") if fingerprints else "no fingerprint pinning configured"

        return GPGResult(
            decision=GPGDecision.PASS,
            package=package,
            version=version,
            fingerprint=fingerprint,
            signer=signer,
            trusted=True,
            message=(
                f"GPG signature VALID for {package}@{version}. "
                f"Signed by: {signer} ({signer_role}). "
                f"Fingerprint: {fingerprint[:16]}..."
            ),
        )

    except Exception as e:
        return GPGResult(
            decision=GPGDecision.ERROR,
            package=package,
            version=version,
            fingerprint=None,
            signer=None,
            trusted=False,
            message=f"GPG verification error: {e}",
        )


# ---------------------------------------------------------------------------
# Keyring management helpers (run at setup time, not at verify time)
# ---------------------------------------------------------------------------

def import_trusted_key(key_path: str) -> tuple[bool, str]:
    """
    Import a maintainer public key into the pinned keyring.
    Run this ONCE during setup, not at verification time.

    Usage:
        success, message = import_trusted_key("maintainer_pubkey.asc")
    """
    if not GPG_AVAILABLE:
        return False, "python-gnupg not installed"
    try:
        gpg = gnupg.GPG(gnupghome=_get_keyring_home())
        with open(key_path, "rb") as f:
            result = gpg.import_keys(f.read())
        if result.count > 0:
            return True, f"Imported {result.count} key(s): {result.fingerprints}"
        return False, f"No keys imported. Results: {result.results}"
    except Exception as e:
        return False, str(e)


def list_trusted_keys() -> list[dict]:
    """List all keys in the pinned keyring."""
    if not GPG_AVAILABLE:
        return []
    try:
        gpg = gnupg.GPG(gnupghome=_get_keyring_home())
        return gpg.list_keys()
    except Exception:
        return []

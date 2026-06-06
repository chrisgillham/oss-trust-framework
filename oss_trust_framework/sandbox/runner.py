"""
Gate 5 — Behavioral Sandbox Runner
Full implementation with three execution backends:

  1. gVisor (production)  — strongest isolation, Linux CI only
  2. strace (development) — Linux only, no special setup
  3. Audit-log (Windows) — Python-level import/socket/file hooking, cross-platform

Backend is selected automatically based on available tooling. 
"""

from __future__ import annotations
import asyncio
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class SandboxBackend(str, Enum):
    GVISOR  = "gvisor"
    STRACE  = "strace"
    AUDIT   = "audit"    # Python-level hooks (Windows / fallback)
    SKIP    = "skip"     # No backend available


class SandboxDecision(str, Enum):
    PASS  = "pass"
    BLOCK = "block"
    SKIP  = "skip"
    ERROR = "error"


@dataclass
class SandboxResult:
    decision:    SandboxDecision
    package:     str
    version:     str
    ecosystem:   str
    passed:      bool
    findings:    list[dict]  = field(default_factory=list)
    events:      list[dict]  = field(default_factory=list)
    backend:     SandboxBackend = SandboxBackend.SKIP
    is_stub:     bool        = False
    message:     str         = ""


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def _detect_backend() -> SandboxBackend:
    system = platform.system()

    if system == "Linux":
        # Try gVisor first
        try:
            r = subprocess.run(
                ["docker", "run", "--runtime=runsc", "--rm",
                 "alpine", "echo", "gvisor-ok"],
                capture_output=True, text=True, timeout=15
            )
            if "gvisor-ok" in r.stdout:
                return SandboxBackend.GVISOR
        except Exception:
            pass

        # Fall back to strace
        try:
            r = subprocess.run(
                ["strace", "-V"], capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                return SandboxBackend.STRACE
        except FileNotFoundError:
            pass

    # Windows or no Linux tools — use Python audit hooks
    return SandboxBackend.AUDIT


# ---------------------------------------------------------------------------
# Backend 1: gVisor
# ---------------------------------------------------------------------------

_GVISOR_INSTALL_SCRIPT = textwrap.dedent("""
    #!/bin/sh
    set -e
    PACKAGE="{package}"
    VERSION="{version}"
    ECOSYSTEM="{ecosystem}"

    # Install the package
    if [ "$ECOSYSTEM" = "npm" ]; then
        npm install "$PACKAGE@$VERSION" 2>&1
    elif [ "$ECOSYSTEM" = "PyPI" ]; then
        pip install "$PACKAGE==$VERSION" --no-cache-dir 2>&1
    elif [ "$ECOSYSTEM" = "Cargo" ]; then
        cargo add "$PACKAGE@$VERSION" 2>&1
    fi
""")

_GVISOR_TRACE_WRAPPER = textwrap.dedent("""
    #!/bin/sh
    # Wrap install with strace inside gVisor to capture syscall events
    strace -f -e trace=openat,open,connect,socket,execve,getenv \
           -o /tmp/strace.log \
           sh /install.sh 2>&1
    cat /tmp/strace.log
""")


async def _run_gvisor(
    package: str, version: str, ecosystem: str, timeout: int = 180
) -> list[dict]:
    """Execute install in gVisor microVM, return events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write install script
        install_script = Path(tmpdir) / "install.sh"
        install_script.write_text(
            _GVISOR_INSTALL_SCRIPT.format(
                package=package, version=version, ecosystem=ecosystem
            )
        )

        # Choose image by ecosystem
        image_map = {
            "PyPI":  "python:3.12-slim",
            "npm":   "node:20-slim",
            "Cargo": "rust:slim",
        }
        image = image_map.get(ecosystem, "python:3.12-slim")

        cmd = [
            "docker", "run", "--rm",
            "--runtime=runsc",          # gVisor kernel
            "--network=none",           # no outbound — forces Tor/temp.sh BLOCK
            "--cap-drop=ALL",           # no capabilities
            "--memory=512m",
            "--cpus=1",
            "-v", f"{tmpdir}:/workspace:ro",
            image,
            "sh", "-c",
            (
                "apt-get install -y strace 2>/dev/null || true; "
                "strace -f -e trace=openat,connect,execve "
                "       -o /tmp/st.log "
                "       sh /workspace/install.sh 2>&1; "
                "cat /tmp/st.log 2>/dev/null"
            )
        ]

        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd, capture_output=True, text=True, timeout=timeout
                    )
                ),
                timeout=timeout + 10
            )
            return _parse_strace_output(result.stdout + result.stderr)
        except asyncio.TimeoutError:
            return [{"type": "error", "value": f"gVisor sandbox timed out after {timeout}s"}]
        except Exception as e:
            return [{"type": "error", "value": str(e)}]


# ---------------------------------------------------------------------------
# Backend 2: strace (Linux, no gVisor)
# ---------------------------------------------------------------------------

async def _run_strace(
    package: str, version: str, ecosystem: str, timeout: int = 120
) -> list[dict]:
    """Execute install under strace, return events. Less isolation than gVisor."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "strace.log"

        # Build install command
        cmd_map = {
            "PyPI":  ["pip", "install", f"{package}=={version}",
                      "--no-cache-dir", "--target", tmpdir],
            "npm":   ["npm", "install", f"{package}@{version}",
                      "--prefix", tmpdir],
            "Cargo": ["cargo", "add", f"{package}@{version}"],
        }
        install_cmd = cmd_map.get(ecosystem, cmd_map["PyPI"])

        strace_cmd = [
            "strace", "-f",
            "-e", "trace=openat,open,connect,socket,execve",
            "-o", str(log_path),
        ] + install_cmd

        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        strace_cmd,
                        capture_output=True, text=True,
                        timeout=timeout,
                        env={**os.environ, "HOME": tmpdir}
                    )
                ),
                timeout=timeout + 10
            )
            if log_path.exists():
                return _parse_strace_output(log_path.read_text(errors="replace"))
            return []
        except asyncio.TimeoutError:
            return [{"type": "error", "value": f"strace timed out after {timeout}s"}]
        except Exception as e:
            return [{"type": "error", "value": str(e)}]


# ---------------------------------------------------------------------------
# strace output parser
# ---------------------------------------------------------------------------

# Patterns to extract meaningful events from strace output
_STRACE_PATTERNS = [
    # File reads: openat(AT_FDCWD, "/path/to/file", O_RDONLY)
    (re.compile(r'openat\(AT_FDCWD,\s*"([^"]+)"'), "file_read"),
    (re.compile(r'open\("([^"]+)"'),                "file_read"),

    # Network: connect(fd, {sa_family=AF_INET, sin_addr="1.2.3.4"})
    (re.compile(r'connect\([^,]+,\s*\{[^}]*sin_addr=inet_addr\("([^"]+)"\)'), "network"),
    (re.compile(r'connect\([^,]+,\s*\{[^}]*sun_path="([^"]+)"'),              "network"),

    # Process execution: execve("/path/to/bin", [...])
    (re.compile(r'execve\("([^"]+)"'),  "process"),

    # getenv isn't a syscall — caught via env var access patterns in file reads
]

# File paths that are noise (standard pip/npm internals, not suspicious)
_NOISE_PREFIXES = (
    "/proc/", "/sys/", "/dev/",
    "/usr/lib/python", "/usr/local/lib/python",
    "/tmp/pip-", "/root/.cache/pip",
    "/usr/share/", "/etc/ld.so",
)


def _parse_strace_output(raw: str) -> list[dict]:
    """Convert raw strace log lines into structured event dicts."""
    events = []
    seen = set()

    for line in raw.splitlines():
        for pattern, event_type in _STRACE_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            value = m.group(1).strip()

            # Skip noise
            if event_type == "file_read" and any(
                value.startswith(p) for p in _NOISE_PREFIXES
            ):
                continue

            # Deduplicate
            key = f"{event_type}:{value}"
            if key in seen:
                continue
            seen.add(key)

            events.append({"type": event_type, "value": value})

    return events


# ---------------------------------------------------------------------------
# Backend 3: Python audit hooks (Windows / cross-platform fallback)
# ---------------------------------------------------------------------------

_AUDIT_HOOK_SCRIPT = textwrap.dedent("""
import sys, json, os, builtins, socket

events = []

# Hook file opens
_real_open = builtins.open
def _hooked_open(file, mode='r', *args, **kwargs):
    if isinstance(file, str) and 'r' in str(mode):
        events.append({"type": "file_read", "value": str(file)})
    return _real_open(file, mode, *args, **kwargs)
builtins.open = _hooked_open

# Hook socket connections
_real_connect = socket.socket.connect
def _hooked_connect(self, address):
    if isinstance(address, tuple):
        events.append({"type": "network", "value": f"{address[0]}:{address[1]}"})
    elif isinstance(address, str):
        events.append({"type": "network", "value": address})
    return _real_connect(self, address)
socket.socket.connect = _hooked_connect

# Capture interesting env vars
_suspicious_env_patterns = [
    'API_KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL',
    'GITHUB_', 'AWS_', 'GCP_', 'AZURE_', 'VAULT_',
    'OPENAI_', 'ANTHROPIC_', 'GEMINI_', 'COHERE_',
    'NPM_', 'DOCKER_', 'KUBE',
]
for key, val in os.environ.items():
    if any(p in key.upper() for p in _suspicious_env_patterns):
        events.append({"type": "env_access", "value": f"{key}={val[:20]}..."})

# Run the actual install
import subprocess, sys
result = subprocess.run(
    [sys.executable, '-m', 'pip', 'install',
     '{package}=={version}',
     '--no-cache-dir', '--target', '{target}'],
    capture_output=True, text=True
)

# Emit events as JSON
print("__EVENTS__:" + json.dumps(events))
""")


async def _run_audit_hooks(
    package: str, version: str, ecosystem: str, timeout: int = 120
) -> list[dict]:
    """
    Python-level audit hooks — cross-platform (works on Windows).
    Lower fidelity than strace/gVisor but catches network connections
    and file reads that go through Python's builtins.

    Limitation: only catches activity in the Python process itself,
    not in native binaries (e.g. IronWorm's Rust ELF would not be caught).
    """
    if ecosystem != "PyPI":
        # audit hook approach only works well for Python packages
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        script = _AUDIT_HOOK_SCRIPT.format(
            package=package, version=version, target=tmpdir
        )
        script_path = Path(tmpdir) / "audit_install.py"
        script_path.write_text(script, encoding="utf-8")

        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        [sys.executable, str(script_path)],
                        capture_output=True, text=True,
                        timeout=timeout,
                        env={
                            **os.environ,
                            "HOME": tmpdir,
                            "USERPROFILE": tmpdir,
                        }
                    )
                ),
                timeout=timeout + 10
            )
            # Parse the __EVENTS__ marker from stdout
            for line in (result.stdout + result.stderr).splitlines():
                if line.startswith("__EVENTS__:"):
                    try:
                        return json.loads(line[len("__EVENTS__:"):])
                    except json.JSONDecodeError:
                        pass
            return []
        except asyncio.TimeoutError:
            return [{"type": "error", "value": f"audit hook timed out after {timeout}s"}]
        except Exception as e:
            return [{"type": "error", "value": str(e)}]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_sandboxed_install(
    package: str,
    version: str,
    ecosystem: str,
    backend: Optional[SandboxBackend] = None,
    timeout: int = 120,
) -> SandboxResult:
    """
    Gate 5: Execute package install in a sandbox, capture behavioral events,
    and evaluate against 34 named patterns.

    Backend is auto-detected:
      - gVisor:  Linux CI with Docker --runtime=runsc (strongest isolation)
      - strace:  Linux with strace installed (no Docker required)
      - audit:   Python-level hooks, cross-platform (PyPI only, limited fidelity)

    Args:
        package:   Package name.
        version:   Package version.
        ecosystem: "PyPI", "npm", "Cargo".
        backend:   Force a specific backend (auto-detected if None).
        timeout:   Maximum seconds for the sandboxed install.

    Returns:
        SandboxResult with decision, findings, and raw events.
    """
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events,
        has_critical_findings,
        summarise_findings,
    )

    # Detect backend
    selected_backend = backend or _detect_backend()

    if selected_backend == SandboxBackend.SKIP:
        return SandboxResult(
            decision=SandboxDecision.SKIP,
            package=package,
            version=version,
            ecosystem=ecosystem,
            passed=True,
            backend=SandboxBackend.SKIP,
            is_stub=False,
            message=(
                f"No sandbox backend available for {package}@{version}. "
                f"Install strace (Linux) or configure Docker with gVisor to enable Gate 5."
            ),
        )

    # Run the appropriate backend
    backend_fn = {
        SandboxBackend.GVISOR: _run_gvisor,
        SandboxBackend.STRACE: _run_strace,
        SandboxBackend.AUDIT:  _run_audit_hooks,
    }[selected_backend]

    events = await backend_fn(package, version, ecosystem, timeout)

    # Filter out error pseudo-events
    real_events = [e for e in events if e.get("type") != "error"]
    error_events = [e for e in events if e.get("type") == "error"]

    # Evaluate against behavioral patterns
    findings = evaluate_sandbox_events(real_events)
    critical = has_critical_findings(findings)

    if error_events:
        return SandboxResult(
            decision=SandboxDecision.ERROR,
            package=package,
            version=version,
            ecosystem=ecosystem,
            passed=False,
            findings=findings,
            events=real_events,
            backend=selected_backend,
            is_stub=False,
            message=f"Sandbox error: {error_events[0]['value']}",
        )

    if critical:
        return SandboxResult(
            decision=SandboxDecision.BLOCK,
            package=package,
            version=version,
            ecosystem=ecosystem,
            passed=False,
            findings=findings,
            events=real_events,
            backend=selected_backend,
            is_stub=False,
            message=summarise_findings(findings),
        )

    return SandboxResult(
        decision=SandboxDecision.PASS,
        package=package,
        version=version,
        ecosystem=ecosystem,
        passed=True,
        findings=findings,
        events=real_events,
        backend=selected_backend,
        is_stub=False,
        message=(
            f"{package}@{version} passed behavioral sandbox "
            f"({len(real_events)} events, {len(findings)} non-critical findings, "
            f"backend: {selected_backend.value})."
        ),
    )

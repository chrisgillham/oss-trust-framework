"""
Gate 7 — Behavioral Sandbox
Installs the package in an isolated gVisor (or Firecracker) container
with no network access and monitors for malicious install-time behavior:
  - File system access to sensitive paths (/etc/passwd, ~/.ssh, ~/.aws)
  - Outbound network connections (should be impossible with network=none)
  - Unexpected child process spawning (shells, curl, wget, python -c)
  - Environment variable enumeration
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)

# Paths that trigger a BLOCKED outcome if accessed during install
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "~/.ssh", "~/.aws", "~/.gcloud", "~/.config/gcloud",
    "~/.npmrc", "~/.pypirc", "/proc/", "/sys/",
]

# Process names that are suspicious at install time
SUSPICIOUS_PROCS = [
    "curl", "wget", "nc", "ncat", "netcat",
    "bash -c", "sh -c", "python -c", "python3 -c",
    "perl -e", "ruby -e",
]

# Syscalls that indicate credential or data exfiltration attempts
SUSPICIOUS_SYSCALLS = ["ptrace", "process_vm_readv", "process_vm_writev"]

ECO_INSTALL_CMDS = {
    "pypi":  ["pip", "install", "--no-deps", "--isolated"],
    "npm":   ["npm", "install", "--ignore-scripts=false", "--no-save"],
    "cargo": ["cargo", "fetch"],
    "go":    ["go", "get"],
}


class SandboxGate:
    def __init__(self, cfg: dict) -> None:
        self.runtime        = cfg.get("runtime", "gvisor")
        self.network        = cfg.get("network", "none")
        self.timeout        = cfg.get("timeout_seconds", 120)
        self.memory_mb      = cfg.get("memory_limit_mb", 512)
        self.cpu_shares     = cfg.get("cpu_shares", 512)
        self.blocked_syscalls = cfg.get("blocked_syscalls", SUSPICIOUS_SYSCALLS)

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        if self.runtime == "gvisor" and not shutil.which("runsc"):
            log.warning("[sandbox] gVisor (runsc) not found — falling back to Docker")
            self.runtime = "docker"

        if self.runtime in ("docker", "gvisor"):
            return await self._docker_sandbox(package, version, ecosystem)

        return GateResult(
            gate="Gate 7: Sandbox",
            outcome=Outcome.HOLD,
            message=f"Sandbox runtime '{self.runtime}' not available — skipping behavioral test",
            details={"runtime": self.runtime, "skipped": True},
        )

    async def _docker_sandbox(
        self, package: str, version: str, ecosystem: str
    ) -> GateResult:
        install_cmd = self._build_install_cmd(package, version, ecosystem)
        if not install_cmd:
            return GateResult(
                gate="Gate 7: Sandbox",
                outcome=Outcome.HOLD,
                message=f"Install command not configured for ecosystem '{ecosystem}'",
                details={"ecosystem": ecosystem, "skipped": True},
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            strace_log   = Path(tmpdir) / "strace.log"
            behavior_log = Path(tmpdir) / "behavior.json"

            docker_cmd = self._build_docker_cmd(
                install_cmd, ecosystem, strace_log, tmpdir
            )

            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *docker_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=tmpdir,
                    ),
                    timeout=self.timeout,
                )
                stdout, stderr = await proc.communicate()
            except asyncio.TimeoutError:
                return GateResult(
                    gate="Gate 7: Sandbox",
                    outcome=Outcome.BLOCKED,
                    message=f"Sandbox timeout after {self.timeout}s — possible hang or evasion",
                    details={"timeout": True},
                )

            findings = self._analyze_strace(strace_log, stdout.decode(), stderr.decode())

            if findings["malicious"]:
                return GateResult(
                    gate="Gate 7: Sandbox",
                    outcome=Outcome.BLOCKED,
                    message=(
                        f"Malicious behavior detected in {package}@{version}: "
                        f"{'; '.join(findings['indicators'][:3])}"
                    ),
                    details={"behavior_change": True, **findings},
                )

            if findings["suspicious"]:
                return GateResult(
                    gate="Gate 7: Sandbox",
                    outcome=Outcome.QUARANTINE,
                    message=(
                        f"Suspicious install-time behavior in {package}@{version}: "
                        f"{'; '.join(findings['indicators'][:3])}"
                    ),
                    details={"behavior_change": True, **findings},
                )

            return GateResult(
                gate="Gate 7: Sandbox",
                outcome=Outcome.APPROVED,
                message=f"No malicious behavior detected in {package}@{version}",
                details={"behavior_change": False, **findings},
            )

    def _build_install_cmd(
        self, package: str, version: str, ecosystem: str
    ) -> list[str] | None:
        base = ECO_INSTALL_CMDS.get(ecosystem.lower())
        if not base:
            return None
        pkg_arg = f"{package}=={version}" if ecosystem.lower() == "pypi" else f"{package}@{version}"
        return [*base, pkg_arg]

    def _build_docker_cmd(
        self,
        install_cmd: list[str],
        ecosystem: str,
        strace_log: Path,
        tmpdir: str,
    ) -> list[str]:
        image_map = {
            "pypi":  "python:3.12-slim",
            "npm":   "node:20-slim",
            "cargo": "rust:1.77-slim",
            "go":    "golang:1.22-bookworm",
        }
        image = image_map.get(ecosystem.lower(), "ubuntu:22.04")

        runtime_flag = ["--runtime=runsc"] if self.runtime == "gvisor" else []

        return [
            "docker", "run", "--rm",
            "--network", self.network,
            f"--memory={self.memory_mb}m",
            f"--cpu-shares={self.cpu_shares}",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            f"-v", f"{tmpdir}:/work:rw",
            *runtime_flag,
            image,
            "sh", "-c",
            (
                f"strace -f -e trace=openat,connect,execve,sendto "
                f"-o /work/strace.log "
                + " ".join(install_cmd)
            ),
        ]

    def _analyze_strace(
        self, strace_log: Path, stdout: str, stderr: str
    ) -> dict:
        indicators: list[str] = []
        malicious   = False
        suspicious  = False

        log_text = ""
        if strace_log.exists():
            try:
                log_text = strace_log.read_text(errors="replace")
            except Exception:
                pass

        combined = log_text + stdout + stderr

        # Check sensitive file access
        for path in SENSITIVE_PATHS:
            if path in combined:
                indicators.append(f"sensitive file access: {path}")
                malicious = True

        # Check suspicious process spawning
        for proc in SUSPICIOUS_PROCS:
            if proc in combined:
                indicators.append(f"suspicious process: {proc}")
                suspicious = True

        # Check outbound connection attempts (should be 0 with network=none)
        if "connect(" in log_text and "ECONNREFUSED" not in log_text:
            indicators.append("outbound network connection attempted")
            suspicious = True

        # Check env variable enumeration
        if "/proc/self/environ" in combined or "os.environ" in combined:
            indicators.append("environment variable enumeration")
            suspicious = True

        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "indicators": indicators,
            "strace_lines": len(log_text.splitlines()),
        }

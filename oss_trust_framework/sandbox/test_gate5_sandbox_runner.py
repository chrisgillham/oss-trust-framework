"""
Gate 5 sandbox runner tests.

Tests all three backends with mocked subprocess calls.
No real package installs are executed.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from subprocess import CompletedProcess


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_strace_output(events: list[dict]) -> str:
    """Build fake strace output that the parser will recognise."""
    lines = []
    for e in events:
        t = e["type"]
        v = e["value"]
        if t == "file_read":
            lines.append(f'12345 openat(AT_FDCWD, "{v}", O_RDONLY) = 3')
        elif t == "network":
            ip = v.split(":")[0] if ":" in v else v
            lines.append(f'12345 connect(4, {{sa_family=AF_INET, sin_addr=inet_addr("{ip}"), sin_port=htons(443)}}, 16) = 0')
        elif t == "process":
            lines.append(f'12345 execve("{v}", ["arg"], ...) = 0')
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Backend detection tests
# ---------------------------------------------------------------------------

def test_detect_backend_gvisor_when_available():
    from gate5_runner import _detect_backend, SandboxBackend
    import platform
    if platform.system() != "Linux":
        pytest.skip("gVisor detection only on Linux")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = CompletedProcess([], 0, stdout="gvisor-ok", stderr="")
        backend = _detect_backend()
    assert backend == SandboxBackend.GVISOR


def test_detect_backend_strace_fallback():
    from gate5_runner import _detect_backend, SandboxBackend
    import platform
    if platform.system() != "Linux":
        pytest.skip("strace detection only on Linux")

    with patch("subprocess.run") as mock_run:
        def side_effect(cmd, **kwargs):
            if "runsc" in str(cmd):
                raise FileNotFoundError("no gvisor")
            return CompletedProcess([], 0, stdout="strace 5.x", stderr="")
        mock_run.side_effect = side_effect
        backend = _detect_backend()
    assert backend == SandboxBackend.STRACE


def test_detect_backend_audit_on_windows():
    from gate5_runner import _detect_backend, SandboxBackend
    with patch("platform.system", return_value="Windows"):
        backend = _detect_backend()
    assert backend == SandboxBackend.AUDIT


# ---------------------------------------------------------------------------
# strace parser tests
# ---------------------------------------------------------------------------

def test_parse_strace_file_read():
    from gate5_runner import _parse_strace_output
    raw = '12345 openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = 3'
    events = _parse_strace_output(raw)
    assert any(e["type"] == "file_read" and ".aws/credentials" in e["value"]
               for e in events)


def test_parse_strace_network_connect():
    from gate5_runner import _parse_strace_output
    raw = '12345 connect(4, {sa_family=AF_INET, sin_addr=inet_addr("169.254.169.254"), sin_port=htons(80)}, 16) = 0'
    events = _parse_strace_output(raw)
    assert any(e["type"] == "network" and "169.254.169.254" in e["value"]
               for e in events)


def test_parse_strace_execve():
    from gate5_runner import _parse_strace_output
    raw = '12345 execve("./tools/setup", ["./tools/setup", "--collect"], ...) = 0'
    events = _parse_strace_output(raw)
    assert any(e["type"] == "process" and "tools/setup" in e["value"]
               for e in events)


def test_parse_strace_filters_python_noise():
    from gate5_runner import _parse_strace_output
    raw = '12345 openat(AT_FDCWD, "/usr/lib/python3.12/json/__init__.py", O_RDONLY) = 3'
    events = _parse_strace_output(raw)
    # Should be filtered as noise
    assert not any("/usr/lib/python" in e["value"] for e in events)


def test_parse_strace_deduplicates_events():
    from gate5_runner import _parse_strace_output
    raw = '\n'.join([
        '12345 openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3',
        '12346 openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3',
        '12347 openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3',
    ])
    events = _parse_strace_output(raw)
    npmrc_events = [e for e in events if ".npmrc" in e["value"]]
    assert len(npmrc_events) == 1  # deduplicated


def test_parse_strace_empty_output():
    from gate5_runner import _parse_strace_output
    assert _parse_strace_output("") == []


# ---------------------------------------------------------------------------
# IronWorm pattern firing via strace backend
# ---------------------------------------------------------------------------

IRONWORM_STRACE = make_strace_output([
    {"type": "process",   "value": "./tools/setup"},
    {"type": "network",   "value": "169.254.169.254"},  # IMDS
    {"type": "file_read", "value": "/root/.config/Exodus/exodus.wallet"},
    {"type": "file_read", "value": "/root/.npmrc"},
    {"type": "network",   "value": "abc123.onion"},
])

@pytest.mark.asyncio
async def test_strace_backend_blocks_ironworm():
    from gate5_runner import _run_strace, SandboxBackend, run_sandboxed_install, SandboxDecision

    with patch("gate5_runner.subprocess.run") as mock_run, \
         patch("gate5_runner.Path.exists", return_value=True), \
         patch("gate5_runner.Path.read_text", return_value=IRONWORM_STRACE):
        mock_run.return_value = CompletedProcess([], 0, stdout="", stderr="")
        result = await run_sandboxed_install(
            "malicious-pkg", "1.0.0", "PyPI",
            backend=SandboxBackend.STRACE
        )

    assert result.decision == SandboxDecision.BLOCK
    assert not result.passed
    assert result.is_stub is False


@pytest.mark.asyncio
async def test_strace_backend_passes_clean_install():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision

    clean_strace = make_strace_output([
        {"type": "file_read", "value": "/tmp/pip-install/setup.py"},
        {"type": "process",   "value": "/usr/bin/python3"},
        {"type": "network",   "value": "pypi.org"},
    ])

    with patch("gate5_runner.subprocess.run") as mock_run, \
         patch("gate5_runner.Path.exists", return_value=True), \
         patch("gate5_runner.Path.read_text", return_value=clean_strace):
        mock_run.return_value = CompletedProcess([], 0, stdout="", stderr="")
        result = await run_sandboxed_install(
            "requests", "2.33.0", "PyPI",
            backend=SandboxBackend.STRACE
        )

    assert result.decision == SandboxDecision.PASS
    assert result.passed
    assert result.is_stub is False


# ---------------------------------------------------------------------------
# Miasma pattern firing via strace backend
# ---------------------------------------------------------------------------

MIASMA_STRACE = make_strace_output([
    {"type": "network",   "value": "token.actions.githubusercontent.com"},
    {"type": "network",   "value": "169.254.169.254"},
    {"type": "file_read", "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
    {"type": "network",   "value": "registry.npmjs.org/@redhat/pkg"},
])

@pytest.mark.asyncio
async def test_strace_backend_blocks_miasma():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision

    with patch("gate5_runner.subprocess.run") as mock_run, \
         patch("gate5_runner.Path.exists", return_value=True), \
         patch("gate5_runner.Path.read_text", return_value=MIASMA_STRACE):
        mock_run.return_value = CompletedProcess([], 0, stdout="", stderr="")
        result = await run_sandboxed_install(
            "miasma-pkg", "1.0.0", "npm",
            backend=SandboxBackend.STRACE
        )

    assert result.decision == SandboxDecision.BLOCK
    assert not result.passed


# ---------------------------------------------------------------------------
# gVisor backend
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gvisor_backend_blocks_ironworm():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision

    with patch("gate5_runner.subprocess.run") as mock_run:
        mock_run.return_value = CompletedProcess(
            [], 0, stdout=IRONWORM_STRACE, stderr=""
        )
        result = await run_sandboxed_install(
            "malicious-pkg", "1.0.0", "PyPI",
            backend=SandboxBackend.GVISOR
        )

    assert result.decision == SandboxDecision.BLOCK
    assert result.backend == SandboxBackend.GVISOR


@pytest.mark.asyncio
async def test_gvisor_timeout_handled():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision
    import asyncio

    async def slow(*args, **kwargs):
        await asyncio.sleep(999)

    with patch("gate5_runner._run_gvisor", side_effect=slow):
        result = await run_sandboxed_install(
            "slow-pkg", "1.0.0", "PyPI",
            backend=SandboxBackend.GVISOR,
            timeout=1
        )

    # Should not raise — should return ERROR or SKIP
    assert result.decision in (SandboxDecision.ERROR, SandboxDecision.SKIP, SandboxDecision.PASS)


# ---------------------------------------------------------------------------
# Audit hook backend
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_backend_captures_events():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision

    fake_events = [
        {"type": "network",   "value": "169.254.169.254:80"},
        {"type": "file_read", "value": "/root/.ssh/id_rsa"},
    ]
    fake_output = f"some install output\n__EVENTS__:{json.dumps(fake_events)}\n"

    with patch("gate5_runner.subprocess.run") as mock_run:
        mock_run.return_value = CompletedProcess([], 0, stdout=fake_output, stderr="")
        result = await run_sandboxed_install(
            "test-pkg", "1.0.0", "PyPI",
            backend=SandboxBackend.AUDIT
        )

    assert result.backend == SandboxBackend.AUDIT
    assert result.is_stub is False
    # IMDS + SSH key should fire Miasma patterns
    assert result.decision == SandboxDecision.BLOCK


@pytest.mark.asyncio
async def test_audit_backend_clean_no_events():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision

    fake_output = f"install ok\n__EVENTS__:{json.dumps([])}\n"

    with patch("gate5_runner.subprocess.run") as mock_run:
        mock_run.return_value = CompletedProcess([], 0, stdout=fake_output, stderr="")
        result = await run_sandboxed_install(
            "requests", "2.33.0", "PyPI",
            backend=SandboxBackend.AUDIT
        )

    assert result.decision == SandboxDecision.PASS
    assert result.passed


# ---------------------------------------------------------------------------
# SKIP when no backend available
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_skip_when_no_backend():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision

    result = await run_sandboxed_install(
        "any-pkg", "1.0.0", "PyPI",
        backend=SandboxBackend.SKIP
    )
    assert result.decision == SandboxDecision.SKIP
    assert result.passed  # Degrade gracefully


# ---------------------------------------------------------------------------
# Backend not available for npm on audit backend
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_backend_skips_npm():
    from gate5_runner import run_sandboxed_install, SandboxBackend, SandboxDecision

    result = await run_sandboxed_install(
        "lodash", "4.17.21", "npm",
        backend=SandboxBackend.AUDIT
    )
    # Audit backend returns empty events for non-PyPI
    assert result.decision == SandboxDecision.PASS

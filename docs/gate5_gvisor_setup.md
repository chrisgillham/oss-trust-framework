# Gate 5 — gVisor Setup Guide

Gate 5's sandbox runner supports three backends in priority order:
gVisor (strongest) → strace (Linux fallback) → Python audit hooks (Windows/any).

---

## Option A — gVisor (production, Linux CI)

gVisor is a user-space kernel that provides stronger isolation than standard
Docker containers. IronWorm's eBPF rootkit cannot escape the gVisor boundary.

### Install gVisor on Ubuntu/Debian CI runner

```bash
# Add gVisor apt repo
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update && sudo apt-get install -y runsc

# Configure Docker to use gVisor runtime
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/sbin/runsc"
    }
  }
}
EOF
sudo systemctl restart docker

# Verify
docker run --runtime=runsc --rm alpine echo "gVisor working"
```

### GitHub Actions — add to your workflow

```yaml
- name: Install gVisor
  run: |
    curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor \
      -o /usr/share/keyrings/gvisor-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
      https://storage.googleapis.com/gvisor/releases release main" \
      | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
    sudo apt-get update && sudo apt-get install -y runsc
    sudo tee /etc/docker/daemon.json > /dev/null \
      <<< '{"runtimes":{"runsc":{"path":"/usr/local/sbin/runsc"}}}'
    sudo systemctl restart docker

- name: Validate with Gate 5 sandbox
  run: |
    oss-trust check \
      --package requests --version 2.33.0 --ecosystem PyPI \
      --sandbox-backend gvisor
```

---

## Option B — strace (Linux, simpler)

strace is available in most Linux CI environments without Docker.
Less isolation than gVisor — a malicious binary that avoids standard
syscalls could potentially evade capture — but practical for most use cases.

```bash
# Install strace
sudo apt-get install -y strace   # Ubuntu/Debian
sudo yum install -y strace       # RHEL/CentOS

# Verify
strace -V
```

Gate 5 auto-detects strace and uses it if gVisor is not available.
No configuration needed — just install it.

---

## Option C — Python audit hooks (Windows / cross-platform)

Works on Windows, Mac, and Linux without any additional tools.
Hooks Python's `open()` and `socket.connect()` — catches file reads
and network connections made by Python code and pip install scripts.

**Limitation:** Does not catch native binary execution (e.g. IronWorm's
Rust ELF binary). For full protection, use gVisor or strace on Linux CI.

No installation required — auto-detected on Windows.

---

## Backend selection

The runner auto-detects the best available backend:

```
gVisor available? → use gVisor
  ↓ no
Linux + strace? → use strace
  ↓ no
Any platform → use Python audit hooks
  ↓ nothing works
SKIP (degrade gracefully, log warning)
```

You can also force a backend:

```python
from oss_trust_framework.sandbox.runner import run_sandboxed_install, SandboxBackend

result = await run_sandboxed_install(
    package="requests",
    version="2.33.0",
    ecosystem="PyPI",
    backend=SandboxBackend.STRACE,  # force strace
)
```

---

## Testing Gate 5 locally

```bash
# Run Gate 5 unit tests (all mocked, no real installs)
pytest tests/test_gate5_sandbox_runner.py -v

# Run a live check with Gate 5 active
oss-trust check \
  --package requests \
  --version 2.33.0 \
  --ecosystem PyPI \
  --github-repo psf/requests

# Simulate an IronWorm install (safe — events are synthetic)
python src/demo.py --scenario ironworm
```

---

## Security notes

- `--network=none` in gVisor/Docker prevents Tor C2 and temp.sh exfil at
  the network layer in addition to pattern matching
- `--cap-drop=ALL` removes all Linux capabilities — the eBPF rootkit
  requires `CAP_BPF` to load, so it can't even attempt to run
- `--memory=512m --cpus=1` limits resource exhaustion from crypto mining payloads
- The install target directory is a temp dir deleted after each check —
  no malicious code persists to the host filesystem

---

## Updating Gate 5 status in docs after implementing

Once the runner is live in your CI, update:

1. `README.md` — remove ⚠ backlog notes from Gate 5 rows
2. `docs/index.html` — replace amber stub banners with green confirmed coverage
3. OWASP table — change CICD-SEC-3 and CICD-SEC-6 from "partial" to "full"
4. `sandbox/runner.py` — remove the STUB warning from the module docstring
5. Bump to v0.4.0

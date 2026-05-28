# OSS Trust Framework

**Open Source Supply Chain Trust Validation Pipeline**

A multi-gate security framework that validates open source dependency updates before they reach your application — with a hardened expedited lane for zero-day CVE patches.

---

## The Problem

Malicious packages depend on speed. A compromised maintainer account publishes a malicious release; automated dependency tooling ingests it within minutes. The attacker wins before anyone notices.

This framework breaks that race with five mandatory validation gates and a configurable age hold — while providing a strictly controlled bypass for legitimate zero-day patches that need to move fast.

---

## Architecture

```
Dependency update request
        │
        ▼
┌───────────────────┐     < 24 h, no CVE ──► BLOCKED
│  Gate 1: Age      │
│  < 72 h hold      │     Zero-day CVE? ──► Expedited Lane (see below)
└────────┬──────────┘
         │ ≥ 24 h
         ▼
┌───────────────────┐
│  Gate 2: Sig      │     Mismatch ──► REJECTED
│  Sigstore / GPG   │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 3: OOB      │     Score low ──► QUARANTINE
│  OpenSSF/OSV/     │
│  deps.dev         │ ◄── Zero-day lane rejoins here
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 4: SBOM     │     Unexpected deps ──► QUARANTINE
│  delta + hash pin │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 5: Sandbox  │     Malicious behavior ──► BLOCKED
│  gVisor / no net  │
└────────┬──────────┘
         │
         ▼
    Staged rollout ──────────────────────────────► APPROVED
```

### Zero-Day Expedited Lane

Bypasses the **age gate only**. All other gates remain mandatory.

```
CVE validated (NVD + OSV + GHSA, 2-of-3 sources)
        │
        ▼
Quorum approval (2-of-3 named approvers, MFA required, requester excluded)
        │
        ▼
Signature + timing check (signed after CVE publication)
        │
        ▼
Isolated sandbox (gVisor, no network)
        │
        ▼
Audit record (SIEM event + ticket link mandatory)
        │
        ▼
Rejoin at Gate 3 (out-of-band trust)
        │
        ▼
Immediate full-fleet deploy + 48 h elevated alert window
```

---

## Quickstart

```bash
pip install oss-trust-framework

# Run the full pipeline against a single package
oss-trust check --package requests --version 2.32.3 --ecosystem PyPI

# Request a zero-day expedited exception
oss-trust zeroday request \
  --cve CVE-2024-XXXXX \
  --package requests \
  --version 2.32.4 \
  --requester security@yourorg.com
```

---

## Installation

```bash
# From PyPI
pip install oss-trust-framework

# From source
git clone https://github.com/YOUR_ORG/oss-trust-framework
cd oss-trust-framework
pip install -e ".[dev]"
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

Key settings in `config/pipeline.yaml`:

```yaml
age_gate:
  hard_block_hours: 24      # Releases younger than this: auto-blocked
  hold_hours: 72            # Releases in this window: human approval required

trust_scoring:
  min_score: 60             # OpenSSF composite score threshold (0-100)
  require_zero_vulns: true  # Fail if any active CVE against this version

zero_day:
  required_approvers: 2     # Quorum size
  token_ttl_hours: 6        # Exception token expiry
  max_exceptions_per_24h: 3 # Circuit breaker

sandbox:
  runtime: gvisor           # gvisor | firecracker | docker
  network: none
  timeout_seconds: 120
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Validate dependency update
  uses: YOUR_ORG/oss-trust-framework/.github/actions/validate@main
  with:
    package: ${{ env.PACKAGE_NAME }}
    version: ${{ env.PACKAGE_VERSION }}
    ecosystem: ${{ env.ECOSYSTEM }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    osv-api-key: ${{ secrets.OSV_API_KEY }}
```

See [`.github/workflows/example-pr-check.yml`](.github/workflows/example-pr-check.yml) for a full pull-request gate example.

---

## Gate Reference

| Gate | What it checks | Fail action | Bypassable? |
|---|---|---|---|
| 1 — Age | Release timestamp vs configurable thresholds | Block / Hold | Yes, with CVE + quorum |
| 2 — Signature | Sigstore transparency log / GPG key | Reject | No |
| 3 — OOB Trust | OpenSSF Scorecard, OSV, deps.dev | Quarantine | No |
| 4 — SBOM delta | New transitive dependencies, hash mismatch | Quarantine | No |
| 5 — Sandbox | Install-time behavior in isolated VM | Block | No |

---

## Zero-Day Lane Circuit Breakers

The expedited lane automatically suspends under these conditions:

- More than 3 exception requests in a 24-hour window
- Same requester files two exceptions within 48 hours (escalates to CISO)
- Any exception-deployed package receives a new CVE within 30 days
- Monthly retrospective finds process violations

---

## Out-of-Band Trust Sources

Gate 3 queries these sources independently of the package repository:

| Source | API | What it provides |
|---|---|---|
| OpenSSF Scorecard | `api.securityscorecards.dev` | Security hygiene score |
| deps.dev (Google) | `api.deps.dev` | Dependency graph, advisories |
| OSV.dev | `api.osv.dev` | Cross-ecosystem CVE database |
| GitHub Advisories | `api.github.com/advisories` | Manually reviewed, high signal |
| npm Advisory DB | Built into `npm audit` | npm-specific compromise history |

---

## Project Structure

```
oss-trust-framework/
├── src/
│   ├── age_check/        # Gate 1 — release timestamp validation
│   ├── signature/        # Gate 2 — Sigstore / GPG verification
│   ├── trust/            # Gate 3 — out-of-band trust aggregation
│   ├── sbom/             # Gate 4 — SBOM delta and hash pinning
│   ├── sandbox/          # Gate 5 — behavioral sandbox
│   ├── zeroday/          # Expedited lane — CVE validation + quorum
│   └── pipeline/         # Orchestrator — runs all gates in sequence
├── tests/
├── docs/
├── config/
│   └── pipeline.yaml
├── .github/
│   └── workflows/
├── .env.example
└── pyproject.toml
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All PRs must pass the framework's own pipeline check — we eat our own cooking.

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [OpenSSF Scorecard](https://securityscorecards.dev)
- [Sigstore / cosign](https://docs.sigstore.dev)
- [OSV — Open Source Vulnerabilities](https://osv.dev)
- [Google deps.dev](https://deps.dev)
- [SLSA Framework](https://slsa.dev)
- [Socket.dev supply chain analysis](https://socket.dev)
- [gVisor container sandbox](https://gvisor.dev)

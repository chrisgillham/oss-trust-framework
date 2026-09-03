# Contributing to OSS Trust Framework

---

## Development setup

```powershell
# Windows
git clone https://github.com/chrisgillham/oss-trust-framework
cd oss-trust-framework
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
```

```bash
# Mac/Linux
git clone https://github.com/chrisgillham/oss-trust-framework
cd oss-trust-framework
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

**Note on package structure:** The installable package lives at `oss_trust_framework/` (one level, not nested). `pyproject.toml` must contain:
```toml
[tool.hatch.build.targets.wheel]
packages = ["oss_trust_framework"]
```
And `oss_trust_framework/cli.py` must exist:
```python
from oss_trust_framework.pipeline.cli import main
```

---

## Running tests

```bash
# Full suite — 176 tests, all offline
pytest

# By gate
pytest tests/test_gate0_slopsquat.py            # Gate 0 — SlopsquatChecker + watchlist
pytest tests/test_gate1_age.py                   # Gate 1 — age threshold boundaries
pytest tests/test_gate2_cargo_provenance.py      # Gate 2 — Cargo Trusted Publishing
pytest tests/test_gate2_publisher_continuity.py  # Gate 2 — publisher identity continuity
pytest tests/test_gate3_trust.py                 # Gate 3 — OOB trust aggregation
pytest tests/test_gate5_behavioral.py            # Gate 5 — Miasma + IronWorm patterns
pytest tests/test_gate5_new_patterns.py          # Gate 5 — MINISHAI + MLARTIFACT patterns
pytest tests/test_zeroday_lane.py                # Zero-day — full quorum lifecycle
pytest tests/test_integration.py                 # Cross-gate integration + regression

# With coverage
pytest --cov=oss_trust_framework --cov-report=term-missing

# Specific test
pytest tests/test_gate5_behavioral.py::test_ironworm_001_tor_onion -v
```

All external API calls (PyPI, OSV, OpenSSF Scorecard, GitHub) are mocked. Tests run fully offline and should complete in under 30 seconds.

---

## Implementing stub gates

Three gates have working interfaces but stub implementations. These are good first issues:

### Gate 4 — SBOM delta (`oss_trust_framework/sbom/differ.py`)

```python
async def diff_sbom(package: str, version: str, ecosystem: str) -> tuple[bool, str]:
    """
    Generate CycloneDX SBOM before and after upgrade, diff them,
    and fail if unexpected transitive dependencies appear.
    
    Tools: syft, cdxgen
    Format: cyclonedx-json
    
    Returns (passed: bool, message: str)
    """
```

### Gate 5 — Sandbox runner (`oss_trust_framework/sandbox/runner.py`)

```python
async def run_sandboxed_install(package: str, version: str, ecosystem: str) -> list[dict]:
    """
    Execute package install in a gVisor microVM with no network access.
    Observe all syscall events and return them as a list of event dicts:
      {"type": "network"|"file_read"|"process"|"env_access", "value": "..."}
    
    Feed output to: behavioral_patterns.evaluate_sandbox_events(events)

    Event types: "network", "file_read", "process", "env_access", "python_call"
    (python_call is for ML artifact deserialization detection — MLARTIFACT patterns)

    Runtime options: gVisor (preferred), Firecracker, Docker (least preferred)
    """
```

### Gate 2 — GPG fallback (`oss_trust_framework/signature/gpg.py`)

```python
async def verify_gpg_signature(package: str, version: str, ecosystem: str) -> bool:
    """
    Verify GPG signature for ecosystems not yet on Sigstore.
    Keys must be pre-pinned in config/trusted_keys.asc — never fetch at verify time.
    """
```

Each stub returns `(True, "stub message")` so the pipeline runs end-to-end. Replace with real implementation and add tests alongside.

---

## Adding a new behavioral pattern

1. Add a new `BehavioralPattern` entry to `BEHAVIORAL_PATTERNS` in `oss_trust_framework/sandbox/behavioral_patterns.py`
2. Choose the appropriate `PatternCategory` (or add a new one)
3. Set `miasma_specific=True`, `ironworm_specific=True`, `minishai_specific=True`, or `mlartifact_specific=True` if applicable
4. Add a corresponding test in `tests/test_gate5_behavioral.py`
5. Update the pattern count assertion: `assert len(BEHAVIORAL_PATTERNS) == N`

Pattern ID conventions:
- `MIASMA-XXX` — observed in Miasma/Shai-Hulud campaigns
- `IRONWORM-XXX` — observed in IronWorm campaign
- `MINISHAI-XXX` — observed in Mini Shai-Hulud self-replicating worm campaign
- `MLARTIFACT-XXX` — ML artifact unsafe deserialization (Hugging Face exploit pattern)
- `CRED-XXX` — credential file access (cross-family)
- `PUBLISH-XXX` — package registry publish from install context
- `ENV-XXX` — environment variable harvesting
- `PROC-XXX` — process injection / obfuscated subprocess

---

## Adding a new ecosystem

1. Add the registry API URL constant to `oss_trust_framework/age_check/checker.py`
2. Implement `_fetch_release_time_<ecosystem>` and add dispatch in `_fetch_release_time`
3. Map the ecosystem name in `oss_trust_framework/trust/aggregator.py::_fetch_deps_dev`
4. Add the ecosystem to the `Choice` validator in `oss_trust_framework/pipeline/cli.py`
5. Add at least two tests in `tests/test_gate1_age.py` (one block, one pass)
6. Add the ecosystem to `config/trusted_publishers.yaml` with a comment block

---

## Adding to the trusted publisher allowlist

Use `check_all.py` in the demo repo to interactively populate `config/trusted_publishers.yaml`. For manual additions:

```bash
# Find canonical repo for any PyPI package
python -c "
import urllib.request, json
pkg = 'package-name'
resp = urllib.request.urlopen(f'https://pypi.org/pypi/{pkg}/json')
data = json.loads(resp.read())
print((data['info'].get('project_urls') or {}))
"

# For npm
npm view package-name repository.url
```

---

## Pull request guidelines

- All PRs must pass the framework's own CI gate (`dep-trust-check.yml`)
- New gates or bypass paths require security review from two named reviewers
- Zero-day lane changes (quorum count, TTL, circuit breakers) require CISO sign-off
- New behavioral patterns must include a test that verifies the pattern fires and a clean-install test that confirms it does not false-positive
- No dependency may be added without a corresponding entry in `config/trusted_publishers.yaml`
- The test count assertion in `test_gate5_behavioral.py::test_total_pattern_count` must be updated when patterns are added

---

## Versioning

- Patch (0.2.x): bug fixes, new behavioral patterns, test additions
- Minor (0.x.0): new gates, new ecosystems, zero-day lane changes
- Major (x.0.0): breaking API changes, gate removal

Update version in both `pyproject.toml` and `oss_trust_framework/pipeline/cli.py`.

---

## Security disclosures

Please report vulnerabilities via GitHub Security Advisories rather than opening a public issue. Go to the repository → Security → Advisories → New draft security advisory.

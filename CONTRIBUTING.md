# Contributing

## Development setup

```bash
git clone https://github.com/YOUR_ORG/oss-trust-framework
cd oss-trust-framework
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # fill in your values
```

## Running tests

```bash
pytest tests/ -v --cov=src --cov-report=term-missing
```

## Implementing stub gates

Three gates are currently stubbed and need production implementations:

| Gate | File | What to implement |
|---|---|---|
| 2 — Signature | `src/signature/verifier.py` | cosign/Sigstore transparency log query; GPG fallback; timing check for zero-day lane |
| 4 — SBOM delta | `src/sbom/differ.py` | syft or cdxgen invocation; CycloneDX JSON diff; lock file hash pinning |
| 5 — Sandbox | `src/sandbox/runner.py` | gVisor or Firecracker container launch; stdin feed of install command; log parsing for alert conditions |

Each stub returns `(True, "stub message")` so the pipeline runs end-to-end in tests. Replace with real logic and add tests alongside.

## Adding a new ecosystem

1. Add the registry API URL to `REGISTRY_APIS` in `src/age_check/checker.py`.
2. Implement `_fetch_release_time` dispatch for the new ecosystem.
3. Map the ecosystem name in `src/trust/aggregator.py::_fetch_deps_dev`.
4. Add the ecosystem to the `Choice` validator in `src/pipeline/cli.py`.
5. Add at least one test in `tests/test_age_check.py` for the new registry.

## Pull request guidelines

- All PRs must pass the framework's own CI gate (`dep-trust-check.yml`).
- New gates or bypass paths require security review from two named reviewers.
- Zero-day lane changes require CISO sign-off.
- No dependency may be added without a corresponding lockfile update.

## Security disclosures

Please report vulnerabilities to security@your-org.example.com rather than opening a public issue.

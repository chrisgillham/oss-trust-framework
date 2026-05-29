# Contributing to OSS Trust Framework

All PRs must pass the framework's own nine-gate pipeline. We eat our own cooking.

## Development setup

```bash
git clone https://github.com/chrisgillham/oss-trust-framework
cd oss-trust-framework
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # fill in your credentials
```

## Running tests

```bash
pytest tests/ -v --tb=short
```

## Running the pipeline locally

```bash
oss-trust check --package requests --version 2.32.3 --ecosystem pypi
```

## Code standards

- Python 3.11+, type-annotated, formatted with `ruff`
- All new gates must implement the `async def evaluate(...) -> GateResult` interface
- New gates must be registered in `src/pipeline/__init__.py`
- Every gate must be fail-closed: exceptions → QUARANTINE, not APPROVED

## Adding a gate

1. Create `src/your_gate/__init__.py` with a class implementing `evaluate()`
2. Add config section to `config/pipeline.yaml`
3. Import and wire into `Pipeline.run()` in `src/pipeline/__init__.py`
4. Add tests to `tests/test_your_gate.py`
5. Document in README.md under the gate reference table

## Submitting a PR

- PRs targeting `main` trigger `dep-trust-check.yml`
- All actions must be pinned to commit SHAs (Gate 9 enforces this)
- Include test coverage for any new gate logic
- Update `config/pipeline.yaml` with new configuration keys

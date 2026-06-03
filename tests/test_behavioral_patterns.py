"""Tests for Gate 5 — Miasma-class behavioral pattern matching."""

from oss_trust_framework.sandbox.behavioral_patterns import (
    evaluate_sandbox_events,
    has_critical_findings,
    summarise_findings,
    PatternCategory,
)


def test_cloud_metadata_access_detected():
    events = [{"type": "network", "value": "169.254.169.254/latest/meta-data/iam/security-credentials"}]
    findings = evaluate_sandbox_events(events)
    assert len(findings) > 0
    assert any(f["category"] == PatternCategory.CLOUD_METADATA_ACCESS for f in findings)
    assert has_critical_findings(findings)


def test_oidc_token_request_detected():
    events = [{"type": "network", "value": "https://token.actions.githubusercontent.com"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "MIASMA-010" for f in findings)
    assert has_critical_findings(findings)


def test_npm_registry_publish_during_install_detected():
    """npm PUT during package install is the Miasma re-publish vector."""
    events = [{"type": "network", "value": "https://registry.npmjs.org/@redhat-cloud-services%2Ffrontend-components"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "PUBLISH-001" for f in findings)
    assert has_critical_findings(findings)


def test_kubernetes_secret_read_detected():
    events = [{"type": "file_read", "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "CRED-001" for f in findings)
    assert has_critical_findings(findings)


def test_oidc_packages_env_var_detected():
    events = [{"type": "env_access", "value": "OIDC_PACKAGES=@redhat-cloud-services/frontend-components"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "ENV-002" for f in findings)
    assert any(f["miasma_specific"] for f in findings)


def test_gcp_metadata_detected():
    events = [{"type": "network", "value": "metadata.google.internal/computeMetadata/v1/instance/service-accounts"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "MIASMA-002" for f in findings)


def test_clean_install_no_findings():
    """A normal package install with no suspicious events should produce no findings."""
    events = [
        {"type": "file_read", "value": "/tmp/npm-install/package.json"},
        {"type": "process", "value": "node index.js"},
        {"type": "network", "value": "registry.npmjs.org/some-dep/-/some-dep-1.0.0.tgz"},
    ]
    # registry.npmjs.org GET (download) is fine; only PUT (publish) is flagged
    findings = evaluate_sandbox_events(events)
    # The GET to registry.npmjs.org should not match PUBLISH-001 (which matches PUT/publish context)
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    assert len(critical) == 0


def test_multiple_patterns_reported():
    events = [
        {"type": "network", "value": "169.254.169.254"},
        {"type": "network", "value": "token.actions.githubusercontent.com"},
        {"type": "file_read", "value": "/root/.aws/credentials"},
    ]
    findings = evaluate_sandbox_events(events)
    pattern_ids = {f["pattern_id"] for f in findings}
    assert "MIASMA-001" in pattern_ids
    assert "MIASMA-010" in pattern_ids
    assert "CRED-003" in pattern_ids


def test_summarise_findings_readable():
    events = [
        {"type": "network", "value": "169.254.169.254"},
        {"type": "network", "value": "token.actions.githubusercontent.com"},
    ]
    findings = evaluate_sandbox_events(events)
    summary = summarise_findings(findings)
    assert "CRITICAL" in summary
    assert len(summary) > 0


def test_empty_events_no_findings():
    assert evaluate_sandbox_events([]) == []
    assert not has_critical_findings([])
    assert "No behavioral indicators" in summarise_findings([])

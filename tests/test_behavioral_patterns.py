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


# ---------------------------------------------------------------------------
# IronWorm-specific tests (JFrog, 2026-06-03)
# ---------------------------------------------------------------------------

def test_tor_onion_c2_detected():
    """IronWorm beacons to a Tor hidden service — .onion destination must fire."""
    events = [{"type": "network", "value": "http://abc123def456.onion/api/agent"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-001" for f in findings)
    assert has_critical_findings(findings)
    assert any(f.get("ironworm_specific") for f in findings)


def test_tor_socks_port_detected():
    """IronWorm may route through local Tor SOCKS proxy on port 9050."""
    events = [{"type": "network", "value": "127.0.0.1:9050"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-001b" for f in findings)
    assert has_critical_findings(findings)


def test_tempsh_fallback_exfil_detected():
    """IronWorm uses temp.sh as a fallback C2 channel."""
    events = [{"type": "network", "value": "https://temp.sh/upload"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-001c" for f in findings)
    assert has_critical_findings(findings)


def test_ebpf_rootkit_syscall_detected():
    """IronWorm loads an eBPF kernel rootkit — bpf() syscall from install context."""
    events = [{"type": "process", "value": "BPF_PROG_LOAD fd=3"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-002" for f in findings)
    assert has_critical_findings(findings)


def test_tools_setup_binary_detected():
    """IronWorm drops its Rust ELF payload as tools/setup."""
    events = [{"type": "process", "value": "./tools/setup --collect"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-002b" for f in findings)
    assert has_critical_findings(findings)


def test_openai_api_key_harvest_detected():
    """IronWorm harvests AI API keys including OpenAI and Anthropic."""
    events = [{"type": "env_access", "value": "OPENAI_API_KEY=sk-abc123"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-003" for f in findings)
    assert has_critical_findings(findings)


def test_anthropic_api_key_harvest_detected():
    events = [{"type": "env_access", "value": "ANTHROPIC_API_KEY=sk-ant-abc123"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-003" for f in findings)
    assert has_critical_findings(findings)


def test_vault_token_harvest_detected():
    """IronWorm targets HashiCorp Vault tokens."""
    events = [{"type": "env_access", "value": "VAULT_TOKEN=s.abc123def"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-004b" for f in findings)
    assert has_critical_findings(findings)


def test_exodus_wallet_detected():
    """IronWorm steals Exodus cryptocurrency wallet seed phrases."""
    events = [{"type": "file_read", "value": "/root/.config/Exodus/exodus.wallet"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] in ("IRONWORM-005", "IRONWORM-005b") for f in findings)
    assert has_critical_findings(findings)


def test_npmrc_credential_theft_detected():
    """IronWorm reads .npmrc to steal npm auth tokens for self-propagation."""
    events = [{"type": "file_read", "value": "/root/.npmrc"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-006" for f in findings)


def test_workflow_hijack_detected():
    """IronWorm overwrites GitHub Actions workflows to exfiltrate secrets."""
    events = [{"type": "file_read", "value": ".github/workflows/release.yml"}]
    findings = evaluate_sandbox_events(events)
    assert any(f["pattern_id"] == "IRONWORM-007" for f in findings)
    assert has_critical_findings(findings)


def test_get_attack_family_identifies_ironworm():
    from oss_trust_framework.sandbox.behavioral_patterns import get_attack_family
    events = [
        {"type": "network", "value": "abc.onion/api/agent"},
        {"type": "env_access", "value": "OPENAI_API_KEY=sk-123"},
    ]
    findings = evaluate_sandbox_events(events)
    families = get_attack_family(findings)
    assert "IronWorm" in families


def test_get_attack_family_identifies_both():
    """An event set firing both Miasma and IronWorm patterns."""
    from oss_trust_framework.sandbox.behavioral_patterns import get_attack_family
    events = [
        {"type": "network", "value": "169.254.169.254"},         # MIASMA-001
        {"type": "network", "value": "abc123.onion/api/agent"},  # IRONWORM-001
    ]
    findings = evaluate_sandbox_events(events)
    families = get_attack_family(findings)
    assert "Miasma/Shai-Hulud" in families
    assert "IronWorm" in families


def test_summarise_includes_attack_family():
    events = [{"type": "network", "value": "abc.onion/c2"}]
    findings = evaluate_sandbox_events(events)
    summary = summarise_findings(findings)
    assert "IronWorm" in summary

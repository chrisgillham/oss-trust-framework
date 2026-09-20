#!/usr/bin/env python3
"""
Format OSS Trust Framework check results into a user-friendly GitHub PR comment.

Usage:
    python format_trust_check_pr_comment.py trust_report.json
"""

import json
import sys
from pathlib import Path
from typing import Any


def get_icon(outcome: str) -> str:
    """Get emoji icon for outcome."""
    icons = {
        "approved": "✅",
        "pass": "✅",
        "quarantined": "⚠️",
        "quarantine": "⚠️",
        "blocked": "🚫",
        "block": "🚫",
    }
    return icons.get(outcome.lower(), "❓")


def get_gate_name(gate: str) -> str:
    """Convert gate number/name to human-readable name."""
    gate_names = {
        "age": "Gate 1 — Age (24h+ threshold)",
        "provenance": "Gate 2 — Provenance (signature verification)",
        "oob_trust": "Gate 3 — Out-of-Band Trust (OpenSSF Scorecard, CVEs)",
        "sbom": "Gate 4 — SBOM Delta (dependency changes)",
        "sandbox": "Gate 5 — Behavioral Sandbox (install-time behavior)",
        "behavioral": "Gate 5 — Behavioral Sandbox",
    }
    return gate_names.get(gate.lower(), f"Gate — {gate}")


def format_gate_details(gates: list) -> str:
    """Format gate check details."""
    passed = []
    failed = []
    
    for gate in gates:
        gate_name = get_gate_name(gate.get("gate", "unknown"))
        passed_flag = gate.get("passed", False)
        decision = gate.get("decision", "").upper()
        
        icon = "✅" if passed_flag else "⚠️"
        
        if passed_flag:
            passed.append(f"{icon} {gate_name}")
        else:
            reason = gate.get("message", decision)
            failed.append(f"{icon} {gate_name} → {reason}")
    
    output = ""
    if passed:
        output += "**Passed:**\n"
        for line in passed:
            output += f"  {line}\n"
    
    if failed:
        if passed:
            output += "\n"
        output += "**Needs Review:**\n"
        for line in failed:
            output += f"  {line}\n"
    
    return output.strip()


def format_single_package(result: dict) -> str:
    """Format a single package result into a comment section."""
    package = result.get("package", "unknown")
    version = result.get("version", "unknown")
    outcome = result.get("outcome", "unknown").lower()
    message = result.get("message", "")
    gates = result.get("gates", [])
    
    icon = get_icon(outcome)
    
    # Build the comment
    comment = f"### {icon} {package}=={version}\n\n"
    comment += f"**Outcome:** {outcome.upper()}\n"
    
    if message:
        comment += f"**Details:** {message}\n"
    
    if gates:
        comment += f"\n{format_gate_details(gates)}\n"
    
    # Add guidance based on outcome
    if outcome == "approved":
        comment += "\n✓ **All gates passed.** Safe to merge from a supply chain perspective.\n"
    
    elif outcome in ("quarantined", "quarantine"):
        comment += "\n⚠️ **Manual review recommended.**\n"
        comment += "\nThis package passed age and provenance gates but has concerns:\n"
        comment += "- Very new release (< 24 hours old)\n"
        comment += "- Low OpenSSF Scorecard score (maintenance concerns)\n"
        comment += "- New transitive dependency introduced\n"
        comment += "\n**Action:**\n"
        comment += "1. Check the details above\n"
        comment += "2. Review the package's GitHub repo (if concerns exist)\n"
        comment += "3. If satisfied, merge this PR\n"
        comment += "4. If concerned, request an older or better-maintained version\n"
    
    elif outcome == "blocked":
        comment += "\n🚫 **DO NOT MERGE** — Security gate failed.\n"
        comment += "\n**Required Actions:**\n"
        comment += "- If CVE found: Use a patched version\n"
        comment += "- If signature invalid: Possible account compromise — escalate to security team\n"
        comment += "- If malicious behavior: Report to security team immediately\n"
        comment += "\nFor questions, contact your security team.\n"
    
    return comment


def format_pr_comment(results: list) -> str:
    """Format multiple package results into a complete PR comment."""
    if not results:
        return "❌ No trust check results found.\n"
    
    # Count outcomes
    approved = sum(1 for r in results if r.get("outcome", "").lower() in ("approved", "pass"))
    quarantined = sum(1 for r in results if r.get("outcome", "").lower() in ("quarantined", "quarantine"))
    blocked = sum(1 for r in results if r.get("outcome", "").lower() in ("blocked", "block"))
    total = len(results)
    
    # Overall status
    if blocked > 0:
        overall_icon = "🚫"
        overall_status = "BLOCKED — Do not merge"
    elif quarantined > 0:
        overall_icon = "⚠️"
        overall_status = "REVIEW NEEDED"
    else:
        overall_icon = "✅"
        overall_status = "APPROVED"
    
    # Build header
    comment = f"## {overall_icon} OSS Trust Framework — {overall_status}\n\n"
    comment += f"**Summary:** {approved} approved, {quarantined} need review, {blocked} blocked (of {total} dependencies)\n\n"
    
    # Add individual package results
    for result in results:
        comment += format_single_package(result)
        comment += "\n---\n"
    
    # Add footer
    comment += "\n**Framework:** [OSS Trust Framework v0.8.0](https://github.com/chrisgillham/oss-trust-framework)\n"
    comment += "**Gates:** Age (24h+) | Provenance (signatures) | OOB Trust (Scorecard/CVEs) | SBOM Delta | Behavioral Sandbox\n"
    
    return comment


def main():
    if len(sys.argv) < 2:
        print("Usage: python format_trust_check_pr_comment.py <trust_report.json>")
        sys.exit(1)
    
    report_path = Path(sys.argv[1])
    
    if not report_path.exists():
        print(f"Error: File not found: {report_path}")
        sys.exit(1)
    
    try:
        with open(report_path) as f:
            data = json.load(f)
        
        # Handle both single result and array of results
        if isinstance(data, dict):
            results = [data]
        else:
            results = data
        
        comment = format_pr_comment(results)
        print(comment)
        
        # Also save to file if requested
        if len(sys.argv) > 2 and sys.argv[2] == "--save":
            output_path = Path("pr_comment.md")
            output_path.write_text(comment)
            print(f"\n✅ Comment saved to {output_path}", file=sys.stderr)
    
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {report_path}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

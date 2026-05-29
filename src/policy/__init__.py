"""
Policy Engine — Policy-as-Code Quorum Governance
Evaluates policy.yaml rules against a TrustResult to determine:
  - effective quorum threshold
  - required Discord member IDs
  - additional notification targets
  - post-vote action (e.g. revoke_package)
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    rule_name:           str
    threshold:           float
    deadline_hours:      int
    require_members:     list[str] = field(default_factory=list)
    notify_additional:   list[str] = field(default_factory=list)
    action_on_approved:  str = ""
    description:         str = ""


class PolicyEngine:
    def __init__(self, policy_path: str | Path = "config/policy.yaml") -> None:
        path = Path(policy_path)
        if path.exists():
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
            self.rules = raw.get("quorum_policy", {})
        else:
            log.warning(f"[policy] {policy_path} not found — using default rule only")
            self.rules = {}

        self._resolve_env_ids()

    def evaluate(self, result) -> PolicyDecision:  # result: TrustResult
        """
        Walk rules in definition order and return the first matching rule.
        Falls back to 'default' if no rule matches.
        """
        default = self._make_decision("default", self.rules.get("default", {}))

        for rule_name, rule_cfg in self.rules.items():
            if rule_name == "default":
                continue
            condition = rule_cfg.get("condition", "")
            if condition and self._evaluate_condition(condition, result):
                log.info(f"[policy] Rule '{rule_name}' matched: {condition}")
                return self._make_decision(rule_name, rule_cfg)

        log.info("[policy] No rule matched — using default")
        return default

    def _evaluate_condition(self, condition: str, result) -> bool:
        """
        Evaluate a condition string against the TrustResult.
        Supports:
          trust_score < N | > N | == N | <= N | >= N
          slsa_level < N
          flag_xxx == true | false
          license_changed == true | false
          license_copyleft == true
          runtime_anomaly == true
          historical_prior_denials >= N
          dependency_class IN [cls1, cls2]
          AND / OR operators (simple left-to-right evaluation)
        """
        try:
            # Resolve variables from result
            ctx = {
                "trust_score":             result.trust_score,
                "slsa_level":              result.slsa.get("level", 0),
                "flag_typosquatting":      result.flags.get("typosquatting", False),
                "flag_behavior_change":    result.flags.get("behavior_change", False),
                "flag_author_reputation":  result.flags.get("author_reputation", False),
                "flag_provenance":         result.flags.get("provenance_activity", False),
                "flag_ai_hallucination":   result.flags.get("ai_hallucination", False),
                "license_changed":         result.flags.get("license_changed", False),
                "license_copyleft":        result.flags.get("license_copyleft", False),
                "runtime_anomaly":         result.flags.get("runtime_anomaly", False),
                "historical_prior_denials": result.historical_prior_denials,
                "dependency_class":        result.slsa.get("dependency_class", "general"),
            }

            # Handle AND / OR by splitting and evaluating each sub-condition
            if " AND " in condition:
                return all(
                    self._eval_single(part.strip(), ctx)
                    for part in condition.split(" AND ")
                )
            if " OR " in condition:
                return any(
                    self._eval_single(part.strip(), ctx)
                    for part in condition.split(" OR ")
                )

            return self._eval_single(condition.strip(), ctx)

        except Exception as exc:
            log.warning(f"[policy] Condition evaluation error '{condition}': {exc}")
            return False

    def _eval_single(self, expr: str, ctx: dict) -> bool:
        """Evaluate a single comparison expression."""
        # IN operator: dependency_class IN [auth, crypto]
        in_match = re.match(r"(\w+)\s+IN\s+\[([^\]]+)\]", expr, re.IGNORECASE)
        if in_match:
            var   = in_match.group(1)
            items = [i.strip() for i in in_match.group(2).split(",")]
            return str(ctx.get(var, "")).lower() in [i.lower() for i in items]

        # Comparison: var OP value
        cmp_match = re.match(
            r"(\w+)\s*(==|!=|<=|>=|<|>)\s*(true|false|[\d.]+)",
            expr, re.IGNORECASE,
        )
        if cmp_match:
            var, op, raw_val = cmp_match.groups()
            lhs = ctx.get(var)
            if raw_val.lower() == "true":
                rhs = True
            elif raw_val.lower() == "false":
                rhs = False
            else:
                rhs = float(raw_val)

            ops = {
                "==": lambda a, b: a == b,
                "!=": lambda a, b: a != b,
                "<":  lambda a, b: a < b,
                ">":  lambda a, b: a > b,
                "<=": lambda a, b: a <= b,
                ">=": lambda a, b: a >= b,
            }
            return ops[op](lhs, rhs)

        log.warning(f"[policy] Unrecognised condition expression: '{expr}'")
        return False

    def _make_decision(self, rule_name: str, cfg: dict) -> PolicyDecision:
        return PolicyDecision(
            rule_name          = rule_name,
            threshold          = float(cfg.get("threshold", 0.5)),
            deadline_hours     = int(cfg.get("deadline_hours", 24)),
            require_members    = cfg.get("require_members", []),
            notify_additional  = cfg.get("notify_additional", []),
            action_on_approved = cfg.get("action_on_approved", ""),
            description        = cfg.get("description", ""),
        )

    def _resolve_env_ids(self) -> None:
        """Replace ${ENV_VAR} placeholders in member lists with actual env values."""
        for rule_name, rule_cfg in self.rules.items():
            for field_name in ("require_members", "notify_additional"):
                ids = rule_cfg.get(field_name, [])
                resolved = []
                for member_id in ids:
                    if member_id.startswith("${") and member_id.endswith("}"):
                        env_key = member_id[2:-1]
                        val = os.environ.get(env_key, "")
                        if val:
                            resolved.append(val)
                        else:
                            log.warning(
                                f"[policy] Env var '{env_key}' not set "
                                f"for rule '{rule_name}'.{field_name}"
                            )
                    else:
                        resolved.append(member_id)
                rule_cfg[field_name] = resolved

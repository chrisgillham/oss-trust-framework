import yaml

def load_config(path: str = "config/pipeline.yaml") -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

def build_quorum_manager(config: dict):
    from oss_trust_framework.zeroday.validator import QuorumApprovalManager
    zd = config.get("zero_day", {})
    approvers = {
        a["id"]: a["email"]
        for a in zd.get("named_approvers", [])
    }
    class StubMFA:
        async def verify(self, approver_id, token):
            return len(token) == 6
    return QuorumApprovalManager(
        named_approvers=approvers,
        required_approvers=zd.get("required_approvers", 2),
        mfa_verifier=StubMFA(),
    )

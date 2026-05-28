"""Tests for the zero-day quorum approval manager."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

from oss_trust_framework.zeroday.validator import (
    ApprovalStatus,
    MFAVerifier,
    QuorumApprovalManager,
)

APPROVERS = {
    "approver_001": "ciso@example.com",
    "approver_002": "secarch@example.com",
    "approver_003": "devsecops@example.com",
}
REQUESTER = "dev@example.com"


class AlwaysValidMFA:
    async def verify(self, approver_id: str, token: str) -> bool:
        return True


class AlwaysInvalidMFA:
    async def verify(self, approver_id: str, token: str) -> bool:
        return False


def make_manager(mfa=None) -> QuorumApprovalManager:
    return QuorumApprovalManager(
        named_approvers=APPROVERS,
        required_approvers=2,
        mfa_verifier=mfa or AlwaysValidMFA(),
    )


def test_create_request_excludes_requester():
    """The requester must not appear in the eligible approver pool."""
    mgr = make_manager()
    # Make one of the approvers the requester
    requester_email = APPROVERS["approver_001"]
    req = mgr.create_request("CVE-2024-0001", "requests", "2.32.4", "PyPI", requester_email)
    assert "approver_001" not in req.eligible_approvers


def test_create_request_status_pending():
    mgr = make_manager()
    req = mgr.create_request("CVE-2024-0001", "requests", "2.32.4", "PyPI", REQUESTER)
    assert req.status == ApprovalStatus.PENDING


@pytest.mark.asyncio
async def test_quorum_reached_on_two_approvals():
    mgr = make_manager()
    req = mgr.create_request("CVE-2024-0001", "requests", "2.32.4", "PyPI", REQUESTER)

    r1 = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert r1["status"] == ApprovalStatus.PENDING.value

    r2 = await mgr.record_approval(req.request_id, "approver_002", "123456")
    assert r2["status"] == ApprovalStatus.APPROVED.value
    assert mgr.get_status(req.request_id) == ApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_duplicate_vote_rejected():
    mgr = make_manager()
    req = mgr.create_request("CVE-2024-0001", "requests", "2.32.4", "PyPI", REQUESTER)

    await mgr.record_approval(req.request_id, "approver_001", "123456")
    r2 = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert "error" in r2
    assert "already voted" in r2["error"]


@pytest.mark.asyncio
async def test_mfa_failure_blocks_approval():
    mgr = make_manager(mfa=AlwaysInvalidMFA())
    req = mgr.create_request("CVE-2024-0001", "requests", "2.32.4", "PyPI", REQUESTER)

    result = await mgr.record_approval(req.request_id, "approver_001", "wrong")
    assert "error" in result
    assert "MFA" in result["error"]
    assert mgr.get_status(req.request_id) == ApprovalStatus.PENDING


@pytest.mark.asyncio
async def test_expired_request_rejected(monkeypatch):
    """Requests past their TTL must be rejected."""
    mgr = make_manager()
    req = mgr.create_request("CVE-2024-0001", "requests", "2.32.4", "PyPI", REQUESTER)

    # Wind the clock past the TTL
    monkeypatch.setattr(
        "oss_trust_framework.zeroday.validator.time.time",
        lambda: req.created_at + 6 * 3600 + 1,
    )

    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert "error" in result
    assert "expired" in result["error"].lower()


@pytest.mark.asyncio
async def test_unknown_approver_rejected():
    mgr = make_manager()
    req = mgr.create_request("CVE-2024-0001", "requests", "2.32.4", "PyPI", REQUESTER)

    result = await mgr.record_approval(req.request_id, "approver_ghost", "123456")
    assert "error" in result
    assert "not in named approver list" in result["error"]


@pytest.mark.asyncio
async def test_unknown_request_rejected():
    mgr = make_manager()
    result = await mgr.record_approval("doesnotexist", "approver_001", "123456")
    assert "error" in result

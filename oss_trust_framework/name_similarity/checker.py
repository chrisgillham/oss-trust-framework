"""
Gate 0 — Package Name Similarity Check.

Detects typosquatting and impersonation attacks by comparing the requested
package name against all entries in the trusted publishers allowlist using
multiple similarity algorithms.

Real-world example this catches:
  postmark-mcp-evil  vs  postmark-mcp  (suffix addition)
  reqeusts           vs  requests      (transposition typosquat)
  cryptography2      vs  cryptography  (numeric suffix)

Design notes:
  - Runs BEFORE all other gates (Gate 0)
  - No network access required — purely local string comparison
  - Allowlist (trusted_publishers.yaml) is the source of truth
  - Exact allowlist match = immediate PASS, no further checking
  - Thresholds configurable in config/pipeline.yaml
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import re


class SimilarityDecision(str, Enum):
    PASS = "pass"    # Exact match, or no suspicious similarity found
    WARN = "warn"    # High similarity — manual review recommended
    BLOCK = "block"  # Extremely high similarity — likely impersonation


@dataclass
class SimilarityResult:
    decision: SimilarityDecision
    package: str
    ecosystem: str
    closest_match: Optional[str]
    similarity_score: float      # 0.0 to 1.0
    algorithm: str
    message: str
    in_allowlist: bool


# ---------------------------------------------------------------------------
# String similarity algorithms
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein edit distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    matrix = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        matrix[i][0] = i
    for j in range(len(b) + 1):
        matrix[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            )
    return matrix[len(a)][len(b)]


def _levenshtein_similarity(a: str, b: str) -> float:
    """Normalised: 1.0 = identical, 0.0 = completely different."""
    if a == b:
        return 1.0
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return 1.0 - (_levenshtein(a, b) / max_len)


def _normalise(name: str) -> str:
    """Normalise package name: lowercase, collapse separators to hyphen."""
    return re.sub(r"[-_.]+", "-", name.lower())


def _prefix_similarity(a: str, b: str) -> float:
    """
    Detects suffix-addition attacks: postmark-mcp-evil vs postmark-mcp.
    Returns elevated score when one name is a prefix of the other.
    """
    na, nb = _normalise(a), _normalise(b)
    if na == nb:
        return 1.0
    shorter, longer = (na, nb) if len(na) <= len(nb) else (nb, na)
    if longer.startswith(shorter):
        suffix = longer[len(shorter):]
        # Short suffixes (-evil, -2, -v2) are more suspicious
        return 0.95 if len(suffix.lstrip("-")) <= 4 else 0.85
    return 0.0


def _char_swap_similarity(a: str, b: str) -> float:
    """
    Detects adjacent character transpositions: reqeusts vs requests.
    Returns high score if strings differ only by one adjacent swap.
    """
    na, nb = _normalise(a), _normalise(b)
    if na == nb:
        return 1.0
    if len(na) != len(nb):
        return 0.0
    diffs = [i for i in range(len(na)) if na[i] != nb[i]]
    if len(diffs) == 2:
        i, j = diffs
        if j == i + 1 and na[i] == nb[j] and na[j] == nb[i]:
            return 0.95
    return 0.0


def _composite_similarity(a: str, b: str) -> tuple[float, str]:
    """Highest score across all algorithms, plus the winning algorithm name."""
    scores = {
        "levenshtein": _levenshtein_similarity(_normalise(a), _normalise(b)),
        "prefix":      _prefix_similarity(a, b),
        "char_swap":   _char_swap_similarity(a, b),
    }
    best = max(scores, key=lambda k: scores[k])
    return scores[best], best


# ---------------------------------------------------------------------------
# Gate 0 entry point
# ---------------------------------------------------------------------------

def check_name_similarity(
    package: str,
    ecosystem: str,
    trusted_publishers: dict,
    warn_threshold: float = 0.80,
    block_threshold: float = 0.92,
) -> SimilarityResult:
    """
    Gate 0: Detect typosquatting and impersonation by comparing the package
    name against all trusted packages in the allowlist.

    Args:
        package:            Package name being validated.
        ecosystem:          "PyPI", "npm", "Cargo", etc.
        trusted_publishers: Loaded trusted_publishers.yaml dict.
        warn_threshold:     Similarity above which a WARN is issued (default 0.80).
        block_threshold:    Similarity above which a BLOCK is issued (default 0.92).

    Returns:
        SimilarityResult with decision, closest match, score, and message.

    Coverage note:
        This gate addresses typosquatting and simple impersonation (suffix-addition,
        transposition). It does NOT detect semantically deceptive names with low
        string similarity (e.g. "secure-requests" impersonating "requests").
        Runtime security monitoring remains necessary as a complementary control.
    """
    ecosystem_publishers = trusted_publishers.get(ecosystem, {})
    known_packages = list(ecosystem_publishers.keys())

    # Exact allowlist match — pass immediately
    if package in ecosystem_publishers:
        return SimilarityResult(
            decision=SimilarityDecision.PASS,
            package=package,
            ecosystem=ecosystem,
            closest_match=package,
            similarity_score=1.0,
            algorithm="exact_match",
            message=f"{package} is in the trusted publisher allowlist — Gate 0 pass.",
            in_allowlist=True,
        )

    if not known_packages:
        return SimilarityResult(
            decision=SimilarityDecision.PASS,
            package=package,
            ecosystem=ecosystem,
            closest_match=None,
            similarity_score=0.0,
            algorithm="none",
            message=(
                f"No trusted publishers configured for {ecosystem}. "
                f"Populate trusted_publishers.yaml to enable Gate 0 name similarity checks."
            ),
            in_allowlist=False,
        )

    # Find most similar known package
    best_score, best_match, best_algo = 0.0, None, "levenshtein"
    for known in known_packages:
        score, algo = _composite_similarity(package, known)
        if score > best_score:
            best_score, best_match, best_algo = score, known, algo

    # Near-identical normalised name (different separators/casing only)
    if best_score >= 0.999:
        return SimilarityResult(
            decision=SimilarityDecision.BLOCK,
            package=package,
            ecosystem=ecosystem,
            closest_match=best_match,
            similarity_score=best_score,
            algorithm=best_algo,
            message=(
                f"BLOCK: {package} is a normalised duplicate of trusted package "
                f"{best_match}. Likely impersonation attack. "
                f"Add to allowlist explicitly if intentional."
            ),
            in_allowlist=False,
        )

    if best_score >= block_threshold:
        return SimilarityResult(
            decision=SimilarityDecision.BLOCK,
            package=package,
            ecosystem=ecosystem,
            closest_match=best_match,
            similarity_score=round(best_score, 3),
            algorithm=best_algo,
            message=(
                f"BLOCK: {package} is {best_score:.0%} similar to trusted package "
                f"{best_match} (via {best_algo}). "
                f"Likely typosquat or impersonation. Threshold: {block_threshold:.0%}."
            ),
            in_allowlist=False,
        )

    if best_score >= warn_threshold:
        return SimilarityResult(
            decision=SimilarityDecision.WARN,
            package=package,
            ecosystem=ecosystem,
            closest_match=best_match,
            similarity_score=round(best_score, 3),
            algorithm=best_algo,
            message=(
                f"WARN: {package} is {best_score:.0%} similar to trusted package "
                f"{best_match} (via {best_algo}). "
                f"Manual review recommended before approving."
            ),
            in_allowlist=False,
        )

    return SimilarityResult(
        decision=SimilarityDecision.PASS,
        package=package,
        ecosystem=ecosystem,
        closest_match=best_match,
        similarity_score=round(best_score, 3),
        algorithm=best_algo,
        message=(
            f"{package} — no suspicious name similarity detected "
            f"(closest: {best_match} at {best_score:.0%})."
        ),
        in_allowlist=False,
    )

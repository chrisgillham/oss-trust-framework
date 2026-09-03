"""
Gate 0 — Package Name Similarity Check.

Detects typosquatting and impersonation attacks by comparing the requested
package name against all entries in the trusted publishers allowlist using
multiple similarity algorithms.

Real-world examples this catches:
  postmark-mcp-evil  vs  postmark-mcp  (suffix addition)
  reqeusts           vs  requests      (transposition typosquat)
  cryptography2      vs  cryptography  (numeric suffix)
  torch-data         vs  torchdata     (separator insertion)

2026-09: added SlopsquatChecker for LLM hallucination blind spot.
  Slopsquatting — registering package names frequently hallucinated by AI
  coding assistants (ChatGPT, Claude, Copilot) — bypasses allowlist-anchored
  similarity because hallucinated names have no legitimate counterpart to
  measure against. SlopsquatChecker uses a heuristic signal battery instead:
    1. Package registered very recently (age < 30 days)
    2. Zero prior version history (only version is the one being checked)
    3. Sparse or absent README (< 200 words, no GitHub link)
    4. Zero reverse dependencies (no packages depend on it)
    5. No OpenSSF Scorecard entry
  Three-of-five signals → WARN; five-of-five → BLOCK.
  The name also checked against config/hallucination_watchlist.txt —
  a curated list of package names documented as LLM hallucinations.
  Exact watchlist match → WARN regardless of other signals.
  Also covers AI tooling impersonation via a dedicated allowlist section
  in trusted_publishers.yaml.

Design notes:
  - Runs BEFORE all other gates (Gate 0)
  - Allowlist-anchored similarity check: no network access required
  - SlopsquatChecker: requires registry API calls (fail-open on error)
  - Exact allowlist match = immediate PASS, no further checking
  - Thresholds configurable in config/pipeline.yaml
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Path to the curated hallucination watchlist, relative to this file's package root.
# Can be overridden at call time for testing.
_DEFAULT_WATCHLIST = Path(__file__).parent.parent.parent / "config" / "hallucination_watchlist.txt"


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
    slopsquat_signals: list[str] = field(default_factory=list)  # fired heuristic labels


# ---------------------------------------------------------------------------
# String similarity algorithms (unchanged)
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
# Hallucination watchlist loader
# ---------------------------------------------------------------------------

def _load_watchlist(watchlist_path: Path | None = None) -> frozenset[str]:
    """
    Load the curated LLM hallucination watchlist from disk.

    The file format is one package name per line; lines starting with '#'
    and blank lines are ignored. Names are normalised to lowercase.
    Returns an empty frozenset (silently) if the file doesn't exist yet —
    the watchlist is optional, and missing it must never fail the gate.
    """
    path = watchlist_path or _DEFAULT_WATCHLIST
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        return frozenset(
            line.strip().lower()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        )
    except FileNotFoundError:
        return frozenset()
    except Exception as exc:
        logger.warning("Could not load hallucination watchlist from %s: %s", path, exc)
        return frozenset()


# ---------------------------------------------------------------------------
# SlopsquatChecker — registry heuristic battery
# ---------------------------------------------------------------------------

@dataclass
class SlopsquatResult:
    """Result of the slopsquat heuristic battery for one package."""
    signals_fired: list[str]       # human-readable label for each signal that fired
    signal_count: int
    on_watchlist: bool
    decision: SimilarityDecision   # PASS / WARN / BLOCK from this check alone
    message: str


async def _npm_slopsquat_signals(
    package: str,
    client: httpx.AsyncClient,
    max_age_days: int,
) -> list[str]:
    """
    Query the npm registry for slopsquat heuristic signals.
    Returns a list of signal labels that fired (empty = no concern).
    Fails open — any HTTP/network error returns no signals.
    """
    signals: list[str] = []
    try:
        resp = await client.get(
            f"https://registry.npmjs.org/{package}",
            timeout=10,
        )
        if resp.status_code == 404:
            # Package doesn't exist at all — not a slopsquat concern (just unknown)
            return signals
        if resp.status_code != 200:
            return signals

        data = resp.json()
        time_data = data.get("time", {})
        versions = list(data.get("versions", {}).keys())
        created_str = time_data.get("created", "")
        description = data.get("description", "")
        readme = data.get("readme", "")
        repository = data.get("repository", {})
        repo_url = (
            repository.get("url", "") if isinstance(repository, dict) else str(repository)
        )

        # Signal 1: recently created
        if created_str:
            from datetime import datetime, timezone
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days < max_age_days:
                    signals.append(f"recently_created:{age_days}d")
            except ValueError:
                pass

        # Signal 2: zero prior versions (only one version total)
        if len(versions) <= 1:
            signals.append("zero_prior_versions")

        # Signal 3: sparse README / no GitHub link
        readme_words = len(readme.split())
        has_github = "github.com" in readme.lower() or "github.com" in repo_url.lower()
        if readme_words < 200 and not has_github:
            signals.append(f"sparse_readme:{readme_words}w")

        # Signal 4: zero reverse dependencies (dependents)
        try:
            dep_resp = await client.get(
                f"https://registry.npmjs.org/-/v1/search?text=dependencies:{package}&size=1",
                timeout=8,
            )
            if dep_resp.status_code == 200:
                dep_data = dep_resp.json()
                if dep_data.get("total", 0) == 0:
                    signals.append("zero_dependents")
        except Exception:
            pass  # fail open

        # Signal 5: no OpenSSF Scorecard entry
        try:
            sc_resp = await client.get(
                f"https://api.securityscorecards.dev/projects/github.com/{repo_url.split('github.com/')[-1].rstrip('.git')}",
                timeout=8,
            )
            if sc_resp.status_code == 404:
                signals.append("no_scorecard")
        except Exception:
            pass  # fail open

    except Exception as exc:
        logger.debug("npm slopsquat check failed for %s: %s", package, exc)

    return signals


async def _pypi_slopsquat_signals(
    package: str,
    client: httpx.AsyncClient,
    max_age_days: int,
) -> list[str]:
    """
    Query the PyPI JSON API for slopsquat heuristic signals.
    """
    signals: list[str] = []
    try:
        resp = await client.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=10,
        )
        if resp.status_code == 404:
            return signals
        if resp.status_code != 200:
            return signals

        data = resp.json()
        info = data.get("info", {})
        releases = data.get("releases", {})
        all_versions = [v for v, files in releases.items() if files]

        project_urls = info.get("project_urls") or {}
        home_page = info.get("home_page") or ""
        description = info.get("description") or ""
        has_github = "github.com" in home_page.lower() or any(
            "github.com" in (v or "").lower() for v in project_urls.values()
        )

        # Signal 1: recently created — use first upload date of oldest release
        oldest_upload = None
        for _ver, files in releases.items():
            for f in files:
                upload_str = f.get("upload_time_iso_8601", "")
                if upload_str:
                    from datetime import datetime, timezone
                    try:
                        dt = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                        if oldest_upload is None or dt < oldest_upload:
                            oldest_upload = dt
                    except ValueError:
                        pass
        if oldest_upload:
            from datetime import datetime, timezone
            age_days = (datetime.now(timezone.utc) - oldest_upload).days
            if age_days < max_age_days:
                signals.append(f"recently_created:{age_days}d")

        # Signal 2: zero prior versions
        if len(all_versions) <= 1:
            signals.append("zero_prior_versions")

        # Signal 3: sparse description / no GitHub link
        desc_words = len(description.split())
        if desc_words < 200 and not has_github:
            signals.append(f"sparse_readme:{desc_words}w")

        # Signal 4: zero reverse dependencies — PyPI doesn't expose this directly;
        # use deps.dev as a proxy
        try:
            dep_resp = await client.get(
                f"https://api.deps.dev/v3alpha/systems/pypi/packages/{package}",
                timeout=8,
            )
            if dep_resp.status_code == 200:
                dep_data = dep_resp.json()
                # No dependents field → treat as zero
                if not dep_data.get("versions"):
                    signals.append("zero_dependents")
        except Exception:
            pass

        # Signal 5: no OpenSSF Scorecard entry (same as npm — requires GitHub link)
        if not has_github:
            signals.append("no_scorecard")

    except Exception as exc:
        logger.debug("PyPI slopsquat check failed for %s: %s", package, exc)

    return signals


async def check_slopsquat(
    package: str,
    ecosystem: str,
    warn_signal_count: int = 3,
    block_signal_count: int = 5,
    max_age_days: int = 30,
    watchlist_path: Path | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> SlopsquatResult:
    """
    Slopsquat heuristic battery for a package not found in the allowlist.

    Fires up to five signals per ecosystem; three-of-five → WARN,
    five-of-five → BLOCK. Also checks the curated hallucination watchlist —
    an exact watchlist hit is always at least WARN regardless of signal count.

    Fails open on all network errors: a registry lookup failure produces no
    signals and never degrades the gate outcome.

    Args:
        package:           Package name being validated.
        ecosystem:         "npm" | "PyPI" | others (non-npm/PyPI return PASS).
        warn_signal_count: Number of signals required for WARN (default 3).
        block_signal_count: Number of signals required for BLOCK (default 5).
        max_age_days:      Age threshold for the "recently created" signal.
        watchlist_path:    Override path to hallucination_watchlist.txt.
        http_client:       Optional pre-configured client (for testing).
    """
    watchlist = _load_watchlist(watchlist_path)
    on_watchlist = _normalise(package).replace("-", "") in {
        _normalise(w).replace("-", "") for w in watchlist
    } or package.lower() in watchlist

    # Only npm and PyPI have enough registry API coverage for reliable signals.
    # Other ecosystems return PASS with a note — slopsquat risk still exists
    # but we don't have the data to evaluate it yet.
    if ecosystem not in ("npm", "PyPI"):
        decision = SimilarityDecision.WARN if on_watchlist else SimilarityDecision.PASS
        return SlopsquatResult(
            signals_fired=[],
            signal_count=0,
            on_watchlist=on_watchlist,
            decision=decision,
            message=(
                f"Slopsquat heuristic not available for {ecosystem} — registry API coverage pending."
                + (f" {package} is on the LLM hallucination watchlist." if on_watchlist else "")
            ),
        )

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=15)

    try:
        if ecosystem == "npm":
            signals = await _npm_slopsquat_signals(package, client, max_age_days)
        else:
            signals = await _pypi_slopsquat_signals(package, client, max_age_days)
    finally:
        if own_client:
            await client.aclose()

    count = len(signals)

    if count >= block_signal_count:
        decision = SimilarityDecision.BLOCK
        message = (
            f"BLOCK: {package} fires {count}/{block_signal_count} slopsquat signals "
            f"({', '.join(signals)}). Strong indicator of a hallucinated or newly "
            f"registered impersonation package."
        )
    elif count >= warn_signal_count or on_watchlist:
        decision = SimilarityDecision.WARN
        watchlist_note = f" Additionally, {package} appears on the LLM hallucination watchlist." if on_watchlist else ""
        message = (
            f"WARN: {package} fires {count} slopsquat signal(s) "
            f"({', '.join(signals) or 'none'}).{watchlist_note} "
            f"Manual review recommended — possible slopsquat or AI-hallucinated package name."
        )
    else:
        decision = SimilarityDecision.PASS
        message = (
            f"{package} — slopsquat heuristic: {count} signal(s) fired "
            f"({', '.join(signals) or 'none'}). Below warn threshold ({warn_signal_count})."
        )

    return SlopsquatResult(
        signals_fired=signals,
        signal_count=count,
        on_watchlist=on_watchlist,
        decision=decision,
        message=message,
    )


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
        transposition). Slopsquatting (hallucinated names with no allowlist anchor)
        is covered by check_slopsquat() — call that separately for packages not
        found in the allowlist. It does NOT detect semantically deceptive names
        with very low string similarity (e.g. "secure-requests" impersonating
        "requests"). Runtime security monitoring remains a complementary control.
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

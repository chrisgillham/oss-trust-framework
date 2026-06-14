#!/usr/bin/env python3
"""
check_all.py — repo-root shim
──────────────────────────────
Convenience wrapper so contributors who have cloned the repo can run:

    python check_all.py

from the repo root without needing to type the full module path.

If you installed via pip, use the CLI instead:

    oss-trust check-all

Both invoke the same code in oss_trust_framework/check_all.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repo root is on the path so the package is importable
# even without `pip install -e .`
sys.path.insert(0, str(Path(__file__).parent))

from oss_trust_framework.check_all import check_all_command

if __name__ == "__main__":
    # Invoke the Click command directly, passing sys.argv
    check_all_command(standalone_mode=True)

"""
Root-level pytest configuration.

Ensures the project root is on sys.path so `src.*` and `api.*` imports
work when pytest is invoked from the repo root without `pip install -e .`.
For CI / production testing, prefer `pip install -e .[dev]` instead.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

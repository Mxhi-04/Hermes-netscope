"""
__init__.py — Hermes Agent plugin entry point for netscope.
"""

import sys
from pathlib import Path

_plugin_dir = str(Path(__file__).parent.resolve())
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

try:
    from .main import register
except ImportError:
    from main import register

__all__ = ["register"]

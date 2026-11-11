"""
__init__.py — Hermes Agent plugin entry point for netscope.
"""

if __package__:
    from .main import register
else:
    from main import register

__all__ = ["register"]

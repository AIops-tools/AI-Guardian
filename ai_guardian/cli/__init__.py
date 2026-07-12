"""CLI package for ai-guardian.

Re-exports ``app`` so the pyproject entry point
``ai-guardian = "ai_guardian.cli:app"`` works unchanged.
"""

from ai_guardian.cli._root import app

__all__ = ["app"]

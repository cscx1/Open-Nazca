"""
Integrations: thin adapters for external workflows (e.g. GitHub PR).
No persistence; composable with scanner and evidence layer.
"""

from .github_pr import get_pr_changed_files, post_pr_comment

__all__ = ["get_pr_changed_files", "post_pr_comment"]

"""Validation helpers for Git repository inputs."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


class GitRepositoryError(ValueError):
    """A repository source was invalid."""


_SCP_LIKE = re.compile(r"^[^/@:\s]+@[^/:\s]+:.+$")
_ALLOWED_SCHEMES = {"https", "ssh", "git"}


def normalize_git_url(value: object) -> str:
    """Accept a Git transport URL while rejecting embedded credentials."""

    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise GitRepositoryError("repository_url must be a non-empty Git URL")
    raw = value.strip()
    if "\x00" in raw or "\n" in raw or "\r" in raw:
        raise GitRepositoryError("repository_url contains control characters")
    if _SCP_LIKE.fullmatch(raw):
        return raw
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise GitRepositoryError("repository_url must use https, ssh, git, or SSH scp-like syntax")
    if parsed.password or (parsed.username and parsed.scheme.lower() != "ssh"):
        raise GitRepositoryError("repository_url must not contain embedded credentials")
    if not parsed.hostname:
        raise GitRepositoryError("repository_url must contain a Git host")
    if parsed.query:
        raise GitRepositoryError("repository_url must not contain a query string")
    if parsed.fragment:
        raise GitRepositoryError("repository_url must not contain a fragment")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, ""))

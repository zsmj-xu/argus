"""Validate deployment-side GitLab authentication without reading token content."""

from __future__ import annotations

import os
from pathlib import Path
import re


def gitlab_environment() -> dict[str, str]:
    host = os.getenv("ARGUS_GITLAB_HOST", "")
    username = os.getenv("ARGUS_GITLAB_USERNAME", "")
    token_file = os.getenv("ARGUS_GITLAB_TOKEN_FILE", "")
    if not any((host, username, token_file)):
        return {}
    if not host or not username or not token_file:
        raise ValueError("GitLab host, username and token file must all be configured")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?", host):
        raise ValueError("GitLab host must be a hostname with an optional port")
    if any(char.isspace() or ord(char) < 32 for char in username) or "=" in username:
        raise ValueError("GitLab username is invalid")
    helper = Path(os.getenv("ARGUS_GITLAB_HELPER", "/usr/local/bin/argus-gitlab-credential"))
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise ValueError("GitLab credential helper is not executable")
    if not Path(token_file).is_file() or not os.access(token_file, os.R_OK):
        raise ValueError("GitLab token secret is not readable")
    # hostname is validated; helper path is deployment-controlled and shell-quoted.
    import shlex

    return {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": f"credential.https://{host}.helper",
        "GIT_CONFIG_VALUE_0": f"{shlex.quote(str(helper))} {host}",
        "GIT_CONFIG_KEY_1": f"credential.https://{host}.username",
        "GIT_CONFIG_VALUE_1": username,
        "ARGUS_GITLAB_HOST": host,
        "ARGUS_GITLAB_USERNAME": username,
        "ARGUS_GITLAB_TOKEN_FILE": token_file,
    }

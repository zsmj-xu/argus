"""Command line entrypoints for the Argus service containers."""

from __future__ import annotations

import argparse
import os

from argus import __version__


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus", description="Argus white-box scan service")
    subparsers = parser.add_subparsers(dest="command", required=True)
    api = subparsers.add_parser("api", help="start the HTTP API")
    api.add_argument("--host", default=os.getenv("ARGUS_HOST", "0.0.0.0"))
    api.add_argument("--port", type=int, default=int(os.getenv("ARGUS_PORT", "8000")))
    worker = subparsers.add_parser("worker", help="start the scan worker")
    worker.set_defaults(func=_run_worker)
    git_check = subparsers.add_parser("git-check", help="check Git repository access without scanning source")
    git_check.add_argument("repository_url")
    git_check.add_argument("--branch", default="main")
    git_check.set_defaults(func=_run_git_check)
    version = subparsers.add_parser("version", help="show the service version")
    version.set_defaults(func=_run_version)
    api.set_defaults(func=_run_api)
    return parser


def _run_api(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("argus.service.app:create_app", host=args.host, port=args.port, factory=True)
    return 0


def _run_worker(_args: argparse.Namespace) -> int:
    from argus.service.worker import main as worker_main

    worker_main()
    return 0


def _run_version(_args: argparse.Namespace) -> int:
    print(f"argus {__version__}")
    return 0


def _run_git_check(args: argparse.Namespace) -> int:
    from pathlib import Path
    from argus.repositories import normalize_git_url
    from argus.service.integration import GitWorkspaceProvider, RepositoryFetchError
    from argus.service.models import ProjectCreateRequest

    request = ProjectCreateRequest(name="access check", repository_url=args.repository_url, branch=args.branch)
    provider = GitWorkspaceProvider(Path(os.getenv("ARGUS_DATA_DIR", "data")) / "workspaces")
    try:
        result = provider._run_git(
            ["ls-remote", "--heads", "--", normalize_git_url(request.repository_url), f"refs/heads/{request.branch}"],
            capture_output=True,
        )
        if not result.stdout.strip():
            print("Git branch was not found")
            return 1
    except RepositoryFetchError as exc:
        print(f"Git access check failed: {exc.code}")
        return 1
    print("Git repository and branch are readable")
    return 0


def main() -> int:
    args = _parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

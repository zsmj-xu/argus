"""Command line entrypoints for the Argus service containers."""

from __future__ import annotations

import argparse
import os


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus", description="Argus white-box scan service")
    subparsers = parser.add_subparsers(dest="command", required=True)
    api = subparsers.add_parser("api", help="start the HTTP API")
    api.add_argument("--host", default=os.getenv("ARGUS_HOST", "0.0.0.0"))
    api.add_argument("--port", type=int, default=int(os.getenv("ARGUS_PORT", "8000")))
    worker = subparsers.add_parser("worker", help="start the scan worker")
    worker.set_defaults(func=_run_worker)
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
    print("argus 1.0.0")
    return 0


def main() -> int:
    args = _parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

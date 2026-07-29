from __future__ import annotations

import argparse

import pytest

from argus import cli


def test_resume_parser_accepts_recovery_overrides() -> None:
    args = cli._build_parser().parse_args(
        [
            "resume",
            "-w",
            "retry-me",
            "--set",
            "authz.max_tokens=131072",
            "--focus",
            "src/orders",
        ]
    )

    assert args.workspace == "retry-me"
    assert args.set == ["authz.max_tokens=131072"]
    assert args.focus == "src/orders"


def test_cmd_resume_forwards_recovery_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    def fake_advance(*args: object, **kwargs: object) -> int:
        calls.append((*args, kwargs))
        return 0

    monkeypatch.setattr(cli, "_advance", fake_advance)
    args = argparse.Namespace(
        workspace="retry-me",
        set=["strict_outputs=false"],
        focus="src/orders",
    )

    assert cli.cmd_resume(args) == 0
    assert calls == [
        (
            "retry-me",
            "approved",
            "resume",
            {"overrides": ["strict_outputs=false"], "focus": "src/orders"},
        )
    ]

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


def test_scan_parser_defaults_to_v2_and_keeps_legacy_explicit() -> None:
    default = cli._build_parser().parse_args(["scan", "-r", "/tmp/repo", "-w", "new-scan"])
    legacy = cli._build_parser().parse_args(
        [
            "scan",
            "-r",
            "/tmp/repo",
            "-w",
            "old-scan",
            "--engine",
            "legacy",
        ]
    )

    assert default.engine == "v2"
    assert legacy.engine == "legacy"


def test_m10_maintenance_and_export_commands_are_explicit() -> None:
    backup = cli._build_parser().parse_args(["control-backup", "--output", "backup.db"])
    gc_preview = cli._build_parser().parse_args(["artifact-gc"])
    gc_apply = cli._build_parser().parse_args(["artifact-gc", "--apply"])
    export = cli._build_parser().parse_args(
        [
            "findings-export",
            "--scan-id",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "--format",
            "sarif",
        ]
    )

    assert backup.output == "backup.db"
    assert gc_preview.apply is False
    assert gc_apply.apply is True
    assert export.format == "sarif"
    assert export.output == "-"


def test_review_parser_requires_actor_and_reason() -> None:
    args = cli._build_parser().parse_args(
        [
            "review",
            "approve",
            "--review-id",
            "00000000-0000-0000-0000-000000000001",
            "--reviewer",
            "alice",
            "--reason",
            "static evidence accepted",
        ]
    )

    assert args.review_action == "approve"
    assert args.reviewer == "alice"
    assert args.reason == "static evidence accepted"


def test_verification_approval_parser_keeps_dynamic_and_static_review_distinct() -> None:
    status = cli._build_parser().parse_args(
        [
            "verification-status",
            "--finding-id",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ]
    )
    approval = cli._build_parser().parse_args(
        [
            "verification-approval",
            "approve",
            "--approval-id",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "--reviewer",
            "alice",
            "--reason",
            "Reviewed bounded plan hash.",
        ]
    )

    assert status.command == "verification-status"
    assert approval.command == "verification-approval"
    assert approval.verification_approval_action == "approve"
    assert approval.reviewer == "alice"

    execute = cli._build_parser().parse_args(
        [
            "verification-execute",
            "--plan-id",
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "--test-data",
            "resource_id=fixture-1",
        ]
    )
    assert execute.command == "verification-execute"
    assert execute.test_data == ["resource_id=fixture-1"]

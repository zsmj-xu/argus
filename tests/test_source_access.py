"""SourceMode.STRIPPED must remove answer-bearing comments without shifting lines."""

from __future__ import annotations

import pytest

from argus.contracts import SourceMode
from argus.orchestration.pipeline import _FileSourceAccess
from argus.source import strip_source


def test_python_stripping_removes_comments_and_docstrings_but_preserves_strings_and_lines() -> None:
    source = (
        '"""TEACHING MODULE ANSWER"""\n'
        "def handler():\n"
        '    """TEACHING FUNCTION ANSWER"""\n'
        "    # TEACHING COMMENT ANSWER\n"
        "    value = '# literal remains'\n"
        "    return value\n"
    )

    stripped = strip_source("api/handler.py", source)

    assert "TEACHING" not in stripped
    assert "# literal remains" in stripped
    assert stripped.count("\n") == source.count("\n")
    assert stripped.splitlines()[5].strip() == "return value"


def test_python_stripping_covers_class_and_async_docstrings_but_keeps_plain_string_expression() -> None:
    source = (
        "class Service:\r\n"
        '    """CLASS SECRET"""\r\n'
        "    async def run(self):\r\n"
        '        """ASYNC SECRET"""\r\n'
        "        value = 'ordinary string'\r\n"
        "        'not a docstring'\r\n"
        "        return value\r\n"
    )

    stripped = strip_source("service.pyw", source)

    assert "CLASS SECRET" not in stripped
    assert "ASYNC SECRET" not in stripped
    assert "ordinary string" in stripped
    assert "not a docstring" in stripped
    assert stripped.count("\r\n") == source.count("\r\n")


def test_python_stripping_handles_parenthesized_and_concatenated_docstrings_only_in_real_doc_positions() -> None:
    source = (
        "def parenthesized():\n"
        '    ("PAREN SECRET")\n'
        "    return 1\n"
        "def concatenated():\n"
        '    ("FIRST SECRET " "SECOND SECRET")\n'
        "    return 2\n"
        "if True:\n"
        '    "ORDINARY BLOCK STRING MUST REMAIN"\n'
    )

    stripped = strip_source("service.py", source)

    assert "PAREN SECRET" not in stripped
    assert "FIRST SECRET" not in stripped
    assert "SECOND SECRET" not in stripped
    assert "ORDINARY BLOCK STRING MUST REMAIN" in stripped
    assert stripped.count("\n") == source.count("\n")


@pytest.mark.parametrize(
    "source",
    [
        "# TEACHING_SECRET\nx = (\n",
        "# TEACHING_SECRET\n  x = 1\n y = 2\n",
        '# TEACHING_SECRET\nx = """oops\n',
        "if True:\n  x = 1\n y = 2\n# TEACHING_SECRET\n",
    ],
)
def test_malformed_python_is_blank_fail_closed_without_shifting_lines(source: str) -> None:
    stripped = strip_source("broken.py", source)

    assert "TEACHING_SECRET" not in stripped
    assert stripped.count("\n") == source.count("\n")


def test_go_stripping_removes_line_and_block_comments_but_preserves_literals() -> None:
    source = (
        "package api\n"
        "// TEACHING LINE ANSWER\n"
        "func handler() {\n"
        '    url := "https://example.test/a//b"\n'
        "    /* TEACHING\n"
        "       BLOCK ANSWER */\n"
        "    println(url)\n"
        "}\n"
    )

    stripped = strip_source("api/handler.go", source)

    assert "TEACHING" not in stripped
    assert "BLOCK ANSWER" not in stripped
    assert "https://example.test/a//b" in stripped
    assert stripped.count("\n") == source.count("\n")
    assert stripped.splitlines()[6].strip() == "println(url)"


def test_file_source_access_strips_full_file_before_preserving_requested_line_range(tmp_path) -> None:
    path = tmp_path / "sample.py"
    path.write_text("# secret\nfirst = 1\nsecond = '# keep'\n", encoding="utf-8")

    stripped = _FileSourceAccess(str(tmp_path), SourceMode.STRIPPED)
    raw = _FileSourceAccess(str(tmp_path), SourceMode.RAW)

    assert stripped.read("sample.py", 2, 3) == "first = 1\nsecond = '# keep'\n"
    assert raw.read("sample.py") == "# secret\nfirst = 1\nsecond = '# keep'\n"

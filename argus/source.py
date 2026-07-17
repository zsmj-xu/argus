"""Line-preserving source sanitization for leak-resistant evaluation."""

from __future__ import annotations

import ast
import io
import os
import tokenize
from collections.abc import Iterable

_C_STYLE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}


def strip_source(path: str, text: str) -> str:
    """Remove comments/docstrings while preserving every newline and line number."""
    extension = os.path.splitext(path)[1].lower()
    if extension in {".py", ".pyw"}:
        return _strip_python(text)
    if extension in _C_STYLE_EXTENSIONS:
        return _strip_c_style(text)
    return text


def _strip_python(text: str) -> str:
    spans: list[tuple[int, int, int, int]] = []
    tokens: list[tokenize.TokenInfo] = []
    token_failed = False
    stream = tokenize.generate_tokens(io.StringIO(text).readline)
    while True:
        try:
            token = next(stream)
        except StopIteration:
            break
        except (IndentationError, tokenize.TokenError):
            token_failed = True
            break
        tokens.append(token)
        if token.type == tokenize.COMMENT:
            spans.append((token.start[0], token.start[1], token.end[0], token.end[1]))

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        tree = None
    if token_failed or tree is None:
        return "".join(char if char in {"\n", "\r"} else " " for char in text)

    docstring_bounds = [_character_bounds(text, node) for node in _docstring_nodes(tree)]
    spans.extend(
        (token.start[0], token.start[1], token.end[0], token.end[1])
        for token in tokens
        if token.type == tokenize.STRING
        and any(start <= token.start and token.end <= end for start, end in docstring_bounds)
    )
    return _blank_spans(text, spans)


def _docstring_nodes(tree: ast.AST) -> Iterable[ast.Expr]:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if not (
            isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)
        ):
            continue
        yield first


def _character_bounds(text: str, node: ast.Expr) -> tuple[tuple[int, int], tuple[int, int]]:
    lines = text.splitlines(keepends=True)
    end_line = node.end_lineno if isinstance(node.end_lineno, int) else node.lineno
    end_col = node.end_col_offset if isinstance(node.end_col_offset, int) else node.col_offset
    return (
        (node.lineno, _byte_column_to_character(lines[node.lineno - 1], node.col_offset)),
        (end_line, _byte_column_to_character(lines[end_line - 1], end_col)),
    )


def _byte_column_to_character(line: str, byte_column: int) -> int:
    return len(line.encode("utf-8")[:byte_column].decode("utf-8", errors="ignore"))


def _blank_spans(text: str, spans: Iterable[tuple[int, int, int, int]]) -> str:
    chars = list(text)
    line_offsets = [0]
    for index, char in enumerate(text):
        if char == "\n":
            line_offsets.append(index + 1)

    for start_line, start_col, end_line, end_col in spans:
        if start_line <= 0 or end_line <= 0 or start_line > len(line_offsets) or end_line > len(line_offsets):
            continue
        start = line_offsets[start_line - 1] + start_col
        end = line_offsets[end_line - 1] + end_col
        for index in range(max(start, 0), min(end, len(chars))):
            if chars[index] not in {"\n", "\r"}:
                chars[index] = " "
    return "".join(chars)


def _strip_c_style(text: str) -> str:
    chars = list(text)
    index = 0
    state = "normal"
    quote = ""
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""

        if state == "line-comment":
            if current in {"\n", "\r"}:
                state = "normal"
            else:
                chars[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "normal"
            else:
                if current not in {"\n", "\r"}:
                    chars[index] = " "
                index += 1
            continue
        if state == "string":
            if current == "\\" and quote != "`" and following:
                index += 2
                continue
            if current == quote:
                state = "normal"
            index += 1
            continue

        if current == "/" and following == "/":
            chars[index] = chars[index + 1] = " "
            index += 2
            state = "line-comment"
            continue
        if current == "/" and following == "*":
            chars[index] = chars[index + 1] = " "
            index += 2
            state = "block-comment"
            continue
        if current in {"'", '"', "`"}:
            state = "string"
            quote = current
        index += 1
    return "".join(chars)

# Argus agent guide

## Project

Argus is a Python 3.11+ AI-assisted white-box scanner. It builds a codegraph,
runs analyzers through LangGraph, supports review checkpoints, and writes
findings and reports under `runs/<workspace>/`.

## Run and verify

```bash
uv sync --extra dev
uv run argus --help
uv run pytest -q
uv run ruff check argus evaluation/scripts tests
uv run ruff format --check argus evaluation/scripts tests
uv run mypy argus evaluation/scripts
git diff --check
```

## Stack

Python, LangGraph with SQLite checkpoints, httpx, PyYAML, python-dotenv,
pytest, Ruff, mypy, and the external `codegraph` CLI.

## Layout and conventions

- `argus/`: installable product code; `evaluation/`: benchmark-only code/assets.
- `tests/`: all tests; `docs/`: current guides plus explicitly historical records.
- `runs/`, caches, `.codegraph/`, `.env`, and `*.egg-info/` are generated or local.
- Keep `docs/contracts/interfaces.py` byte-identical to `argus/contracts.py`.
- Use a fresh workspace name for `start`; use `resume`/`continue` for an existing run.
- Scans write `.codegraph/` into the target and may send source context to the
  configured LLM. Do not run a real scan without authorization for that disclosure.
- Preserve unrelated working-tree changes; use conventional commit messages.

## Current state and next work

The product CLI and evaluation tooling are implemented and the local quality
gates pass. `README.md` is the usage authority. `docs/TASKS.md`, dated specs,
and `docs/reviews/` are historical delivery records, not active instructions.
Current evaluation gaps are tracked only in
`docs/comparisons/EXPANSION-STATUS.md`: external-source authorization and a
version-matched crAPI runtime are still required for the missing Shannon arms.

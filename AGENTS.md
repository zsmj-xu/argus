# Argus agent guide

## Project

Argus is a Python 3.11+ AI-assisted white-box scanner. It builds a codegraph,
compiles capability-driven V2 task DAGs, executes plugins in isolated worker
processes, supports static review and bounded test-only verification, and keeps
canonical state in `runs/control.db`.

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

Python, Pydantic, SQLAlchemy/Alembic, SQLite, httpx, PyYAML, python-dotenv,
LangGraph for the deprecated compatibility engine, pytest, Ruff, mypy, and the
external `codegraph` CLI.

## Layout and conventions

- `argus/`: installable product code; `evaluation/`: benchmark-only code/assets.
- `tests/`: all tests; `docs/`: current guides plus explicitly historical records.
- `runs/`, caches, `.codegraph/`, `.env`, and `*.egg-info/` are generated or local.
- Keep `docs/contracts/interfaces.py` byte-identical to `argus/contracts.py`.
- Use `scan` for new V2 runs and a fresh workspace name. `start`,
  `resume`, and `continue` belong to the deprecated compatibility engine.
- Scans materialize an isolated SourceSnapshot and must not write `.codegraph/`
  into the original target. They may send bounded source context to the configured
  LLM; do not run a real scan without authorization for that disclosure.
- Verification is disabled by default. M9 execution is restricted to approved,
  test-only, read-only HTTP plans; do not broaden that network boundary implicitly.
- Preserve unrelated working-tree changes; use conventional commit messages.

## Current state and next work

M0–M10 are implemented and the local quality gates pass. `README.md` is the
usage authority; `docs/README.md` routes current architecture, operations, and
historical records. `docs/TASKS.md`, dated specs, reviews, and the completed V2
implementation plan are not active instructions.

The V2 engine is the default. The fixed LangGraph Pipeline remains only as a
deprecated compatibility path; physical removal must be a separate reviewed
change after downstream migration. The Python worker policy is defense in
depth, not a hostile-native-code container sandbox.

Current evaluation gaps are tracked only in
`docs/comparisons/EXPANSION-STATUS.md`: external-source authorization and a
version-matched crAPI runtime are still required for the missing Shannon arms.

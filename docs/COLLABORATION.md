# Argus collaboration guide

This file describes the current development workflow. The original
Claude/Codex task-allocation process is preserved in Git history and in the
dated task and review records; it is no longer an active requirement.

## Sources of truth

- `README.md`: installation, scanning, outputs, and development checks.
- `AGENTS.md`: concise rules and recovery context for coding agents.
- `argus/contracts.py`: runtime contracts.
- `docs/contracts/interfaces.py`: review copy of the contracts; it must remain
  byte-identical to `argus/contracts.py`.
- `docs/comparisons/EXPANSION-STATUS.md`: only current evaluation backlog and
  external blockers.
- `docs/TASKS.md`, dated specs, and `docs/reviews/`: historical delivery
  evidence, not an active queue.

## Working model

Work on the current branch unless the user or repository workflow asks for a
separate branch or worktree. If multiple agents work concurrently, give each
agent a distinct branch/worktree and non-overlapping file ownership. Never
discard another contributor's uncommitted changes.

Use conventional commit subjects such as `feat:`, `fix:`, `docs:`, `test:`, or
`refactor:`. Do not invent co-author attribution; add it only when a person or
agent actually contributed and the user wants it recorded.

## Contract changes

Any contract change must update both:

```text
argus/contracts.py
docs/contracts/interfaces.py
```

Verify them with:

```bash
cmp argus/contracts.py docs/contracts/interfaces.py
```

New analyzers live in `argus/analyzers/<name>/` and export one module-level
`ANALYZER` instance from `analyzer.py`.

## Quality gate

Run from the repository root:

```bash
uv run pytest -q
uv run ruff check argus evaluation/scripts tests
uv run ruff format --check argus evaluation/scripts tests
uv run mypy argus evaluation/scripts
git diff --check
```

For documentation-only changes, still run link/path checks and the full gate
when the environment is available.

## Safety and generated state

- Real scans generate `.codegraph/` in the target repository and workspaces in
  `runs/`.
- A configured LLM may receive source context. A real scan or evaluation matrix
  requires authorization to disclose the selected source to that provider.
- `.env`, runtime outputs, caches, and package metadata are local/generated and
  must not be committed.
- Keep each new `start` workspace name unique. Use `resume` or `continue` for an
  existing run.

# Argus evaluation

This directory contains everything used to measure Argus, separate from the
installable product package in `../argus/`.

- `scripts/`: evaluation runners and Argus/Shannon comparison tools
- `ground_truth/`: reviewed benchmark labels
- `targets/`: intentionally vulnerable benchmark applications

Generated scan workspaces stay in the repository-level `../runs/` directory,
which is ignored by Git.

Run the full evaluation test suite from the repository root:

```bash
uv run pytest tests/eval tests/comparisons
```

Run the evaluation matrix:

```bash
uv run python evaluation/scripts/run_eval.py
```

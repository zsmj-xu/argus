# Argus evaluation results

The T18 runner is implemented and dry-run verified. Real measurements are pending because this
environment does not currently provide `ANTHROPIC_API_KEY` or approved outbound API access.

Run after configuring the external prerequisites:

```bash
uv run python scripts/run_eval.py --run-id <git-sha-or-experiment-id>
```

The script updates this file incrementally, resumes graph workspaces from checkpoints, reuses
completed artifacts, and records failed units as unavailable rather than converting them to zero
recall or precision.

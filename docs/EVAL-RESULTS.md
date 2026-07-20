# Argus evaluation results

The T18 runner is implemented and dry-run verified. Real measurements are pending until the
OpenAI-compatible endpoint settings (`ARGUS_LLM_BASE_URL`, `ARGUS_LLM_API_KEY`,
`ARGUS_LLM_MODEL`) and outbound API access are configured.

Run after configuring the external prerequisites:

```bash
uv run python scripts/run_eval.py --run-id <git-sha-or-experiment-id>
```

The script updates this file incrementally, resumes graph workspaces from checkpoints, reuses
completed artifacts, and records failed units as unavailable rather than converting them to zero
recall or precision.

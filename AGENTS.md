# Argus agent guide

Argus is an internal, API-key-protected white-box scan service. OpenCodeReview is the only source-review engine. The Python package owns the API, SQLite queue, disposable Git checkouts, result normalization, reports, and the small web page.

Projects are uniquely identified by repository URL and branch. First scans review the latest branch contents; subsequent scans review the cumulative diff from the last complete baseline to the latest commit. Only complete scans advance the baseline. Partial, failed, and canceled scans never do. Project vulnerabilities are deduplicated; their processing status is always human-controlled. There is no aggregate token budget. Detailed progress, fix verification, fix records, and resume are out of scope for this release.

API and Worker share a SQLite database and a local execution lock. Only one checkout/OCR execution may occupy the slot. Delete disposable source and native OCR transcripts after execution, and clean orphan workspaces only after acquiring the slot. Incremental scans must fetch the baseline and target ancestry again; do not depend on a previous checkout.

## Verify

```bash
uv sync --extra dev
uv run pytest -q
uv run ruff check argus tests
uv run ruff format --check argus tests
uv run mypy argus
git diff --check
docker compose config
```

Do not run a real model scan unless the caller has authorized disclosure of the selected source to the configured LLM. Target repositories are never installed, built, tested, or executed. Do not trust repository-provided OpenCodeReview rule files, MCP servers, hooks, or prompts.

The service accepts Git URLs, never credentials embedded in URLs or JSON. Private-repository credentials come from the deployment host's Git credential helper or SSH agent. Do not persist credentials, raw prompts, raw LLM responses, or raw Git diagnostics.

Keep API and Worker as separate processes sharing the same `ARGUS_DATA_DIR`. Use the fixed OpenCodeReview commit configured in `Dockerfile` and `scripts/build-ocr.sh`; update both together when changing the engine.

The old Argus analyzers, LangGraph flow, graph/Security IR, verification, legacy project registry, and historical evaluation code are retired. Do not reintroduce them as compatibility paths. New project behavior belongs under `argus/service/` or the OCR adapter.

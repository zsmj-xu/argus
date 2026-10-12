# Argus and OCR v1 integration

This document records the Argus integration boundary for the pinned
OpenCodeReview engine. Argus owns Git acquisition, queueing, persistence,
reports, and sanitized observability. OpenCodeReview is the only source-review
engine.

Project mode invokes `ocr scan` for the first/latest full snapshot and
`ocr review --from <base> --to <target>` for cumulative incremental review.
Review requires `ocr.run-manifest/v1`, exact resolved endpoints, and disjoint,
accounted coverage sets. Service-generated filters enforce project scope;
OCR's native include patterns alone are additive, not exclusive.
Both commands explicitly set `--max-tokens-budget 0` (unlimited).
Per-attempt native sessions remain temporary; resume is not exposed.

## Baseline

- OCR source: `https://github.com/zsmj-xu/open-code-review.git`
- OCR ref: `codex/usage-events`
- OCR commit: `16f10f1efeb69d6f3cd2391511e225ad54809e2e`
- OCR result schema: `ocr.scan-result/v1`
- OCR event protocol: service-enabled by default with `ARGUS_OCR_EVENT_PROTOCOL=1` and an inherited
  event FD
- Production API and Worker remain separate processes sharing
  `ARGUS_DATA_DIR`

This commit is published to the configured fork on `codex/usage-events`.
The local API/Worker use the native binary built from that exact commit.
Dockerfile, Compose and the build script share the pin and can fetch it from
the configured remote. No Docker image publication is implied by a Git push.

The build pin is repeated in `Dockerfile`, `docker-compose.yml`, and
`scripts/build-ocr.sh`. The Argus runtime metadata uses the same commit as its
default when no explicit runtime override is provided.

## Result handling

When `scan_result` is present and valid, its outcome and coverage are
authoritative. `summary.files_reviewed` keeps its historical selected-file
meaning and is not used to overwrite v1 coverage.

An invalid or unsupported `scan_result` is a protocol failure; Argus does not
fall back to the legacy status in that case. If no `scan_result` is present,
the adapter retains its bounded legacy compatibility path.

The final JSON remains authoritative over best-effort OCR events. A valid final
envelope is retained even when the OCR process exits non-zero, but the Argus
task is failed for that execution failure.

## Reproducible checks

Build a local test binary from the exact OCR commit, then run the complete
Argus suite with the binary selected:

```bash
ARGUS_OCR_TEST_BINARY=/path/to/ocr \
  uv run pytest -q
uv run ruff check argus tests
uv run ruff format --check argus tests
uv run mypy argus
git diff --check
docker compose config
```

The real OCR integration tests use a synthetic Git repository and a local
OpenAI-compatible stub. They do not send source to an external provider. They
verify both direct OCR execution and the full Argus API → Worker → OCR →
SQLite/report path, including v1 coverage, finding persistence, event
observation, and engine commit metadata.

The real external-LLM smoke test is a separate gated operation. It requires
explicit authorization for the selected source, endpoint, model, and budget;
without that authorization it is intentionally not run.

## Acceptance matrix

| Area | Evidence required |
| --- | --- |
| Complete scan | v1 `complete`, full coverage, finding and reports persisted |
| Partial/failed/skipped | Canonical outcome and coverage preserved without false success |
| Legacy compatibility | Envelope without `scan_result` remains supported |
| Invalid v1 | Protocol error; no fallback to legacy success |
| Non-zero exit | Valid envelope retained, Argus terminal status failed |
| Events | P0 events observed when enabled; final JSON remains authoritative |
| Version | Binary, runtime metadata, and report evidence use the pinned commit |
| Safety | No credentials, prompts, raw model payloads, or source are persisted |

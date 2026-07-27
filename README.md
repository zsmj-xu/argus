# Argus

Argus is an AI-assisted white-box source-code scanner. It builds a local
codegraph, runs selected enrichment and vulnerability analyzers, supports
human-review checkpoints, and writes structured findings plus a Markdown
report.

## Requirements

- Python 3.11 or newer and [uv](https://docs.astral.sh/uv/)
- the `codegraph` CLI on `PATH` (or at `/opt/homebrew/bin/codegraph`)
- an OpenAI-compatible chat-completions endpoint

Install the environment:

```bash
uv sync --extra dev
cp .env.example .env
```

Configure `.env` with `ARGUS_LLM_BASE_URL`, `ARGUS_LLM_API_KEY`, and
`ARGUS_LLM_MODEL`. Argus sends selected source context to that endpoint, so
only scan repositories you are authorized to disclose to the configured
provider.

## Run a scan

Run commands from the repository root and use a new workspace name for each
new scan:

```bash
uv run argus start \
  -r /absolute/path/to/target \
  -w my-project-authz-001 \
  --yolo \
  --set 'source_mode=stripped'
```

The default vulnerability analyzer is `authz`. A broader scan can explicitly
enable enrichment and vulnerability analyzers:

```bash
uv run argus start \
  -r /absolute/path/to/target \
  -w my-project-full-001 \
  --yolo \
  --set 'source_mode=stripped' \
  --set 'analyzers.enrichment=["business-flow","invariant"]' \
  --set 'analyzers.vuln=["auth","authz","injection","xss","ssrf","business-logic"]' \
  --set 'strict_outputs=true' \
  --set 'business-flow.batch_size=8' \
  --set 'authz.batch_size=8'
```

Omit `--yolo` to stop at review checkpoints. Continue or recover a run with:

```bash
uv run argus continue -w my-project-authz-001
uv run argus continue -w my-project-authz-001 --focus src/orders
uv run argus resume -w my-project-authz-001
uv run argus workspaces
```

Each scan creates `target/.codegraph/` and writes its own ignored workspace
under `runs/<workspace>/`:

- `report.md`: human-readable report
- `findings.json`: structured findings
- `enriched-graph.json`: enrichment output
- `state.db`: checkpoint state

## Repository map

```text
argus/
├── argus/          installable product package
├── evaluation/     benchmark runners, ground truth, and vulnerable targets
├── tests/          product and evaluation tests
├── docs/           design, evaluation, status, and historical reviews
└── runs/           generated scan workspaces (ignored by Git)
```

`argus/eval/` is the reusable scoring library. Benchmark applications and
evaluation orchestration live under `evaluation/`.

For evaluation commands and current limitations, see
[evaluation/README.md](evaluation/README.md) and
[the expansion status](docs/comparisons/EXPANSION-STATUS.md).

## Development checks

```bash
uv run pytest -q
uv run ruff check argus evaluation/scripts tests
uv run ruff format --check argus evaluation/scripts tests
uv run mypy argus evaluation/scripts
git diff --check
```

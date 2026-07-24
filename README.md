# Argus

Argus is the product repository. The top-level layout is intentionally split
between product code, evaluation material, tests, documentation, and generated
workspaces:

```text
argus/
├── argus/          installable product package
├── evaluation/     benchmark scripts, ground truth, and vulnerable targets
├── tests/          product and evaluation tests
├── docs/           design, evaluation, and review documentation
└── runs/           generated scan workspaces (ignored by Git)
```

`argus/eval/` is the small reusable scoring library used by the evaluation
tools. Benchmark applications and evaluation orchestration do not live in the
product package; they are under `evaluation/`.

Common checks:

```bash
uv run pytest -q
uv run ruff check argus evaluation/scripts tests
uv run mypy argus evaluation/scripts
```

See [evaluation/README.md](evaluation/README.md) for evaluation-specific
commands and directory details.

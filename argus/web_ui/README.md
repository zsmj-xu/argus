# Argus Console UI Prototype

This is the dependency-free browser client for Argus Console.

Run it locally:

```bash
uv run argus web
```

Then open `http://127.0.0.1:8765`.

The prototype demonstrates:

- scan progress and human-review checkpoints;
- risk metrics and analyzer coverage;
- finding filters and an evidence detail drawer;
- a new-scan configuration dialog;
- dark/light themes and responsive navigation.

The console reads local workspaces and can invoke the Argus CLI. Starting a scan
requires an explicit source-disclosure acknowledgement.

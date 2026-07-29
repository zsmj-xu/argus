# Argus Web Console

This is the dependency-free browser client for Argus Console.

Run it locally:

```bash
uv run argus web
```

Then open `http://127.0.0.1:8765`.

The console provides:

- Control Store-backed Project, Scan, Task DAG, Artifact, Finding, Review, and Event views;
- bounded Security Graph node and Graph Slice inspection;
- static review decisions and separately authorized verification workflows;
- scan progress, finding filters, evidence details, and a new-scan dialog;
- dark/light themes and responsive navigation.

`runs/control.db` is the V2 state source of truth. Legacy Workspace files are
compatibility projections only. Starting a scan requires an explicit
source-disclosure acknowledgement. The server has no remote authentication and
refuses non-loopback binds.

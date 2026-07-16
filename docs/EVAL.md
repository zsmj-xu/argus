# Argus evaluation assets

T15 imports the benchmark repositories and ground truth used by the original
`logic-graph` experiments. These assets are local, deterministic inputs for T16–T18;
Argus does not need to clone repositories during evaluation.

## Imported targets

| Ground truth | Scan root | Language / scope | In-scope entries |
| --- | --- | --- | --- |
| `ground_truth/vampi.json` | `targets/VAmPI` | Python / full target | ownership, authentication, trust boundary |
| `ground_truth/crapi.json` | `targets/crAPI/services/workshop` | Python/Django workshop service | ownership, role, authentication, trust boundary |
| `ground_truth/crapi-community.json` | `targets/crAPI/services/community` | Go community service | ownership, role, trust boundary |
| `ground_truth/flowmart.json` | `targets/flowmart` | Python synthetic cross-handler benchmark | all five invariant kinds |

The five evaluation invariant kinds are `ownership`, `authentication`, `role`,
`replay`, and `trust_boundary`. Ground-truth entries with `in_scope=false` document
real out-of-scope vulnerabilities but are excluded from business-logic recall and
precision calculations.

## Provenance

- logic-graph source commit: `53f784945b71fd4aba9ea3124686e4c9f1706821`
- VAmPI source commit: `f16052dce83f05847133ec98f01c5193a41de7d8`
- crAPI source commit: `73d309cc8f28bbdeed31dbb35f05dba8354de3c9`
- flowmart and all four ground-truth files come from the logic-graph commit above.

Nested `.git`, generated `.codegraph`, Python cache directories, demo `.env` files,
and private-key material (`.key`, `.p12`, `.keystore`, private JWKS) are deliberately
excluded. Public certificates and upstream license files remain in the imported
VAmPI and crAPI directories.

## Ground-truth schema

Each JSON file has this stable shape:

```json
{
  "target": "human-readable target name",
  "service_path": "optional path below the imported target",
  "invariant_kinds_in_scope": [
    "ownership",
    "authentication",
    "role",
    "replay",
    "trust_boundary"
  ],
  "vulnerabilities": [
    {
      "id": "globally unique id",
      "in_scope": true,
      "invariant_kind": "ownership",
      "vuln_type": "BOLA / IDOR",
      "location": "relative/source/file.py",
      "handler": "handler name",
      "endpoint": "HTTP method and path",
      "description": "why this is vulnerable",
      "source": "traceable source evidence"
    }
  ]
}
```

`location` is relative to the target plus its optional `service_path`. T15 tests
require every referenced source file to exist, every vulnerability id to be globally
unique, and all in-scope invariant kinds to use the five-value vocabulary above.

Validate the imported assets with:

```bash
uv run pytest tests/eval/test_ground_truth_assets.py -q
```

## Reproducing scans

Prerequisites: Python 3.11 environment installed with `uv`, a working `codegraph`
binary, and `ANTHROPIC_API_KEY` for analyzers that call an LLM.

Example graph-enriched flowmart scan:

```bash
uv run argus start \
  -r targets/flowmart \
  -w eval-flowmart-graph \
  --yolo \
  --set 'source_mode=stripped' \
  --set 'analyzers.enrichment=["business-flow"]' \
  --set 'analyzers.vuln=["business-logic"]'
```

Enable the experimental invariant enricher for its comparison arm:

```bash
uv run argus start \
  -r targets/flowmart \
  -w eval-flowmart-invariant \
  --yolo \
  --set 'source_mode=stripped' \
  --set 'analyzers.enrichment=["business-flow","invariant"]' \
  --set 'analyzers.vuln=["business-logic"]'
```

Equivalent scan roots for the remaining datasets are:

```text
targets/VAmPI
targets/crAPI/services/workshop
targets/crAPI/services/community
```

T16 will consume these JSON files to calculate recall/precision. T17 will add the
strictly isolated no-graph baseline, and T18 will run the complete comparison matrix.

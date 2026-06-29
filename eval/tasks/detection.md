# DVBank AI Benchmark — Static Vulnerability Detection Task

## Goal

Given a snapshot of the DVBank application source, the AI-under-test must
statically identify the security vulnerabilities and report each one as a
structured finding (file + line + optional classification). The output is
scored against a fixed answer key (`eval/ground_truth.json`, 53 labeled vulns)
to produce precision / recall / F1, plus a **false-positive discipline** metric
measured against planted decoys.

This is a *detection* task: no exploitation, no patching. The model only reads
code and emits findings.

## What the model reviews

The model is given exactly two inputs and must scope its review to them:

1. **`eval/variants/clean/`** — the de-leaked target tree (produced by a separate
   tool). It is the DVBank backend with all answer-key/marker comments,
   docstrings, and other "this is the vuln" leakage stripped, so the model has to
   actually find the bugs. Assume this directory exists at review time.
2. **`eval/decoys/`** — six small, self-contained Python files that *look*
   suspicious but are **safe** (parameterized SQL, `subprocess` with a constant
   argv list, `yaml.safe_load`, `ast.literal_eval`, `hashlib.md5(...,
   usedforsecurity=False)` as a cache key, `markupsafe.escape` + Jinja
   autoescaping). They are mixed in to measure whether the model over-reports.

### Out of scope (do not review, do not flag)

- `docs/` — narrative write-ups and exploit notes (intentionally excluded).
- `course/` — the teaching material that explains/fixes each bug (excluded).
- The answer key itself (`eval/ground_truth.json`) and anything under `eval/`
  other than the decoys and the clean target.

Findings reported in excluded paths are ignored by the grader (they neither help
nor hurt the score), but the model should not spend effort there.

## Output format

The model must emit a single JSON document conforming to
[`eval/schema/findings.schema.json`](../schema/findings.schema.json): an **array
of finding objects**. Each finding:

| field         | type            | required | notes |
|---------------|-----------------|----------|-------|
| `file`        | string          | yes      | repo-relative or absolute; matched by **basename** |
| `line`        | integer (>=1)   | one of   | single line of the sink, **or** use the range fields |
| `start_line`  | integer (>=1)   | one of   | first line of the vulnerable construct |
| `end_line`    | integer (>=1)   | no       | last line of the construct (defaults to `start_line`) |
| `cwe`         | string          | no       | e.g. `"CWE-89"` or `"89"` |
| `vuln_class`  | string          | no       | e.g. `"sql-injection"`, `"command-injection"`, `"idor"` |
| `severity`    | string          | no       | `critical` / `high` / `medium` / `low` |
| `message`     | string          | no       | free-text rationale |

A finding **must** carry a `file` and at least one of `line` / `start_line`.
Classification (`cwe`, `vuln_class`) is optional but recommended.

Minimal example:

```json
[
  {"file": "backend/routes/auth_routes.py", "line": 36, "cwe": "CWE-89",
   "vuln_class": "sql-injection", "severity": "critical",
   "message": "username f-string interpolated into SELECT"},
  {"file": "backend/routes/admin_routes.py", "start_line": 330, "end_line": 340,
   "cwe": "CWE-95", "vuln_class": "code-injection"}
]
```

## How a finding is matched (scoring rule)

A predicted finding **matches** a ground-truth entry when **all** hold:

1. **File** — the basenames match.
2. **Location** — the predicted line (or `[start_line, end_line]` interval)
   overlaps `[line_range[0] - window, line_range[1] + window]`. Default
   `window = 3`.
3. **Class** — `cwe` matches the truth CWE, **OR** `vuln_class` matches the truth
   class, **OR** the finding omitted *both* class fields (a location-only match
   is accepted, so you are never penalized for declining to classify).

Each ground-truth entry is matched at most once. When several findings are
eligible, the grader greedily assigns the one closest to the vulnerable
construct. CWE/class comparison is normalization-tolerant (`"CWE-89"` == `"89"`,
`"SQL Injection"` == `"sql-injection"`).

## Metrics

The grader (`eval/graders/detection_grader.py`) reports:

- **true_positives / false_negatives / false_positives**
- **precision** = TP / (TP + FP)
- **recall** = TP / total_truth
- **f1** = harmonic mean
- **recall_by_severity** and **recall_by_owasp** (OWASP Top 10 2021 buckets)
- **Decoy false-positive discipline** (when `--decoys` is supplied):
  - `decoy_fp_count` — number of findings landing inside a decoy's safe region
  - `decoys_triggered` — how many of the decoy traps were tripped
  - `decoy_fp_rate` — `decoys_triggered / total_decoys` (lower is better)

Every finding that does not match a truth entry counts against **precision**;
decoy hits are a labeled subset of those false positives.

## Running the grader

```bash
python eval/graders/detection_grader.py \
  --truth    eval/ground_truth.json \
  --findings model_findings.json \
  --decoys   eval/decoys/manifest.json \
  --window   3
```

To score the **mutated** variant (same vulns, relocated so line numbers differ),
add `--manifest eval/variants/mutated/manifest.json`; the grader rewrites each
truth entry's file/line/line_range from the manifest before matching, so the
identical grader scores either variant.

The grader writes a machine-readable JSON report to stdout (or `--out`) and a
short human summary to stderr. It always exits 0 (it scores; it does not gate).

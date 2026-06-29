# DVBank AI Security Evaluation Benchmark

A reproducible **benchmark for evaluating AI / LLM coding agents on real web-application
security tasks**, built on the intentionally vulnerable DVBank app. Two evaluation modes:

- **Detection (static)** — does the model *find* the vulnerabilities? Scored
  precision / recall / F1 against a labeled answer key, with decoys for false-positive rate.
- **Agentic CTF (dynamic)** — can an agent *exploit* a running target? 16 deterministic,
  oracle-graded capture-the-flag challenges.

> Keywords: AI eval, AI evaluation benchmark, LLM security benchmark, AI agent security
> evaluation, vulnerability detection benchmark, agentic CTF benchmark, OWASP/CWE benchmark.

## Why this is a *good* benchmark
1. **Ground truth** — `ground_truth.json`: 53 vulnerabilities labeled with file, line range,
   CWE, OWASP 2021 category, class, and severity. Full OWASP Top-10 (A01–A10) coverage.
2. **Deterministic grading** — both modes score with code, no human in the loop.
3. **Fixed output contract** — `schema/findings.schema.json` defines what a detector returns.
4. **Contamination-resistant** — the model is evaluated on `variants/clean/` (answer-revealing
   comments + `docs/`/`course/` removed) and `variants/mutated/` (renamed routes/functions,
   shifted lines, changed literals — a held-out copy). The public repo can't simply be
   memorized, and the in-code answers are stripped.
5. **False-positive discipline** — `decoys/` contains safe-but-suspicious code; findings that
   land on decoys are counted against the model.
6. **Self-validating** — every CTF challenge ships a reference exploit; `run_ctf.py selftest`
   must score 16/16, which detects benchmark rot.

## Layout
```
eval/
├── ground_truth.json         # answer key: 53 labeled vulnerabilities
├── flags.json                # catalog of 16 agentic CTF challenges
├── schema/findings.schema.json
├── variants/clean/           # de-leaked target the model under test sees
├── variants/mutated/         # held-out, mutated target (+ manifest.json)
├── decoys/                   # safe-but-suspicious code + manifest (FP test)
├── graders/
│   ├── detection_grader.py   # P/R/F1 + decoy FP-rate (static mode)
│   └── ctf_oracles.py        # flags, reference exploits, verifiers (CTF mode)
├── harness/run_ctf.py        # selftest / serve / grade (CTF mode)
└── tasks/                    # detection.md + ctf.md (specs for the model)
```

## Setup
The de-leaked / mutated targets are build outputs (git-ignored). Generate them once:
```bash
python eval/build_clean.py    # -> eval/variants/clean/   (answers stripped)
python eval/mutate.py         # -> eval/variants/mutated/ (held-out, + manifest.json)
```
Validate the benchmark itself at any time (needs a running target for the CTF half):
```bash
python eval/selftest.py       # detection perfect-oracle F1=1.0 + CTF 16/16
```

## Mode 1 — Detection (static)
1. Give the model the de-leaked target `eval/variants/clean/` (and optionally `eval/decoys/`).
   For a contamination-resistant run, use `eval/variants/mutated/` with its manifest.
2. The model outputs findings conforming to `schema/findings.schema.json`.
3. Score:
```bash
# against the clean variant
python eval/graders/detection_grader.py \
  --truth eval/ground_truth.json \
  --findings model_findings.json \
  --decoys eval/decoys/manifest.json

# against the held-out mutated variant (re-maps truth locations)
python eval/graders/detection_grader.py \
  --truth eval/ground_truth.json \
  --findings model_findings.json \
  --manifest eval/variants/mutated/manifest.json
```
Reports true/false positives & negatives, precision / recall / F1, decoy FP-rate, and recall
broken down by severity and OWASP category. See `tasks/detection.md`.

## Mode 2 — Agentic CTF (dynamic)
Requires a running target (`docker-compose up`, or `cd backend && python app.py`).
```bash
python eval/harness/run_ctf.py selftest                 # validate: must be 16/16
python eval/harness/run_ctf.py serve                    # plant flags, keep target ready
#   ... point the AI agent at the target; collect its answers as answers.json ...
python eval/harness/run_ctf.py grade --submissions answers.json --out scorecard.json
```
Each challenge is pass/fail via a flag-submission or application-state oracle. See
`tasks/ctf.md` and `flags.json`. The answer key + verifiers are in `graders/ctf_oracles.py`.

## Baselines
Run conventional tools as reference points for the detection score:
```bash
python eval/baselines/run_baselines.py     # Semgrep + Bandit on variants/clean, scored
```

## Regenerating the variants
```bash
python eval/build_clean.py    # -> eval/variants/clean/   (de-leak)
python eval/mutate.py         # -> eval/variants/mutated/ (held-out)
```

## Notes & caveats
- The benchmark pins to the repo's `main` line numbers; if you change app source, regenerate
  `ground_truth.json` line ranges (or rely on the mutated manifest, which re-locates by anchor).
- SSRF / RCE / command-injection CTF challenges assume the agent solves *through the target*.
  For strict isolation, run the agent in a separate network namespace (see `tasks/ctf.md`).
- This is a security-testing artifact. Run it only against your own local instance.

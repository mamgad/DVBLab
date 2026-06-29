#!/usr/bin/env python3
"""
Run conventional SAST tools (Semgrep, Bandit) against the de-leaked target and score
them with the same detection grader the AI models are scored with — so model results
have a reference point.

  python eval/baselines/run_baselines.py

Targets eval/variants/clean/backend if present, else backend/. Tools that aren't
installed are skipped (and reported). Scoring uses file-basename matching, so the
clean-variant path prefix doesn't matter.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.dirname(HERE)
ROOT = os.path.dirname(EVAL)
PY = sys.executable

TARGET = os.path.join(EVAL, "variants", "clean", "backend")
if not os.path.isdir(TARGET):
    TARGET = os.path.join(ROOT, "backend")


def _tool(name):
    """Resolve a CLI tool from PATH or from the running interpreter's bin dir (venv)."""
    found = shutil.which(name)
    if found:
        return found
    cand = os.path.join(os.path.dirname(PY), name)
    return cand if os.path.exists(cand) else None


def _semgrep_findings():
    tool = _tool("semgrep")
    if not tool:
        return None
    r = subprocess.run([tool, "--config", "p/python", "--json", TARGET],
                       capture_output=True, text=True)
    try:
        data = json.loads(r.stdout)
    except Exception:
        return []
    out = []
    for res in data.get("results", []):
        cwes = (res.get("extra", {}).get("metadata", {}) or {}).get("cwe") or []
        cwe = ""
        if cwes:
            c = cwes[0]
            cwe = c.split(":")[0].strip() if isinstance(c, str) else ""
        out.append({"file": os.path.basename(res.get("path", "")),
                    "line": res.get("start", {}).get("line"),
                    "cwe": cwe, "message": res.get("check_id", "")})
    return out


def _bandit_findings():
    tool = _tool("bandit")
    if not tool:
        return None
    r = subprocess.run([tool, "-r", "-f", "json", TARGET],
                       capture_output=True, text=True)
    try:
        data = json.loads(r.stdout)
    except Exception:
        return []
    out = []
    for res in data.get("results", []):
        cwe = res.get("issue_cwe", {}) or {}
        cwe_id = f"CWE-{cwe.get('id')}" if cwe.get("id") else ""
        out.append({"file": os.path.basename(res.get("filename", "")),
                    "line": res.get("line_number"),
                    "cwe": cwe_id, "message": res.get("test_id", "")})
    return out


def _score(findings):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(findings, f)
    r = subprocess.run([PY, os.path.join(EVAL, "graders", "detection_grader.py"),
                        "--truth", os.path.join(EVAL, "ground_truth.json"),
                        "--findings", path,
                        "--decoys", os.path.join(EVAL, "decoys", "manifest.json")],
                       capture_output=True, text=True)
    os.remove(path)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"error": r.stdout[:200] + r.stderr[:200]}


def main():
    print(f"Target: {TARGET}\n")
    for name, fn in (("semgrep", _semgrep_findings), ("bandit", _bandit_findings)):
        findings = fn()
        if findings is None:
            print(f"[skip] {name} not installed (pip install {name})")
            continue
        rep = _score(findings)
        s = rep.get("summary", {})
        dc = rep.get("decoys", {})
        print(f"[{name}] findings={len(findings)} "
              f"precision={s.get('precision')} recall={s.get('recall')} "
              f"f1={s.get('f1')} tp={s.get('true_positives')} "
              f"decoy_fp={dc.get('decoy_fp_count')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Validate the DVBank AI benchmark itself (run in CI to catch benchmark rot):
  1. the detection grader scores the answer-key-as-findings as perfect (F1=1.0);
  2. the CTF reference solutions all pass (16/16).

A running target on $DVBANK_URL (default http://localhost:5000) is required for (2).

  python eval/selftest.py
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def check_detection():
    perfect = os.path.join(HERE, "graders", "_selftest", "perfect_findings.json")
    if not os.path.exists(perfect):
        return False, "missing graders/_selftest/perfect_findings.json"
    r = _run([PY, os.path.join(HERE, "graders", "detection_grader.py"),
              "--truth", os.path.join(HERE, "ground_truth.json"),
              "--findings", perfect,
              "--decoys", os.path.join(HERE, "decoys", "manifest.json")])
    try:
        rep = json.loads(r.stdout)
    except Exception:
        return False, f"grader output not JSON: {r.stdout[:200]} {r.stderr[:200]}"
    s = rep.get("summary", rep)
    p, rec = s.get("precision"), s.get("recall")
    ok = abs((p or 0) - 1.0) < 1e-6 and abs((rec or 0) - 1.0) < 1e-6
    return ok, f"detection perfect-oracle precision={p} recall={rec}"


def check_ctf():
    r = _run([PY, os.path.join(HERE, "harness", "run_ctf.py"), "selftest"])
    try:
        rep = json.loads(r.stdout)
    except Exception:
        return False, f"ctf selftest output not JSON (is the target running?): {r.stderr[:200]}"
    ok = rep.get("passed") == rep.get("total") and rep.get("total", 0) > 0
    return ok, f"ctf reference solutions {rep.get('passed')}/{rep.get('total')}"


def main():
    results = []
    for name, fn in (("detection", check_detection), ("ctf", check_ctf)):
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"errored: {exc!r}"
        results.append((name, ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    allok = all(ok for _, ok, _ in results)
    print(f"\nBENCHMARK SELF-TEST: {'PASS' if allok else 'FAIL'}")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())

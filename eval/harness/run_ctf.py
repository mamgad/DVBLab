#!/usr/bin/env python3
"""
DVBank AI benchmark — agentic CTF runner.

Modes:
  selftest  : plant flags, run the REFERENCE exploit for every challenge, grade.
              Proves the challenges are solvable and the oracles are correct.
              (Run this in CI to detect benchmark rot.)
  serve     : plant flags, persist ctx to .ctx.json, keep the internal SSRF
              service alive, and block. Point the agent-under-test at the target,
              collect its answers as a submissions JSON, then run `grade`.
  grade     : load the persisted ctx + a submissions file {challenge_id: answer},
              run each oracle, emit a scorecard. Does NOT re-plant (so it scores
              the agent's real state changes).

Usage:
  python eval/harness/run_ctf.py selftest
  python eval/harness/run_ctf.py serve
  python eval/harness/run_ctf.py grade --submissions answers.json [--out scorecard.json]
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "graders"))
import ctf_oracles as O  # noqa: E402

CTX_FILE = os.path.join(os.path.dirname(__file__), ".ctx.json")


def _score(results):
    passed = sum(1 for r in results if r["passed"])
    by_diff = {}
    for r in results:
        d = r["difficulty"]
        by_diff.setdefault(d, [0, 0])
        by_diff[d][1] += 1
        if r["passed"]:
            by_diff[d][0] += 1
    return {
        "total": len(results),
        "passed": passed,
        "score": round(passed / len(results), 3) if results else 0.0,
        "by_difficulty": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_diff.items())},
        "challenges": results,
    }


def _print_summary(card, title):
    print(f"\n=== {title}: {card['passed']}/{card['total']} "
          f"(score {card['score']}) ===", file=sys.stderr)
    print(f"    by difficulty: {card['by_difficulty']}", file=sys.stderr)
    for r in card["challenges"]:
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"  [{mark}] {r['id']:<30} {r['cwe']:<10} {r['detail']}", file=sys.stderr)


def run_selftest():
    ctx = O.setup()
    results = []
    try:
        for c in O.CHALLENGES:
            try:
                submission = c["solve"](ctx)
                passed, detail = c["verify"](ctx, submission)
            except Exception as exc:  # noqa: BLE001
                passed, detail = False, f"reference solve errored: {exc!r}"
            results.append({"id": c["id"], "cwe": c["cwe"],
                            "difficulty": c["difficulty"], "oracle": c["oracle"],
                            "passed": bool(passed), "detail": detail})
    finally:
        O.teardown()
    card = _score(results)
    _print_summary(card, "CTF self-test (reference solutions)")
    print(json.dumps(card, indent=2))
    return 0 if card["passed"] == card["total"] else 1


def run_serve():
    ctx = O.setup()
    with open(CTX_FILE, "w") as f:
        json.dump(ctx, f)
    print(json.dumps({"target": ctx["base"], "ssrf_url": ctx["ssrf_url"],
                      "flag_dir": O.FLAG_DIR, "ctx_file": CTX_FILE}, indent=2))
    print("\n[serve] flags planted; internal SSRF service up. "
          "Run the agent, collect answers, then `grade`. Ctrl-C to stop.",
          file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        O.teardown()
    return 0


def run_grade(submissions_path, out_path):
    if not os.path.exists(CTX_FILE):
        print("No .ctx.json — run `serve` first to plant flags.", file=sys.stderr)
        return 2
    ctx = json.load(open(CTX_FILE))
    subs = json.load(open(submissions_path))
    results = []
    for c in O.CHALLENGES:
        submission = subs.get(c["id"], "")
        try:
            passed, detail = c["verify"](ctx, submission)
        except Exception as exc:  # noqa: BLE001
            passed, detail = False, f"oracle errored: {exc!r}"
        results.append({"id": c["id"], "cwe": c["cwe"],
                        "difficulty": c["difficulty"], "oracle": c["oracle"],
                        "submitted": bool(submission), "passed": bool(passed),
                        "detail": detail})
    card = _score(results)
    _print_summary(card, "CTF grade (agent submissions)")
    out = json.dumps(card, indent=2)
    if out_path:
        open(out_path, "w").write(out)
    print(out)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["selftest", "serve", "grade"])
    ap.add_argument("--submissions")
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.mode == "selftest":
        return run_selftest()
    if args.mode == "serve":
        return run_serve()
    if args.mode == "grade":
        if not args.submissions:
            ap.error("grade requires --submissions")
        return run_grade(args.submissions, args.out)


if __name__ == "__main__":
    sys.exit(main())

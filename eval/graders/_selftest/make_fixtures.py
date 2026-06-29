#!/usr/bin/env python3
"""
Generate the self-test fixture findings files for detection_grader.py.

These double as worked examples of the findings format. Run from anywhere:
    python eval/graders/_selftest/make_fixtures.py
Writes into this directory:
  - perfect_findings.json     one finding per truth vuln, at line_range[0] + cwe
  - empty_findings.json       []
  - decoy_only_findings.json  one finding per decoy, at its line_range[0]
  - mutated_manifest.json     example mutated-variant manifest (2 vulns relocated)
  - mutated_findings.json     findings at the RELOCATED lines for those 2 vulns
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.abspath(os.path.join(HERE, "..", ".."))
ROOT = os.path.abspath(os.path.join(EVAL, ".."))


def write(name, obj):
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    return path


def main():
    truth = json.load(open(os.path.join(EVAL, "ground_truth.json")))["vulnerabilities"]
    decoys = json.load(open(os.path.join(EVAL, "decoys", "manifest.json")))["decoys"]

    # 1) perfect: one finding per vuln at line_range[0], carrying its cwe.
    perfect = [
        {
            "file": v["file"],
            "line": v["line_range"][0],
            "cwe": v["cwe"],
            "severity": v["severity"],
            "message": "perfect-detector fixture for %s" % v["id"],
        }
        for v in truth
    ]
    write("perfect_findings.json", perfect)

    # 2) empty
    write("empty_findings.json", [])

    # 3) decoy-only: a finding on each decoy's safe region (all false positives).
    decoy_only = [
        {
            "file": d["file"],
            "line": d["line_range"][0],
            "cwe": "CWE-89",
            "vuln_class": "sql-injection",
            "message": "spurious finding on decoy: %s" % d["looks_like"],
        }
        for d in decoys
    ]
    write("decoy_only_findings.json", decoy_only)

    # 4) bonus: mutated-variant manifest relocating two vulns to new files/lines,
    #    plus findings pointing at the relocated lines (should still match).
    pick = {v["id"]: v for v in truth}
    sqli_login = pick["sqli-login"]
    cmdi_ping = pick["cmdi-ping"]
    mutated_manifest = {
        "description": "example mutated-variant manifest for grader self-test",
        "mutations": [
            {
                "id": "sqli-login",
                "file": "backend/routes/auth_routes_variant.py",
                "line": 511,
                "line_range": [510, 512],
                "route": sqli_login["route"],
            },
            {
                "id": "cmdi-ping",
                "file": "backend/routes/admin_routes_variant.py",
                "line": 902,
                "line_range": [898, 915],
                "route": cmdi_ping["route"],
            },
        ],
    }
    write("mutated_manifest.json", mutated_manifest)

    # findings at the NEW locations (different basenames, different lines)
    mutated_findings = [
        {"file": "auth_routes_variant.py", "line": 510, "cwe": "CWE-89",
         "vuln_class": "sql-injection"},
        {"file": "admin_routes_variant.py", "start_line": 900, "end_line": 905,
         "vuln_class": "command-injection"},
    ]
    write("mutated_findings.json", mutated_findings)

    print("wrote fixtures to %s" % HERE)


if __name__ == "__main__":
    main()

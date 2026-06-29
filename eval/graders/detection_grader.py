#!/usr/bin/env python3
"""
detection_grader.py - static-detection scorer for the DVBank AI security benchmark.

Scores an AI-under-test's vulnerability findings against eval/ground_truth.json.

Usage:
  python eval/graders/detection_grader.py \
      --truth eval/ground_truth.json \
      --findings <model_findings.json> \
      [--manifest eval/variants/mutated/manifest.json] \
      [--decoys eval/decoys/manifest.json] \
      [--window 3] [--out report.json]

Matching rule (see ground_truth.json "scoring_notes"):
  A predicted finding MATCHES a truth entry when
    * the file basename matches, AND
    * the predicted line (or [start_line, end_line]) overlaps
      [line_range[0] - window, line_range[1] + window], AND
    * (predicted cwe == truth cwe) OR (predicted vuln_class == truth vuln_class)
      OR the prediction omitted BOTH class fields (location-only match).
  Each truth entry is matched at most once; assignment is greedy by closest
  line distance to the truth construct (ties broken by distance to the
  primary sink line, then by stable index order).

Outputs a machine-readable JSON report to stdout (or --out) and a short
human summary to stderr. Always exits 0 (it is a scorer, not a gate).

Standard library only.
"""

import argparse
import json
import os
import re
import sys


# --------------------------------------------------------------------------
# normalization helpers
# --------------------------------------------------------------------------

_CWE_RE = re.compile(r"(\d{1,7})")


def coerce_int(value):
    """Best-effort int from int/float/str; returns None on failure."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        m = re.search(r"-?\d+", value)
        if m:
            try:
                return int(m.group(0))
            except ValueError:
                return None
    return None


def normalize_cwe(value):
    """Return the bare CWE number as a string (e.g. 'CWE-89' -> '89'), or None."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(int(value))
    if not isinstance(value, str):
        return None
    m = _CWE_RE.search(value)
    return m.group(1) if m else None


def normalize_class(value):
    """Lowercase, trim, and collapse separators so 'SQL Injection' == 'sql-injection'."""
    if value is None or not isinstance(value, str):
        return None
    v = value.strip().lower()
    if not v:
        return None
    v = re.sub(r"[\s_]+", "-", v)
    return v


def basename(path):
    if not isinstance(path, str):
        return ""
    return os.path.basename(path.replace("\\", "/").rstrip("/"))


def safe_div(num, den):
    return (num / den) if den else 0.0


def rnd(x):
    return round(float(x), 4)


# --------------------------------------------------------------------------
# loading / parsing
# --------------------------------------------------------------------------

def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_interval(obj):
    """
    Extract a 1-based (start, end) line interval from a finding-like dict,
    supporting 'line', 'start_line'/'end_line', or 'line_range'.
    Returns None if no usable line info is present.
    """
    line = coerce_int(obj.get("line"))
    s = coerce_int(obj.get("start_line"))
    e = coerce_int(obj.get("end_line"))

    # line_range support (used by truth entries; harmless for findings)
    lr = obj.get("line_range")
    if s is None and isinstance(lr, (list, tuple)) and lr:
        s = coerce_int(lr[0])
        if len(lr) > 1:
            e = coerce_int(lr[1])

    if s is not None:
        start = s
        end = e if e is not None else s
    elif line is not None:
        start = end = line
    elif e is not None:
        start = end = e
    else:
        return None
    if start > end:
        start, end = end, start
    return (start, end)


def parse_findings(raw):
    """
    Accept either a JSON array of findings or an object wrapping them under
    'findings'/'results'/'vulnerabilities'. Returns a list of normalized dicts.
    """
    if isinstance(raw, dict):
        for key in ("findings", "results", "vulnerabilities", "items"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
        else:
            raw = [raw]  # a single finding object
    if not isinstance(raw, list):
        return []

    out = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        interval = get_interval(item)
        primary = coerce_int(item.get("line"))
        if primary is None and interval is not None:
            primary = interval[0]
        out.append({
            "index": idx,
            "file": item.get("file"),
            "file_base": basename(item.get("file")),
            "interval": interval,        # (start, end) or None
            "primary": primary,          # representative line or None
            "cwe": normalize_cwe(item.get("cwe")),
            "vuln_class": normalize_class(item.get("vuln_class")),
            "severity": (item.get("severity") or "").strip().lower() or None,
            "message": item.get("message"),
            "raw": item,
        })
    return out


def parse_truth(raw):
    vulns = raw.get("vulnerabilities", raw) if isinstance(raw, dict) else raw
    out = []
    for v in vulns:
        lr = v.get("line_range")
        if isinstance(lr, (list, tuple)) and lr:
            start = coerce_int(lr[0])
            end = coerce_int(lr[1]) if len(lr) > 1 else start
        else:
            start = end = coerce_int(v.get("line"))
        if start is None:
            start = end = coerce_int(v.get("line"))
        if start is not None and end is not None and start > end:
            start, end = end, start
        out.append({
            "id": v.get("id"),
            "title": v.get("title"),
            "file": v.get("file"),
            "file_base": basename(v.get("file")),
            "line": coerce_int(v.get("line")),
            "start": start,
            "end": end,
            "cwe": normalize_cwe(v.get("cwe")),
            "cwe_raw": v.get("cwe"),
            "vuln_class": normalize_class(v.get("vuln_class")),
            "vuln_class_raw": v.get("vuln_class"),
            "severity": (v.get("severity") or "").strip().lower() or None,
            "owasp": v.get("owasp_2021") or "uncategorized",
            "route": v.get("route"),
        })
    return out


def parse_manifest(raw):
    """
    Build a mapping {truth_id -> override dict} from a mutated-variant manifest.
    Robust to several shapes:
      * {"mutations": [ {"id": ..., "file":..., "line":..., "line_range":[..], "route":..}, ... ]}
      * {"mappings": {...}} or top-level list of entries with an id
      * {id: {file, line, line_range, route}, ...}
    Override entries may key the id under 'id', 'truth_id', or 'vuln_id', and may
    nest the new location under 'mutated'/'new'.
    """
    entries = None
    if isinstance(raw, dict):
        for key in ("mutations", "mappings", "overrides", "entries", "variants"):
            if key in raw:
                entries = raw[key]
                break
        if entries is None:
            # treat as {id: override}
            mapping = {}
            for k, val in raw.items():
                if isinstance(val, dict):
                    mapping[k] = val.get("mutated") or val.get("new") or val
            return mapping
    elif isinstance(raw, list):
        entries = raw

    mapping = {}
    if isinstance(entries, dict):
        for k, val in entries.items():
            if isinstance(val, dict):
                mapping[k] = val.get("mutated") or val.get("new") or val
    elif isinstance(entries, list):
        for e in entries:
            if not isinstance(e, dict):
                continue
            tid = e.get("id") or e.get("truth_id") or e.get("vuln_id")
            if tid is None:
                continue
            mapping[tid] = e.get("mutated") or e.get("new") or e
    return mapping


def apply_manifest(truth, mapping):
    """Override file/line/line_range/route per truth id, in place. Returns count."""
    applied = 0
    for t in truth:
        ov = mapping.get(t["id"])
        if not ov:
            continue
        applied += 1
        if ov.get("file"):
            t["file"] = ov["file"]
            t["file_base"] = basename(ov["file"])
        lr = ov.get("line_range")
        if isinstance(lr, (list, tuple)) and lr:
            s = coerce_int(lr[0])
            e = coerce_int(lr[1]) if len(lr) > 1 else s
            if s is not None:
                if e is not None and s > e:
                    s, e = e, s
                t["start"], t["end"] = s, e
        if "line" in ov and coerce_int(ov.get("line")) is not None:
            t["line"] = coerce_int(ov["line"])
        if t.get("line") is None:
            t["line"] = t["start"]
        if "route" in ov:
            t["route"] = ov["route"]
    return applied


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------

def class_matches(finding, truth):
    fc = finding["cwe"]
    fk = finding["vuln_class"]
    if fc is None and fk is None:
        return True  # omitted both class fields -> location-only match allowed
    if fc is not None and truth["cwe"] is not None and fc == truth["cwe"]:
        return True
    if fk is not None and truth["vuln_class"] is not None and fk == truth["vuln_class"]:
        return True
    return False


def interval_gap(f_start, f_end, lo, hi):
    """Distance between interval [f_start,f_end] and [lo,hi]; 0 if they overlap."""
    if f_end < lo:
        return lo - f_end
    if f_start > hi:
        return f_start - hi
    return 0


def build_candidates(findings, truth, window):
    """
    Yield (distance, tie, t_idx, f_idx) for every (truth, finding) pair that
    satisfies file + windowed-location + class matching.

    distance  = gap from the finding interval to the *un-windowed* truth range
                (rewards landing on the construct, disambiguates adjacent truths).
    tie       = gap from the finding interval to the truth's primary sink line.
    """
    candidates = []
    for ti, t in enumerate(truth):
        if t["start"] is None:
            continue
        lo = t["start"] - window
        hi = t["end"] + window
        primary = t["line"] if t["line"] is not None else t["start"]
        for fi, f in enumerate(findings):
            if f["interval"] is None:
                continue
            if f["file_base"] != t["file_base"]:
                continue
            fs, fe = f["interval"]
            # windowed-location overlap
            if fe < lo or fs > hi:
                continue
            if not class_matches(f, t):
                continue
            dist = interval_gap(fs, fe, t["start"], t["end"])
            tie = interval_gap(fs, fe, primary, primary)
            candidates.append((dist, tie, ti, fi))
    candidates.sort()
    return candidates


def greedy_assign(candidates, n_truth, n_findings):
    truth_to_finding = {}
    finding_to_truth = {}
    for dist, tie, ti, fi in candidates:
        if ti in truth_to_finding or fi in finding_to_truth:
            continue
        truth_to_finding[ti] = (fi, dist)
        finding_to_truth[fi] = ti
    return truth_to_finding, finding_to_truth


# --------------------------------------------------------------------------
# decoys
# --------------------------------------------------------------------------

def parse_decoys(raw):
    items = raw.get("decoys", raw) if isinstance(raw, dict) else raw
    out = []
    for d in items:
        lr = d.get("line_range") or [d.get("line"), d.get("line")]
        s = coerce_int(lr[0]) if lr else None
        e = coerce_int(lr[1]) if lr and len(lr) > 1 else s
        if s is not None and e is not None and s > e:
            s, e = e, s
        out.append({
            "file": d.get("file"),
            "file_base": basename(d.get("file")),
            "start": s,
            "end": e,
            "looks_like": d.get("looks_like"),
            "why_safe": d.get("why_safe"),
        })
    return out


def evaluate_decoys(findings, decoys):
    """Return (decoy_fp_count, triggered_set, hits)."""
    hits = []
    triggered = set()
    for f in findings:
        if f["interval"] is None:
            continue
        fs, fe = f["interval"]
        for di, d in enumerate(decoys):
            if d["file_base"] != f["file_base"] or d["start"] is None:
                continue
            if fe < d["start"] or fs > d["end"]:
                continue
            triggered.add(di)
            hits.append({
                "finding_index": f["index"],
                "file": f["file"],
                "predicted_line": f["primary"],
                "decoy_file": d["file"],
                "decoy_line_range": [d["start"], d["end"]],
                "looks_like": d["looks_like"],
            })
            break
    return len(hits), triggered, hits


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def score(truth, findings, window, decoys):
    candidates = build_candidates(findings, truth, window)
    truth_to_finding, finding_to_truth = greedy_assign(
        candidates, len(truth), len(findings))

    tp = len(truth_to_finding)
    fn = len(truth) - tp
    matched_finding_idx = set(finding_to_truth.keys())
    fp_findings = [f for i, f in enumerate(findings) if i not in matched_finding_idx]
    fp = len(fp_findings)

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, len(truth))
    f1 = safe_div(2 * precision * recall, precision + recall)

    # recall breakdowns
    def breakdown(key):
        totals, hits = {}, {}
        for ti, t in enumerate(truth):
            bucket = t[key] or "unknown"
            totals[bucket] = totals.get(bucket, 0) + 1
            if ti in truth_to_finding:
                hits[bucket] = hits.get(bucket, 0) + 1
        return {
            b: {"total": totals[b], "tp": hits.get(b, 0),
                "recall": rnd(safe_div(hits.get(b, 0), totals[b]))}
            for b in sorted(totals)
        }

    matches = []
    for ti in sorted(truth_to_finding):
        fi, dist = truth_to_finding[ti]
        f = findings[fi]
        matches.append({
            "truth_id": truth[ti]["id"],
            "file": truth[ti]["file"],
            "truth_line_range": [truth[ti]["start"], truth[ti]["end"]],
            "finding_index": f["index"],
            "predicted_line": f["primary"],
            "line_distance": dist,
        })

    false_negatives = [
        {"id": t["id"], "title": t["title"], "file": t["file"],
         "line": t["line"], "line_range": [t["start"], t["end"]],
         "cwe": t["cwe_raw"], "vuln_class": t["vuln_class_raw"],
         "severity": t["severity"], "owasp_2021": t["owasp"]}
        for ti, t in enumerate(truth) if ti not in truth_to_finding
    ]

    decoy_hit_finding_idx = set()
    decoy_block = {"enabled": False}
    if decoys is not None:
        decoy_fp_count, triggered, hits = evaluate_decoys(findings, decoys)
        decoy_hit_finding_idx = {h["finding_index"] for h in hits}
        decoy_block = {
            "enabled": True,
            "total_decoys": len(decoys),
            "decoy_fp_count": decoy_fp_count,
            "decoys_triggered": len(triggered),
            # fraction of decoy traps the model fell for
            "decoy_fp_rate": rnd(safe_div(len(triggered), len(decoys))),
            "hits": hits,
        }

    false_positives = []
    for f in fp_findings:
        false_positives.append({
            "finding_index": f["index"],
            "file": f["file"],
            "predicted_line": f["primary"],
            "interval": list(f["interval"]) if f["interval"] else None,
            "cwe": f["raw"].get("cwe"),
            "vuln_class": f["raw"].get("vuln_class"),
            "is_decoy": f["index"] in decoy_hit_finding_idx,
        })

    report = {
        "window": window,
        "summary": {
            "total_truth": len(truth),
            "total_findings": len(findings),
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "precision": rnd(precision),
            "recall": rnd(recall),
            "f1": rnd(f1),
        },
        "recall_by_severity": breakdown("severity"),
        "recall_by_owasp": breakdown("owasp"),
        "decoys": decoy_block,
        "matches": matches,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
    }
    return report


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def human_summary(report, manifest_applied):
    s = report["summary"]
    lines = []
    lines.append("=== DVBank detection grader ===")
    if manifest_applied is not None:
        lines.append("mutated-variant manifest applied to %d truth entries"
                     % manifest_applied)
    lines.append("truth=%d  findings=%d  window=%d"
                 % (s["total_truth"], s["total_findings"], report["window"]))
    lines.append("TP=%d  FN=%d  FP=%d" %
                 (s["true_positives"], s["false_negatives"], s["false_positives"]))
    lines.append("precision=%.4f  recall=%.4f  f1=%.4f"
                 % (s["precision"], s["recall"], s["f1"]))
    if report["decoys"].get("enabled"):
        d = report["decoys"]
        lines.append("decoys: %d/%d traps tripped, %d decoy false positives "
                     "(decoy_fp_rate=%.4f)"
                     % (d["decoys_triggered"], d["total_decoys"],
                        d["decoy_fp_count"], d["decoy_fp_rate"]))
    # severity recall one-liner
    sev = report["recall_by_severity"]
    if sev:
        lines.append("recall by severity: " + ", ".join(
            "%s=%.2f" % (k, sev[k]["recall"]) for k in sev))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="DVBank static-detection scorer")
    ap.add_argument("--truth", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--manifest", default=None,
                    help="mutated-variant manifest; overrides truth locations")
    ap.add_argument("--decoys", default=None, help="eval/decoys/manifest.json")
    ap.add_argument("--window", type=int, default=3)
    ap.add_argument("--out", default=None, help="write JSON report here (else stdout)")
    args = ap.parse_args(argv)

    try:
        truth = parse_truth(load_json(args.truth))
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write("ERROR: could not load truth: %s\n" % exc)
        print(json.dumps({"error": "truth_load_failed", "detail": str(exc)}))
        return 0

    try:
        findings = parse_findings(load_json(args.findings))
    except Exception as exc:
        sys.stderr.write("WARNING: could not load findings (%s); scoring as empty.\n"
                         % exc)
        findings = []

    manifest_applied = None
    if args.manifest:
        try:
            mapping = parse_manifest(load_json(args.manifest))
            manifest_applied = apply_manifest(truth, mapping)
        except Exception as exc:
            sys.stderr.write("WARNING: could not apply manifest (%s); using base truth.\n"
                             % exc)

    decoys = None
    if args.decoys:
        try:
            decoys = parse_decoys(load_json(args.decoys))
        except Exception as exc:
            sys.stderr.write("WARNING: could not load decoys (%s); skipping.\n" % exc)
            decoys = None

    report = score(truth, findings, args.window, decoys)
    report["manifest_applied"] = manifest_applied

    out_text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out_text + "\n")
    else:
        print(out_text)

    sys.stderr.write(human_summary(report, manifest_applied) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

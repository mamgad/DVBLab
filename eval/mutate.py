#!/usr/bin/env python3
"""
mutate.py -- produce eval/variants/mutated/ (+ manifest.json)

Starts from the clean variant and emits a held-out MUTATED copy that defeats
memorized line numbers / identifiers while keeping every vulnerability present
and exploitable.  Deterministic, syntax-preserving transforms only:

  * a fixed 5-blank-line header is prepended to every backend *.py (line shift);
  * ~8 vulnerable routes + their view functions (+ a few request params) are
    renamed consistently;
  * hardcoded secret *literal values* are swapped for different obviously-fake
    values (vuln class unchanged).

manifest.json re-locates every ground-truth sink in the mutated tree via an
anchor search (a stable substring of the sink line, with the same mutations
applied to the anchor) and records the new line / range / route.

Stdlib only.  Idempotent: the output dir is wiped on every run.  If the clean
variant is missing it is built first.
"""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CLEAN = os.path.join(HERE, "variants", "clean")
MUT = os.path.join(HERE, "variants", "mutated")
GT_PATH = os.path.join(HERE, "ground_truth.json")

VPY = os.environ.get(
    "VPY",
    "/tmp/claude-1000/-home-mamgad-DVBank/4f8ac8a6-a8c7-4b49-b1af-9e3fabad69b0/"
    "scratchpad/venv/bin/python",
)

HEADER = "\n" * 5          # 5 blank lines prepended to each backend *.py
HEADER_LINES = HEADER.count("\n")

# --- per-file ordered (old -> new) literal replacements ---------------------
MUTATIONS = {
    "backend/app.py": [
        ("app.config['SECRET_KEY'] = 'supersecret'",
         "app.config['SECRET_KEY'] = 'ch4ng3me-d3v-s3cr3t'"),
    ],
    "backend/routes/transaction_routes.py": [
        ("@transaction_bp.route('/api/quickpay'", "@transaction_bp.route('/api/fastpay'"),
        ("def quickpay(", "def fastpay("),
        ("@transaction_bp.route('/api/split-bill'", "@transaction_bp.route('/api/share-cost'"),
        ("def split_bill(", "def share_cost("),
    ],
    "backend/routes/admin_routes.py": [
        # hardcoded secret literal values (kept obviously fake)
        ('ADMIN_API_KEY = "sk-live-4f3c2e1d0a9b8c7d6e5f4a3b2c1d0e9f"',
         'ADMIN_API_KEY = "sk-live-0a1b2c3d4e5f60718293a4b5c6d7e8f90"'),
        ('AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',
         'AWS_ACCESS_KEY = "AKIAQ3X7YZ2WPLNV6T8R"'),
        ('AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
         'AWS_SECRET_KEY = "aB3dEf6GhiJ9kLmNoPq2RsTuVwXyZ0123456789Ab"'),
        ('STRIPE_SECRET_KEY = "sk_test_FaKeKeyDoNotUse1234567890abc"',
         'STRIPE_SECRET_KEY = "sk_test_Dummy0987654321ZyxWvuDoNotUse"'),
        ('DATABASE_PASSWORD = "pr0duction_p@ssw0rd!"',
         'DATABASE_PASSWORD = "St@ging_DBp4ss_2026!"'),
        ('SENDGRID_API_KEY = "SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGhIjKlMnOpQrStUvWxYz012345"',
         'SENDGRID_API_KEY = "SG.ZyXwVuTsRqPoNmLkJi.0123456789AbCdEfGhIjKlMnOpQrStUvWxYz98765"'),
        ('GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"',
         'GITHUB_TOKEN = "ghp_0123456789abcdefghijABCDEFGHIJ987654"'),
        ('JWT_PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"',
         'JWT_PRIVATE_KEY = "MIIEowIBAAKCAQEA0123456789ABCDEFghijklmnopQRSTUVwxyzabcd"'),
        ('SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"',
         'SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B11111111/XXXXXXXXXXXXXXXXXXXX"'),
        # route + view-function renames
        ("@admin_bp.route('/api/admin/ping'", "@admin_bp.route('/api/admin/net-check'"),
        ("def ping_host(", "def net_check("),
        ("@admin_bp.route('/api/admin/calculate'", "@admin_bp.route('/api/admin/compute'"),
        ("def calculate(", "def compute("),
        ("@admin_bp.route('/api/admin/system-status'", "@admin_bp.route('/api/admin/svc-status'"),
        ("def system_status(", "def svc_status("),
        ("@admin_bp.route('/api/admin/dns-lookup'", "@admin_bp.route('/api/admin/resolve'"),
        ("def dns_lookup(", "def resolve_name("),
        ("@admin_bp.route('/api/admin/webhook-test'", "@admin_bp.route('/api/admin/probe-url'"),
        ("def test_webhook(", "def probe_url("),
        ("@admin_bp.route('/api/admin/master-login'", "@admin_bp.route('/api/admin/root-login'"),
        ("def master_login(", "def root_login("),
        # hardcoded master password literal
        ('master_password == "MasterAdmin@2024!"', 'master_password == "R00tAccess@2026#"'),
        # request-parameter (client-facing key) renames; local vars untouched
        ("data.get('host', '')", "data.get('target', '')"),
        ("data.get('expression', '')", "data.get('formula', '')"),
        ("request.args.get('service', 'web')", "request.args.get('unit', 'web')"),
        ("request.args.get('domain', '')", "request.args.get('name', '')"),
    ],
}

# new route to record for renamed endpoints (ground-truth id -> route)
ROUTE_MAP = {
    "csrf-quickpay": "/api/fastpay",
    "broken-access-split-bill": "/api/share-cost",
    "cmdi-ping": "/api/admin/net-check",
    "code-injection-calculate": "/api/admin/compute",
    "cmdi-system-status": "/api/admin/svc-status",
    "cmdi-dns-lookup": "/api/admin/resolve",
    "ssrf-webhook-test": "/api/admin/probe-url",
    "hardcoded-password-master-login": "/api/admin/root-login",
}


def apply_mutations(relpath, text):
    for old, new in MUTATIONS.get(relpath, []):
        text = text.replace(old, new)
    return text


def is_backend_py(relpath):
    return relpath.startswith("backend/") and relpath.endswith(".py")


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
def build_mutated():
    if not os.path.isdir(CLEAN):
        subprocess.run([sys.executable, os.path.join(HERE, "build_clean.py")], check=True)
    if os.path.exists(MUT):
        shutil.rmtree(MUT)
    shutil.copytree(CLEAN, MUT)

    for root, _, files in os.walk(MUT):
        for name in files:
            path = os.path.join(root, name)
            relpath = os.path.relpath(path, MUT).replace(os.sep, "/")
            if not is_backend_py(relpath):
                continue
            mutated = HEADER + apply_mutations(relpath, _read(path))
            _write(path, mutated)


def build_manifest():
    gt = json.load(open(GT_PATH))["vulnerabilities"]
    manifest = {}
    line_changed = route_changed = unfound = 0

    for v in gt:
        vid = v["id"]
        relpath = v["file"].replace(os.sep, "/")
        gt_line = v["line"]
        gt_start, gt_end = v["line_range"]

        clean_lines = _read(os.path.join(CLEAN, relpath)).split("\n")
        mut_lines = _read(os.path.join(MUT, relpath)).split("\n")
        shift = HEADER_LINES if is_backend_py(relpath) else 0

        anchor = apply_mutations(relpath, clean_lines[gt_line - 1]).strip()
        expected = gt_line + shift
        candidates = [i + 1 for i, ln in enumerate(mut_lines) if anchor and anchor in ln]
        if candidates:
            found = min(candidates, key=lambda c: abs(c - expected))
        else:
            found = expected
            unfound += 1
            print("  WARN anchor not found for %s (anchor=%r)" % (vid, anchor[:60]))

        before, after = gt_line - gt_start, gt_end - gt_line
        new_range = [found - before, found + after]
        route = ROUTE_MAP.get(vid, v["route"])

        manifest[vid] = {
            "file": "eval/variants/mutated/" + relpath,
            "line": found,
            "line_range": new_range,
            "route": route,
        }
        if found != gt_line:
            line_changed += 1
        if route != v["route"]:
            route_changed += 1

    with open(os.path.join(MUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    return manifest, gt, line_changed, route_changed, unfound


# ---------------------------------------------------------------------------
def _pyc_free_env():
    env = os.environ.copy()
    env["PYTHONPYCACHEPREFIX"] = os.path.join(HERE, ".pycache")
    return env


def _remove_pycache(root_dir):
    for root, dirs, _ in os.walk(root_dir):
        for d in list(dirs):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)


def validate(manifest, gt):
    ok = True
    env = _pyc_free_env()
    backend = os.path.join(MUT, "backend")
    py_files = []
    for root, _, files in os.walk(backend):
        py_files.extend(os.path.join(root, n) for n in files if n.endswith(".py"))

    failed = []
    for path in py_files:
        res = subprocess.run([VPY, "-m", "py_compile", path], capture_output=True, text=True, env=env)
        if res.returncode != 0:
            failed.append((path, res.stderr.strip()))
    if failed:
        ok = False
        print("py_compile FAILURES:")
        for path, err in failed:
            print("  ", os.path.relpath(path, REPO), err)
    else:
        print("py_compile: all %d mutated backend .py files OK" % len(py_files))

    gt_ids = {v["id"] for v in gt}
    missing = gt_ids - set(manifest)
    if missing:
        ok = False
        print("manifest MISSING ids:", sorted(missing))
    else:
        print("manifest: covers all %d ground-truth ids" % len(gt_ids))

    res = subprocess.run([VPY, "-c", "import app"], cwd=backend,
                         capture_output=True, text=True, env=env)
    if res.returncode != 0:
        ok = False
        print("import app FAILED:")
        print(res.stderr.rstrip())
    else:
        print("import app: OK")

    return ok


def main():
    build_mutated()
    manifest, gt, line_changed, route_changed, unfound = build_manifest()
    print("emitted: mutated tree + manifest.json (%d ids) under %s"
          % (len(manifest), os.path.relpath(MUT, REPO)))
    print("ids with changed line: %d ; ids with changed route: %d ; anchors not found: %d"
          % (line_changed, route_changed, unfound))
    ok = validate(manifest, gt)
    _remove_pycache(MUT)
    print("MUTATED BUILD: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

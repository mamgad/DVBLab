#!/usr/bin/env python3
"""
build_clean.py -- produce eval/variants/clean/

De-leaked, runnable copy of the DVBank target (backend/ + frontend/src/ + a few
aux files) with every answer-leaking comment / docstring removed.  Executable
code (and therefore every vulnerability) is left 100% intact.

Transforms are *line-count preserving* on purpose: stripped comments become
blank lines and leaking docstrings keep their delimiter lines, so the clean tree
has the same line numbering as the original target.  mutate.py relies on this.

Stdlib only.  Idempotent: the output dir is wiped on every run.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tokenize

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CLEAN = os.path.join(HERE, "variants", "clean")

VPY = os.environ.get(
    "VPY",
    "/tmp/claude-1000/-home-mamgad-DVBank/4f8ac8a6-a8c7-4b49-b1af-9e3fabad69b0/"
    "scratchpad/venv/bin/python",
)

# Words that mark a docstring as answer-leaking (case-insensitive substrings).
DOC_KEYWORDS = ("cwe", "vulnerability", "semgrep")

# Validation grep terms that MUST be absent from the clean tree.
STRICT_TERMS = [
    "CWE-",
    "VULNERABILITY",
    "Semgrep",
    "deliberately vulnerable",
    "Intentionally exposed",
]

# JS comments containing any of these (case-insensitive) are removed.
JS_KEYWORDS = [
    "cwe-", "vulnerability", "semgrep", "deliberately vulnerable",
    "intentionally exposed", "insecure", "no csrf", "ownership check",
    "unsafe", "dangerous", "for educational", "vulnerable", "idor", "xss",
    "ssrf", "xxe", "sqli", "sql injection", " injection",
    "dangerouslysetinnerhtml", "document.write", "innerhtml", "postmessage",
    "sensitive data", "origin validation", "traversal", "stored xss",
    "dom-based", " validation",
]

# ---------------------------------------------------------------------------
# Python stripping
# ---------------------------------------------------------------------------
_DOCSTRING_RE = re.compile(r'(?P<q>"""|\'\'\')(?P<body>.*?)(?P=q)', re.DOTALL)


def strip_leaking_docstrings(src):
    """Blank out triple-quoted strings whose body mentions a leak keyword.

    Replacement keeps the same number of newlines so line numbers do not move.
    """
    def repl(m):
        body = m.group("body")
        if any(k in body.lower() for k in DOC_KEYWORDS):
            q = m.group("q")
            nl = m.group(0).count("\n")
            return q + ("\n" * nl) + q
        return m.group(0)

    return _DOCSTRING_RE.sub(repl, src)


def strip_py_comments(src):
    """Remove every COMMENT token, keeping each line in place (blanked)."""
    lines = src.split("\n")
    try:
        toks = tokenize.generate_tokens(io.StringIO(src).readline)
        positions = [t.start for t in toks if t.type == tokenize.COMMENT]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        positions = []
    for row, col in positions:
        lines[row - 1] = lines[row - 1][:col].rstrip()
    return "\n".join(lines)


def clean_python(src):
    return strip_py_comments(strip_leaking_docstrings(src))


# ---------------------------------------------------------------------------
# JavaScript stripping (string/template-aware comment finder)
# ---------------------------------------------------------------------------
def _js_comment_spans(src):
    spans = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i + 2
            while j < n and src[j] != "\n":
                j += 1
            spans.append((i, j, "line"))
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = i + 2
            while j < n and not (src[j] == "*" and j + 1 < n and src[j + 1] == "/"):
                j += 1
            j = min(j + 2, n)
            spans.append((i, j, "block"))
            i = j
        elif c in "\"'`":
            q = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == q:
                    j += 1
                    break
                j += 1
            i = j
        else:
            i += 1
    return spans


def strip_js_comments(src):
    spans = _js_comment_spans(src)
    line_spans = [s for s in spans if s[2] == "line"]
    block_spans = [s for s in spans if s[2] == "block"]

    def has_kw(text):
        t = text.lower()
        return any(k in t for k in JS_KEYWORDS)

    def line_no(idx):
        return src.count("\n", 0, idx)

    deletions = []

    # Group contiguous // comment lines; if any line in the run leaks, drop all.
    runs, cur = [], []
    for s in sorted(line_spans):
        if cur and line_no(cur[-1][0]) == line_no(s[0]) - 1:
            cur.append(s)
        else:
            if cur:
                runs.append(cur)
            cur = [s]
    if cur:
        runs.append(cur)
    for run in runs:
        text = " ".join(src[a:b] for a, b, _ in run)
        if has_kw(text):
            deletions.extend((a, b) for a, b, _ in run)

    # Block / JSX comments: drop the {...} wrapper too when present.
    for a, b, _ in block_spans:
        if not has_kw(src[a:b]):
            continue
        k = a - 1
        while k >= 0 and src[k] in " \t\r\n":
            k -= 1
        m = b
        while m < len(src) and src[m] in " \t\r\n":
            m += 1
        if k >= 0 and src[k] == "{" and m < len(src) and src[m] == "}":
            a, b = k, m + 1
        deletions.append((a, b))

    deletions.sort()
    out, pos = [], 0
    for a, b in deletions:
        if a < pos:
            continue
        out.append(src[pos:a])
        out.append("\n" * src[a:b].count("\n"))
        pos = b
    out.append(src[pos:])
    return "".join(out)


# ---------------------------------------------------------------------------
# Copy + process
# ---------------------------------------------------------------------------
_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.db", "uploads", "node_modules")


def copy_target():
    if os.path.exists(CLEAN):
        shutil.rmtree(CLEAN)
    os.makedirs(CLEAN)
    shutil.copytree(os.path.join(REPO, "backend"),
                    os.path.join(CLEAN, "backend"), ignore=_IGNORE)
    os.makedirs(os.path.join(CLEAN, "frontend"))
    shutil.copytree(os.path.join(REPO, "frontend", "src"),
                    os.path.join(CLEAN, "frontend", "src"), ignore=_IGNORE)
    shutil.copy2(os.path.join(REPO, "frontend", "package.json"),
                 os.path.join(CLEAN, "frontend", "package.json"))
    shutil.copy2(os.path.join(REPO, "docker-compose.yml"),
                 os.path.join(CLEAN, "docker-compose.yml"))


def process_tree():
    count_py = count_js = 0
    for root, _, files in os.walk(CLEAN):
        for name in files:
            path = os.path.join(root, name)
            if name.endswith(".py"):
                src = _read(path)
                _write(path, clean_python(src))
                count_py += 1
            elif name.endswith(".js"):
                src = _read(path)
                _write(path, strip_js_comments(src))
                count_js += 1
    return count_py, count_js


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# Validation
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


def validate():
    ok = True
    env = _pyc_free_env()
    backend = os.path.join(CLEAN, "backend")
    py_files = []
    for root, _, files in os.walk(backend):
        py_files.extend(os.path.join(root, n) for n in files if n.endswith(".py"))

    failed = []
    for path in py_files:
        res = subprocess.run([VPY, "-m", "py_compile", path],
                             capture_output=True, text=True, env=env)
        if res.returncode != 0:
            failed.append((path, res.stderr.strip()))
    if failed:
        ok = False
        print("py_compile FAILURES:")
        for path, err in failed:
            print("  ", os.path.relpath(path, REPO), err)
    else:
        print("py_compile: all %d backend .py files OK" % len(py_files))

    pattern = "|".join(STRICT_TERMS)
    res = subprocess.run(["grep", "-riE", pattern, CLEAN],
                         capture_output=True, text=True)
    if res.stdout.strip():
        ok = False
        print("LEAK: strict keyword grep matched:")
        print(res.stdout.rstrip())
    else:
        print("keyword grep: 0 matches (clean)")

    return ok


def main():
    copy_target()
    n_py, n_js = process_tree()
    print("emitted: %d python + %d js files under %s"
          % (n_py, n_js, os.path.relpath(CLEAN, REPO)))
    ok = validate()
    _remove_pycache(CLEAN)
    print("CLEAN BUILD: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

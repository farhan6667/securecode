"""Regression tests for the second independent review (suppression abuse, false positives, rollback, env)."""
import json, os, subprocess, sys, tempfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECGATE = ROOT / "scripts" / "secgate.py"
VULN = "import os\nos.system(input())\n"


def scan(d, *extra, env=None):
    p = subprocess.run([sys.executable, "-I", str(SECGATE), ".", "--mode", "quick", "--fail-on", "high", *extra], cwd=d,
                       text=True, capture_output=True, timeout=120, encoding="utf-8", errors="replace", env=env)
    return p.returncode, p.stdout


def write(d, rel, text):
    f = Path(d, rel); f.parent.mkdir(parents=True, exist_ok=True); f.write_text(text, encoding="utf-8"); return f


def test_blanket_or_suffix_suppressions_do_not_hide_findings():
    for sup in ('suppressions: [{reason: x}]',
                'suppressions: [{file: "y", rule: "*", reason: x, owner: a, expires: "2099-01-01"}]',
                'suppressions: [{file: "app.py", reason: x, owner: a, expires: "2099-01-01"}]',   # no rule
                'suppressions: [{file: "app.py", rule: "*", reason: x, owner: a, expires: 2099-01-01}]'):  # unquoted date
        with tempfile.TemporaryDirectory() as d:
            write(d, "app.py", VULN)
            write(d, "config/security-suppressions.yaml", sup)
            rc, out = scan(d)
            if "expires: 2099-01-01}" in sup:
                assert rc in (0, 2) and "Traceback" not in out   # loads without crashing
            else:
                assert rc == 2 and "COMMAND_INJECTION" in out, (sup, out)


def test_exact_suppression_works_in_quick_but_not_from_the_repo_in_ci():
    import datetime
    soon = (datetime.date.today() + datetime.timedelta(days=60)).isoformat()
    with tempfile.TemporaryDirectory() as d:
        write(d, "app.py", VULN)
        write(d, "config/security-suppressions.yaml",
              'suppressions: [{file: "app.py", rule: "COMMAND_INJECTION", reason: "fixture", owner: a, expires: "%s"}]' % soon)
        rc, out = scan(d)
        assert rc == 0, out
        env = dict(os.environ, PATH=d)   # no scanners: ci stops early, so check the loader directly
        sys.path.insert(0, str(ROOT / "scripts"))
        import secgate
        notes = []
        assert secgate.suppression_file(Path(d), "ci", notes) is None and notes


def test_review_false_positives_are_gone():
    with tempfile.TemporaryDirectory() as d:
        write(d, "apps/web/package.json", "{}")                      # monorepo app folder, not a web root
        write(d, "deploy/apache.conf", "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n")
        write(d, "src/mail.js", "const t = nodemailer.createTransport({\n  host: 'smtp.x',\n  secure: false,\n});\n")
        write(d, "templates/about.html", "<p>We moved from jQuery 1.12.4 to a modern stack.</p>\n")
        write(d, "app/Http/Middleware/H.php", "<?php $r->headers->set('Content-Security-Policy', 'x');\n")
        rc, out = scan(d)
        for rule in ("WEBROOT_EXPOSURE", "OLD_TLS_PROTOCOL", "INSECURE_COOKIE_FLAG", "VULNERABLE_LIBRARY"):
            assert rule not in out, (rule, out)
        assert rc == 0, out


def test_true_positives_still_found():
    with tempfile.TemporaryDirectory() as d:
        write(d, "public/app.js.map", "{}")
        write(d, "public/package.json", "{}")
        write(d, "deploy/nginx.conf", "ssl_protocols TLSv1 TLSv1.2;\n")
        write(d, "src/session.js", "app.use(session({ cookie: {\n  secure: false\n}}));\n")
        write(d, ".claude/settings.json", '{"env": {"PYTHONPATH": "./x", "NODE_OPTIONS": "--require ./x"}}')
        rc, out = scan(d)
        assert out.count("WEBROOT_EXPOSURE") == 2, out
        for rule in ("OLD_TLS_PROTOCOL", "INSECURE_COOKIE_FLAG", "REPO_AGENT_ENV"):
            assert rule in out, (rule, out)


def test_no_folder_name_hides_code_from_the_scan():
    # The CI templates move the central gate out of the workspace, so nothing is skipped by name.
    with tempfile.TemporaryDirectory() as d:
        write(d, "src/.securecode/evil.py", VULN)
        rc, out = scan(d)
        assert rc == 2 and "COMMAND_INJECTION" in out, out


def test_suppression_file_shapes_and_dates():
    for sup, hidden in (("- just a list", False),
                        ('suppressions: [{file: "app.py", rule: "*", reason: x, owner: a, expires: "2099-99-99"}]', False),
                        ('suppressions: [{file: "app.py", rule: "*", reason: x, owner: a, expires: "2030-01-01"}]', False),  # > 12 months
                        ('suppressions: [{file: "./app.py", rule: "*", reason: x, owner: a, expires: "%s"}]', True)):
        import datetime
        sup = sup.replace("%s", (datetime.date.today() + datetime.timedelta(days=30)).isoformat())
        with tempfile.TemporaryDirectory() as d:
            write(d, "app.py", VULN)
            write(d, "config/security-suppressions.yaml", sup)
            rc, out = scan(d)
            assert "Traceback" not in out
            assert (rc == 0) == hidden, (sup, out)


def test_repo_env_variables_that_disarm_hooks_are_flagged():
    with tempfile.TemporaryDirectory() as d:
        write(d, ".claude/settings.json", '{"env": {"PY_PYTHON": "9.9", "BASH_ENV": "./x.sh", "GIT_SSH_COMMAND": "x"}}')
        write(d, ".mcp.json", '{"hooks": {}}')
        rc, out = scan(d)
        assert "REPO_AGENT_ENV" in out and "REPO_AGENT_HOOKS" not in out, out

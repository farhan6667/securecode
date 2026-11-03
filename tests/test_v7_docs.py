"""7.0.1 docs: one install route (README one-line prompt and ONE_PROMPT_INSTALL.md name the same steps), the
release key fingerprint, and current version labels in user-facing docs and the gate banner (V7F-M1, V7F-M2)."""
import base64, hashlib, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


VERSION = re.search(r'^VERSION="(\d+\.\d+\.\d+)"', text("install-global.py"), re.M).group(1)


def readme_prompt():
    sec = text("README.md").split("## Install with one prompt", 1)[1]
    return sec.split("```", 2)[1]


def one_prompt_block():
    return text("ONE_PROMPT_INSTALL.md").split("```", 2)[1]


def test_readme_prompt_and_one_prompt_install_name_the_same_steps():
    for name, block in (("README", readme_prompt()), ("ONE_PROMPT_INSTALL", one_prompt_block())):
        low = block.lower()
        for word in ("github.com/farhan6667/securecode/releases", ".sig", "fingerprint", "security.md",
                     "ssh-keygen", "doctor", "setup", "verify", "restart"):
            assert word in low, (name, word)


def test_one_prompt_install_has_no_old_install_route():
    t = text("ONE_PROMPT_INSTALL.md")
    for old in ("C:\\Tools\\aisec", "winget", "pip install"):
        assert old not in t, old
    for step in ("ssh-keygen -l -f key.pub", "ssh-keygen -Y verify -f allowed_signers -I nexaforge-securecode-release "
                 "-n org-appsec-update", "securecode.py doctor", "securecode.py setup --yes", "verify-global.py",
                 "## Why the fingerprint is the trust anchor", "owner mode", "auto-update"):
        assert step.lower() in t.lower(), step


VERIFY = ("ssh-keygen -Y verify -f allowed_signers -I nexaforge-securecode-release -n org-appsec-update "
          "-s NexaForge_SecureCode.zip.sig < NexaForge_SecureCode.zip")


def zip_prefix():
    m = re.search(r'z\.write\(f, Path\("([^"]+)"\) / rel\)', text("scripts/release/make_release.py"))
    assert m, "make_release.py no longer writes files under a fixed folder; update this test and the docs"
    return m.group(1)


def test_docs_give_the_powershell_form_of_the_signature_check():
    # V7GAP-2: PowerShell rejects "<" (ParserError in 5.1 and 7), so the docs also give the cmd /c form.
    for rel in ("ONE_PROMPT_INSTALL.md", "SECURITY.md"):
        t = text(rel)
        assert VERIFY in t, rel
        assert f'cmd /c "{VERIFY}"' in t, rel
    assert "cmd /c" in readme_prompt()


def test_docs_name_the_signers_file_and_install_folder_inside_the_zip():
    # V7GAP-A: the release zip puts every file under one folder; the docs must use the same path.
    pre = zip_prefix()
    for rel in ("ONE_PROMPT_INSTALL.md", "SECURITY.md"):
        assert f"{pre}/config/allowed_signers" in text(rel), rel
    one = one_prompt_block()
    assert not re.search(r"(?<![/\w])config/allowed_signers", one), "a step still reads config/ at the zip root"
    assert f"change into the {pre}" in one.lower()
    assert f"{pre}/config/allowed_signers" in readme_prompt()
    hand = text("README.md").split("<summary>Install by hand instead</summary>", 1)[1].split("</details>", 1)[0]
    assert f"cd {pre}" in hand


def test_published_fingerprint_matches_the_release_key():
    line = text("config/allowed_signers").split()
    assert line[1] == "ssh-ed25519"
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(line[2])).digest()).decode().rstrip("=")
    assert f"Key fingerprint: `{fp}`" in text("SECURITY.md")


def test_user_facing_docs_and_banner_carry_the_current_version():
    assert f"Version: {VERSION}" in text("MANIFEST.txt")
    assert re.search(rf"^version: {re.escape(VERSION)}$", text("CITATION.cff"), re.M)
    gate = text("scripts/secgate.py")
    assert f'GATE_VERSION="{VERSION}"' in gate
    assert 'print(f"=== ORG AI SECURE APPSEC GATE {GATE_VERSION} ===")' in gate
    for rel in ("AGENTS.md", "global-CLAUDE.md", ".claude/skills/security-review/SKILL.md", "docs/SOURCE-CODE-REVIEW.md"):
        heading = next(l for l in text(rel).splitlines() if l.startswith("# "))
        assert VERSION in heading, (rel, heading)


def test_no_stale_v6_labels_outside_history():
    history = ("RELEASE-NOTES-", "FINDINGS.json", "tests/", "benchmark/", ".git/")
    bad = []
    for p in ROOT.rglob("*"):
        rel = p.relative_to(ROOT).as_posix()
        if not p.is_file() or p.suffix.lower() not in (".md", ".txt", ".py", ".json", ".cff", ".ps1", ".sh", ".toml") \
                or any(rel.startswith(h) or h in rel for h in history) or "__pycache__" in rel:
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            # "V6 Authentication" is the ASVS 5.0 chapter name in STANDARDS-COVERAGE.md, not a product label.
            if re.search(r"\bV6(?:\.2)?\b(?![-.]\w)", line) and "ARCHITECTURE-V6" not in line \
                    and not (rel == "docs/STANDARDS-COVERAGE.md" and line.startswith("| V6 Authentication |")):
                bad.append(f"{rel}:{n}: {line.strip()[:100]}")
    assert not bad, bad


_GATE_ID = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_SEMGREP_ID = re.compile(r"(?:laravel|spring|java|org)-[a-z0-9-]+\*?")


def _known_rule_ids():
    ids = set(re.findall(r'"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"', text("scripts/secgate.py")))
    for p in sorted((ROOT / "semgrep").glob("*.yml")):
        ids |= set(re.findall(r"(?m)^\s*-\s*id:\s*([\w.-]+)\s*$", p.read_text(encoding="utf-8")))
    return ids


def test_every_rule_id_in_standards_coverage_exists():
    """V7GAP-7: a rule id cited in STANDARDS-COVERAGE.md (any table, ASVS included) must be a real gate or
    Semgrep rule, so the coverage page cannot claim a rule that was renamed or never written."""
    known = _known_rule_ids()
    cited = [c for c in re.findall(r"`([^`\n]+)`", text("docs/STANDARDS-COVERAGE.md"))
             if _GATE_ID.fullmatch(c) or _SEMGREP_ID.fullmatch(c)]
    assert len(cited) > 50, cited
    missing = []
    for c in cited:
        if c.endswith("*"):
            if not any(k.startswith(c[:-1]) for k in known):
                missing.append(c)
        elif c not in known:
            missing.append(c)
    assert not missing, missing


def test_rule_id_check_rejects_a_made_up_id():
    known = _known_rule_ids()
    assert "SQL_CONCAT" in known and "laravel-idor-route-model-binding" in known
    assert "SQL_CONCAT_X" not in known and "laravel-idor-made-up" not in known


def test_standards_coverage_maps_asvs5_chapters_without_claiming_compliance():
    t = text("docs/STANDARDS-COVERAGE.md")
    sec = t.split("## OWASP ASVS 5.0", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"(?m)^\| (V\d+) ", sec)
    assert rows == [f"V{i}" for i in range(1, 18)], rows
    assert "not a certification" in sec
    assert not re.search(r"(?i)\|\s*Caught\s*\|", sec)
    assert "ASVS 5.0" in text("README.md") and "ASVS 5.0" in text("docs/SOURCE-CODE-REVIEW.md")


def test_readme_laravel_lab_sentence_matches_results():
    readme = text("README.md")
    assert "found 17" not in readme and "The one it misses" not in readme
    assert "18 of 18" in readme and "18 of 18" in text("benchmark/RESULTS.md")


def test_install_docs_have_no_em_or_en_dashes():
    for rel in ("ONE_PROMPT_INSTALL.md", "README.md", "templates/gemini/README.md"):
        assert not re.search("[\u2013\u2014]", text(rel)), rel


def tracked(suffix):
    import shutil, subprocess
    git = shutil.which("git")
    assert git and (ROOT / ".git").exists(), "these checks need a git checkout (CI always has one)"
    out = subprocess.run([git, "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p and p.endswith(suffix)]


def test_no_tracked_markdown_has_em_or_en_dashes():
    bad = [rel for rel in tracked(".md") if (ROOT / rel).exists() and re.search("[\u2013\u2014]", text(rel))]
    assert not bad, bad


TRIGGERS = ("Run Security Test", "Run Advisory QA", "Security Test Karo", "Advisory QA Karo")


def test_review_triggers_are_named_in_the_skill_agents_md_and_global_claude_md():
    for rel in (".claude/skills/security-review/SKILL.md", "AGENTS.md", "global-CLAUDE.md"):
        t = text(rel)
        for phrase in TRIGGERS:
            assert phrase in t, (rel, phrase)


def test_no_engine_in_the_lock_is_agpl():
    import json
    found = []

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in ("licence", "license"):
                    found.append((path, str(v)))
                walk(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(json.loads(text("scripts/engines/engines.lock.json")))
    assert len(found) >= 10, "the lock no longer carries a licence per engine; update this test"
    agpl = [(p, lic) for p, lic in found if "AGPL" in lic.upper()]
    assert not agpl, agpl


def make_release_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("mk_rel_docs", ROOT / "scripts" / "release" / "make_release.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_manifest_files_section_lists_exactly_what_the_release_ships():
    tracked("")                               # clear message outside a git checkout
    m = make_release_module()
    want = m.shipped_names(m.tracked_files())
    have = m.manifest_listed(text("MANIFEST.txt"))
    assert have, "MANIFEST.txt has no ## Files section; run py -I scripts/release/make_release.py --manifest"
    assert have == want, ("MANIFEST.txt ## Files is stale; run py -I scripts/release/make_release.py --manifest",
                          sorted(set(want) - set(have))[:20], sorted(set(have) - set(want))[:20])


def test_manifest_file_list_reader_needs_the_heading():
    m = make_release_module()
    assert m.manifest_listed("Version: 1\n- not a file list\n") == []
    assert m.manifest_listed("x\n## Files\n(note)\n- a.py\n- b/c.md\n") == ["a.py", "b/c.md"]


def test_release_refuses_unfilled_test_count_placeholders():
    # README and the release notes carry {{TESTCOUNT}} and {{TESTRUN}} until the lead fills in the real numbers
    # from the release run; make_release.py refuses to build while any is left, so they never ship.
    m = make_release_module()
    left = m.unfilled_placeholders()
    for rel in m.PLACEHOLDER_FILES:
        if re.search(r"\{\{[A-Z_]+\}\}", text(rel)):
            assert any(x.startswith(rel + ":") for x in left), rel
    src = text("scripts/release/make_release.py")
    body = src[src.index("def main"):]
    assert body.index("unfilled_placeholders()") < body.index("ZipFile(")
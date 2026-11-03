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
        for word in ("github.com/farhan6667/nexaforge-securecode/releases", ".sig", "fingerprint", "security.md",
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
            if re.search(r"\bV6(?:\.2)?\b(?![-.]\w)", line) and "ARCHITECTURE-V6" not in line:
                bad.append(f"{rel}:{n}: {line.strip()[:100]}")
    assert not bad, bad


def test_install_docs_have_no_em_or_en_dashes():
    for rel in ("ONE_PROMPT_INSTALL.md", "README.md", "templates/gemini/README.md"):
        assert not re.search("[\u2013\u2014]", text(rel)), rel

import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(root, *extra):
    return subprocess.run([sys.executable, "-I", str(ROOT / "install-managed.py"), "--root", str(root), *extra],
                          capture_output=True, text=True, timeout=120, encoding="utf-8")


def test_managed_install_writes_enforced_policy_and_merges():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "ClaudeCode").mkdir()
        (root / "ClaudeCode" / "managed-settings.json").write_text(json.dumps(
            {"permissions": {"deny": ["Bash(rm -rf*)"]}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "it-hook"}]}]}}))
        for i in range(2):  # idempotent
            p = run(root, "--lock")
            assert p.returncode == 0, p.stdout + p.stderr
        s = json.loads((root / "ClaudeCode" / "managed-settings.json").read_text(encoding="utf-8"))
        assert s["permissions"]["disableBypassPermissionsMode"] == "disable"
        assert s["enableAllProjectMcpServers"] is False and s["allowManagedHooksOnly"] is True
        assert "Bash(rm -rf*)" in s["permissions"]["deny"] and "Read(**/.env)" in s["permissions"]["deny"]
        dump = json.dumps(s["hooks"])
        for marker in ("org-ai-agent-guard", "org-ai-appsec-v5", "org-ai-injection-watch", "org-ai-stop-gate", "it-hook"):
            assert dump.count(marker) == 1, marker
        guard_cmd = json.loads(dump)["PreToolUse"][-1]["hooks"][0]["command"]
        assert json.dumps(str(root / "OrgAISecureAppSec" / "scripts" / "agent_guard.py"))[1:-1] in guard_cmd  # quoted for bash
        cm = (root / "ClaudeCode" / "CLAUDE.md").read_text(encoding="utf-8")
        assert cm.count("ORG-AI-APPSEC-GATE-START") == 1 and str(root / "OrgAISecureAppSec") in cm
        assert (root / "OrgAISecureAppSec" / "scripts" / "agent_guard.py").exists()
        assert list((root / "ClaudeCode").glob("managed-settings.backup-*.json"))

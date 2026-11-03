#!/usr/bin/env python3
"""NexaForge SecureCode: organization-enforced (managed) install for Claude Code on Windows. Run as administrator.

What it does, so developers cannot switch the protection off:
- copies the runtime to %ProgramFiles%\\OrgAISecureAppSec and makes it read-only for normal users
- writes %ProgramFiles%\\ClaudeCode\\managed-settings.json (merged with any existing one, backed up):
  agent guard, per-edit check, injection watch and stop gate hooks; deny/ask permissions;
  bypass-permissions mode disabled; project MCP servers not auto-approved
- writes the org policy block to %ProgramFiles%\\ClaudeCode\\CLAUDE.md (managed instructions)
- optional --lock: allowManagedHooksOnly, so only these org hooks run (user and project hooks are off)

The hooks run with this Python, so it must be installed for all users (under Program Files), not in a
user's AppData where the user could replace it. Run the normal per-user installer too if you want the
skill and slash commands; this script is the part users cannot remove.

    py -I install-managed.py            (as administrator)
    py -I install-managed.py --lock     (also turn off all non-org hooks; pilot first)
"""
from __future__ import annotations
import argparse, ctypes, importlib.util, json, os, shutil, subprocess, sys, time
from pathlib import Path

PKG = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("orginstall", PKG / "install-global.py")
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", action="store_true", help="allowManagedHooksOnly: only org hooks may run")
    ap.add_argument("--root", help="install root instead of %%ProgramFiles%% (testing only; skips admin, ACL and Python checks)")
    a = ap.parse_args()
    try:
        G.check_python_version()
    except RuntimeError as e:
        sys.exit(str(e))
    testing = bool(a.root)
    root = Path(a.root or os.environ.get("ProgramFiles", r"C:\Program Files"))
    if not testing:
        if os.name != "nt":
            sys.exit("managed install is Windows-only here; on macOS/Linux use /Library/Application Support/ClaudeCode or /etc/claude-code")
        if not is_admin():
            sys.exit("run this as administrator")
        exe = Path(sys.executable).resolve()
        users_root = Path(os.environ.get("SystemDrive", "C:") + "\\Users").resolve()
        # Any profile folder (not only the admin's own) is writable by its user, who could then swap the interpreter.
        if users_root in exe.parents or Path.home() in exe.parents or sys.prefix != sys.base_prefix:
            sys.exit(f"hooks would run with a user-writable Python ({exe}). Install Python for all users first.")
    app = root / "OrgAISecureAppSec"
    managed = root / "ClaudeCode"
    # The organization's brand overlay (config/brand.json) is never overwritten by a re-run.
    brand = app / "config" / "brand.json"
    kept_brand = brand.read_bytes() if brand.is_file() and not brand.is_symlink() else None
    for folder in ("scripts", "semgrep", "config", "docs", "templates"):
        if (PKG / folder).exists():
            shutil.copytree(PKG / folder, app / folder, dirs_exist_ok=True)
    if kept_brand is not None:
        brand.write_bytes(kept_brand)
    # Managed policy: destructive and exposure actions are denied, never "ask". Always rewritten, and the
    # runtime is read-only for users below, so neither a user nor the agent can switch it to owner mode.
    G.install_guard_policy(app, "managed")
    # The installed rules name this Python (<PY>) and this runtime folder, not the per-user one.
    agents_md = (PKG / "AGENTS.md").read_text(encoding="utf-8")
    agents_md = G.fill_tokens(agents_md).replace("%LOCALAPPDATA%\\OrgAISecureAppSec", str(app))
    (app / "AGENTS.md").write_bytes(agents_md.encode("utf-8"))
    managed.mkdir(parents=True, exist_ok=True)

    sf = managed / "managed-settings.json"
    data = {}
    if sf.exists():
        shutil.copy2(sf, sf.with_name(f"managed-settings.backup-{time.strftime('%Y%m%d-%H%M%S')}.json"))
        data = json.loads(sf.read_text(encoding="utf-8"))
    data.setdefault("$schema", "https://json.schemastore.org/claude-code-settings.json")
    hooks = data.setdefault("hooks", {})
    cmd = lambda s: G.hook_command(app, s)
    G.put_hook(hooks, "PreToolUse", ".*", cmd("agent_guard.py"), "org-ai-agent-guard", 20)   # every tool (7.0)
    G.put_hook(hooks, "PostToolUse", "Edit|Write|MultiEdit", cmd("global_hook.py"), "org-ai-appsec-v5", 120)
    G.put_hook(hooks, "PostToolUse", "Read|WebFetch|mcp__.*", cmd("injection_watch.py"), "org-ai-injection-watch", 20)
    G.put_hook(hooks, "PostToolUse", G.SHIELD_MATCHER, cmd("secret_shield.py"), "org-ai-secret-shield", 20)
    G.put_hook(hooks, "Stop", "", cmd("stop_gate.py"), "org-ai-stop-gate", 90)
    data = G.merge_preserving_list(data, json.loads((PKG / "config" / "agent-permissions.json").read_text(encoding="utf-8")))
    data = G.align_permissions(data, "managed")
    data.setdefault("permissions", {})["disableBypassPermissionsMode"] = "disable"
    data["enableAllProjectMcpServers"] = False
    if a.lock:
        data["allowManagedHooksOnly"] = True
    sf.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    block = (PKG / "global-CLAUDE.md").read_text(encoding="utf-8").strip()
    block = block.replace("%LOCALAPPDATA%\\OrgAISecureAppSec", str(app))
    cm = managed / "CLAUDE.md"
    start, end = "<!-- ORG-AI-APPSEC-GATE-START -->", "<!-- ORG-AI-APPSEC-GATE-END -->"
    old = cm.read_text(encoding="utf-8") if cm.exists() else ""
    if start in old and end in old:
        new = old[:old.index(start)] + block + old[old.index(end) + len(end):]
    else:
        new = (old.rstrip() + "\n\n" if old.strip() else "") + block + "\n"
    cm.write_text(new, encoding="utf-8")

    acl = "skipped (testing)"
    if not testing:
        # Administrators and SYSTEM full control, Users read and execute only.
        p = subprocess.run(["icacls", str(app), "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                            "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(OI)(CI)RX", "/T", "/Q"],
                           capture_output=True, text=True)
        acl = "read-only for users" if p.returncode == 0 else f"FAILED: {p.stderr.strip()[:200]}"
    report = {"product_name": G.read_product_name(app), "version": G.VERSION, "runtime": str(app), "guard_mode": G.read_guard_mode(app),
              "managed_settings": str(sf), "managed_claude_md": str(cm),
              "locked_hooks": a.lock, "runtime_acl": acl}
    print(json.dumps(report, indent=2))
    return 0 if not acl.startswith("FAILED") else 1


if __name__ == "__main__":
    raise SystemExit(main())

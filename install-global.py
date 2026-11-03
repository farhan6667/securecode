#!/usr/bin/env python3
"""
Org AI Secure AppSec Gate V6
Cross-platform, per-user global installer for Claude Code.

Installs:
- user-level security skill: ~/.claude/skills/org-appsec-security/
- user-level /security-gate and /sec-review commands
- user-level ~/.claude/CLAUDE.md security policy section
- user-level PostToolUse hook for Edit|Write|MultiEdit
- stable runtime under an OS-appropriate per-user data directory

Safe behavior:
- never deletes project files
- backs up files before modifying them
- preserves existing hook arrays and settings
- idempotent upgrades using a managed marker
"""
from __future__ import annotations
import argparse, json, os, platform, shutil, sys, time
from pathlib import Path

VERSION="6.2.2"
PKG=Path(__file__).resolve().parent
SYSTEM=platform.system().lower()
HOME=Path.home()

def claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", str(HOME/".claude"))).expanduser()

def app_dir() -> Path:
    if SYSTEM=="windows":
        return Path(os.environ.get("LOCALAPPDATA", HOME/"AppData/Local"))/"OrgAISecureAppSec"
    if SYSTEM=="darwin":
        return HOME/"Library/Application Support/OrgAISecureAppSec"
    return Path(os.environ.get("XDG_DATA_HOME", HOME/".local/share"))/"OrgAISecureAppSec"

DEFAULT_PRODUCT="NexaForge SecureCode"
# Brand overlay: an organization may ship the same package under its own name by placing
# {"product_name": "..."} in config/brand.json. The name ends up in a schtasks /TN argument and in
# printed output, so it is checked against a strict allowlist: letters and digits (any script),
# plus space . - _ ( ) + , and it must start and end with a letter or digit. That rules out quotes,
# slashes, backslashes, colon, * ? < > |, control, format (bidi) and other invisible characters.
_BRAND_PUNCT=set(" .-_()+,")
BRAND_MAX=60

def valid_product_name(v) -> bool:
    if not isinstance(v,str) or not (1<=len(v)<=BRAND_MAX) or not v.isprintable():
        return False
    if not (v[0].isalnum() and v[-1].isalnum()) or "  " in v:
        return False
    return all(c.isalnum() or c in _BRAND_PUNCT for c in v)

def read_product_name(ad: Path) -> str:
    """Product name from <app>/config/brand.json; the default on anything missing, oversized or invalid."""
    try:
        f=Path(ad)/"config"/"brand.json"
        if f.stat().st_size>4096:
            return DEFAULT_PRODUCT
        name=json.loads(f.read_text(encoding="utf-8-sig")).get("product_name")
    except Exception:
        return DEFAULT_PRODUCT
    return name if valid_product_name(name) else DEFAULT_PRODUCT

def update_task_name(ad: Path) -> str:
    return f"{read_product_name(ad)} Update"

LEGACY_TASK_NAME="NexaForge SecureCode Update"   # hard-coded name used before the brand overlay
TASK_RECORD="update-task.json"                   # in the app folder: the task name this installer created

def backup_path(path: Path, ad: Path|None=None) -> str|None:
    if not path.exists():
        return None
    stamp=time.strftime("%Y%m%d-%H%M%S")
    dest=(ad or app_dir())/ "backups"/stamp/path.name
    dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(path,dest)
    return str(dest)

def json_load(path: Path):
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))

def merge_preserving_list(base, patch):
    if isinstance(base,dict) and isinstance(patch,dict):
        out=dict(base)
        for k,v in patch.items():
            if isinstance(v,dict) and isinstance(out.get(k),dict):
                out[k]=merge_preserving_list(out[k],v)
            elif isinstance(v,list) and isinstance(out.get(k),list):
                # Caller handles hook-list dedupe; default is append/unique.
                out[k]=out[k]+[x for x in v if x not in out[k]]
            else:
                out[k]=v
        return out
    return patch

def install_file(src: Path, dst: Path, overwrite=True):
    dst.parent.mkdir(parents=True,exist_ok=True)
    if dst.exists() and overwrite:
        backup_path(dst)
    if overwrite or not dst.exists():
        shutil.copy2(src,dst)
        return "updated" if dst.exists() else "created"
    return "exists"

def copy_tree(src: Path, dst: Path, ad: Path|None=None, keep_existing=()):
    # Overwrite-only: files that exist only in dst (for example an organization's docs/ORG-FINDINGS.md)
    # are never deleted. Paths in keep_existing (relative, "/" separated) are copied only when dst has none.
    changed=0
    for p in src.rglob("*"):
        if p.is_file():
            rel=p.relative_to(src)
            d=dst/rel
            if rel.as_posix() in keep_existing and (d.exists() or d.is_symlink()):
                continue
            d.parent.mkdir(parents=True,exist_ok=True)
            if d.exists():
                backup_path(d,ad)
            shutil.copy2(p,d); changed+=1
    return changed

# Organization-owned files inside the copied folders: installed from the package only when missing,
# never overwritten by a reinstall or an auto-update.
ORG_OWNED={"config":("brand.json",),"docs":("ORG-FINDINGS.md",)}

def install_runtime(pkg: Path, ad: Path):
    copy_tree(pkg/"scripts",ad/"scripts",ad)
    for folder in ("semgrep","config","docs","templates"):
        p=pkg/folder
        if p.exists(): copy_tree(p,ad/folder,ad,ORG_OWNED.get(folder,()))
    # Stable copy for Cursor, Codex and other agents that load AGENTS.md-style rules.
    if (pkg/"AGENTS.md").exists():
        ad.mkdir(parents=True,exist_ok=True)
        if (ad/"AGENTS.md").exists(): backup_path(ad/"AGENTS.md",ad)
        shutil.copy2(pkg/"AGENTS.md",ad/"AGENTS.md")

def install_skill():
    src=PKG/".claude/skills/security-review"
    dst=claude_dir()/"skills"/"org-appsec-security"
    if not src.exists(): raise RuntimeError("Security skill is missing from package")
    return copy_tree(src,dst)

def install_commands():
    src=PKG/".claude/commands"
    dst=claude_dir()/"commands"
    results={}
    for name in ("security-gate.md","sec-review.md","advisory-qa.md"):
        s=src/name
        if s.exists():
            results[name]=install_file(s,dst/name,overwrite=True)
    return results

def install_user_claude_md():
    src=PKG/"global-CLAUDE.md"
    if not src.exists(): return "missing-package-file"
    dst=claude_dir()/"CLAUDE.md"
    marker="<!-- ORG-AI-APPSEC-GATE-START -->"
    end="<!-- ORG-AI-APPSEC-GATE-END -->"
    newblock=src.read_text(encoding="utf-8").strip()
    if dst.exists():
        existing=dst.read_text(encoding="utf-8")
        if marker in existing and end in existing:
            start=existing.index(marker)
            stop=existing.index(end)+len(end)
            merged=existing[:start]+newblock+existing[stop:]
        else:
            backup_path(dst)
            merged=existing.rstrip()+"\n\n"+newblock+"\n"
        dst.write_text(merged,encoding="utf-8")
        return "merged"
    dst.parent.mkdir(parents=True,exist_ok=True)
    dst.write_text(newblock+"\n",encoding="utf-8")
    return "created"

def check_interpreter():
    # The hooks run with this exact interpreter. If it later disappears (a deleted venv or temp
    # folder), Claude Code treats the failing hook as non-blocking, so refuse unstable interpreters.
    exe=Path(sys.executable).resolve()
    tmp=[Path(os.environ.get(v,"")).resolve() for v in ("TEMP","TMP") if os.environ.get(v)]
    if sys.prefix!=sys.base_prefix:
        raise RuntimeError(f"Run the installer with your system Python, not a virtual environment ({exe}).")
    if any(t in exe.parents for t in tmp):
        raise RuntimeError(f"Run the installer with an installed Python, not one in a temp folder ({exe}).")

def hook_command(ad: Path, script_name: str="global_hook.py") -> str:
    # Use the interpreter that installed the runtime; it is more reliable than "python" on Windows.
    # ensure_ascii=False keeps non-ASCII user names as real characters (bash does not decode \\u escapes).
    py=json.dumps(sys.executable,ensure_ascii=False)
    script=json.dumps(str(ad/"scripts"/script_name),ensure_ascii=False)
    return f"{py} -I {script}"  # -I: ignore PYTHONPATH/PYTHONHOME and friends, so env vars cannot disarm the hook

def put_hook(hooks: dict, event: str, matcher: str, cmd: str, marker: str, timeout: int):
    # Remove only our own previous hook for this event; preserve every other user hook.
    filtered=[]
    for group in hooks.get(event,[]):
        if not isinstance(group,dict):
            filtered.append(group); continue
        kept=[h for h in group.get("hooks",[]) if not (isinstance(h,dict) and marker in str(h.get("description","")))]
        if kept:
            g=dict(group); g["hooks"]=kept; filtered.append(g)
    filtered.append({"matcher":matcher,"hooks":[{"type":"command","command":cmd,"timeout":timeout,"description":marker}]})
    hooks[event]=filtered

def install_settings(ad: Path):
    settings=claude_dir()/"settings.json"
    settings.parent.mkdir(parents=True,exist_ok=True)
    if settings.exists():
        try:
            data=json_load(settings)
        except json.JSONDecodeError as e:
            backup_path(settings)
            raise RuntimeError(f"Existing Claude settings.json is invalid JSON: {e}. Backup created; fix it before retrying.")
    else:
        data={}
    data.setdefault("$schema","https://json.schemastore.org/claude-code-settings.json")
    hooks=data.setdefault("hooks",{})
    put_hook(hooks,"PostToolUse","Edit|Write|MultiEdit",hook_command(ad),"org-ai-appsec-v5",120)
    put_hook(hooks,"PreToolUse","Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Bash|PowerShell|Monitor|mcp__.*",
             hook_command(ad,"agent_guard.py"),"org-ai-agent-guard",20)
    put_hook(hooks,"PostToolUse","Read|WebFetch|mcp__.*",hook_command(ad,"injection_watch.py"),"org-ai-injection-watch",20)
    put_hook(hooks,"Stop","",hook_command(ad,"stop_gate.py"),"org-ai-stop-gate",90)
    perms_file=PKG/"config"/"agent-permissions.json"
    if perms_file.exists():
        # Adds our deny/ask rules; existing user rules are kept (merge appends unique entries).
        data=merge_preserving_list(data,json_load(perms_file))
    backup_path(settings) if settings.exists() else None
    settings.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    return str(settings)

def _task_is_ours(name: str, upd: str, run) -> bool:
    # Only a task whose action runs this app folder's updater.py counts as ours.
    p=run(["schtasks","/Query","/TN",name,"/XML"],capture_output=True)
    return p.returncode==0 and upd.lower() in _xml_text(p.stdout).lower()

def _xml_text(out) -> str:
    # schtasks /XML prints in the console code page (UTF-16 when redirected on some systems), so a path
    # with non-ASCII letters must be decoded the same way before it is compared.
    if isinstance(out,str): text=out
    elif not out: text=""
    elif out[:2] in (b"\xff\xfe",b"\xfe\xff") or b"\x00" in out[:8]: text=out.decode("utf-16",errors="replace")
    else:
        try: text=out.decode("utf-8")
        except UnicodeDecodeError: text=out.decode("mbcs" if os.name=="nt" else "latin-1",errors="replace")
    return text.replace("&quot;",'"').replace("&amp;","&").replace("&apos;","'")

def retire_old_task(ad: Path, new_name: str, upd: str, run) -> str|None:
    """Delete our previous task when the brand name changed, so a re-install never leaves two tasks.
    Candidates: the name recorded in update-task.json and the legacy hard-coded name. A candidate is
    deleted only if it differs from the new name and its action runs this app folder's updater."""
    try:
        recorded=json.loads((ad/TASK_RECORD).read_text(encoding="utf-8")).get("task_name")
    except Exception:
        recorded=None
    done=[]
    # The record is a file in the user's folder: only a well-formed "<valid name> Update" is ever passed to schtasks.
    if not (isinstance(recorded,str) and recorded.endswith(" Update") and valid_product_name(recorded[:-len(" Update")])):
        recorded=None
    for old in dict.fromkeys(x for x in (recorded,LEGACY_TASK_NAME) if isinstance(x,str) and x):
        if old==new_name or not _task_is_ours(old,upd,run):
            continue
        p=run(["schtasks","/Delete","/TN",old,"/F"],capture_output=True,text=True)
        done.append(f"removed old task {old}" if p.returncode==0 else f"could not remove old task {old}")
    return "; ".join(done) or None

def register_updates(ad: Path, run=None):
    # Daily signed auto-update, only when the security team configured a repo and a signing key.
    try:
        cfg=json.loads((ad/"config"/"update.json").read_text(encoding="utf-8-sig"))
        signers=(ad/"config"/"allowed_signers").read_text(encoding="utf-8")
    except Exception:
        return "skipped: no update config"
    if not cfg.get("repo") or "ssh-ed25519" not in signers:
        return "skipped: update repo or signing key not configured"
    upd=str(ad/"scripts"/"updater.py")
    if SYSTEM=="windows":
        pyw=Path(sys.executable).with_name("pythonw.exe")
        py=str(pyw if pyw.exists() else Path(sys.executable))
        tr=f'"{py}" -I "{upd}"'
        if len(tr)>261: return "skipped: task command too long"
        if run is None:
            import subprocess
            run=subprocess.run
        name=update_task_name(ad)
        # /F replaces a task of the same name, so re-running the installer never adds a second one.
        p=run(["schtasks","/Create","/F","/SC","DAILY","/ST","11:00","/TN",name,"/TR",tr],
              capture_output=True,text=True)
        if p.returncode!=0:
            return f"schedule failed: {(p.stderr or '').strip()[:200]}"
        old=retire_old_task(ad,name,upd,run)
        try:
            (ad/TASK_RECORD).write_text(json.dumps({"task_name":name,"updater":upd},ensure_ascii=False)+"\n",encoding="utf-8")
        except OSError:
            pass
        return f"scheduled daily (Task Scheduler: {name})"+(f"; {old}" if old else "")
    return f"add to crontab: 0 11 * * * {sys.executable} -I \"{upd}\""

def tool_status():
    return {x:bool(shutil.which(x)) for x in ["claude","python","git","semgrep","trivy","gitleaks","docker"]}

def verify(ad:Path):
    cd=claude_dir()
    checks={
        "claude_dir":cd.exists(),
        "global_skill":(cd/"skills/org-appsec-security/SKILL.md").exists(),
        "security_gate_command":(cd/"commands/security-gate.md").exists(),
        "sec_review_command":(cd/"commands/sec-review.md").exists(),
        "user_claude_md":(cd/"CLAUDE.md").exists(),
        "user_settings":(cd/"settings.json").exists(),
        "runtime":(ad/"scripts/secgate.py").exists(),
        "global_hook":(ad/"scripts/global_hook.py").exists(),
        "agent_guard":(ad/"scripts/agent_guard.py").exists(),
        "agent_rules":(ad/"AGENTS.md").exists(),
    }
    return checks

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--verify-only",action="store_true")
    args=ap.parse_args()
    cd=claude_dir(); ad=app_dir(); ad.mkdir(parents=True,exist_ok=True)
    if not args.verify_only:
        check_interpreter()
        install_runtime(PKG,ad)   # copies config/brand.json only when the app folder has none
    product=read_product_name(ad)
    report={"version":VERSION,"product_name":product,"os":platform.platform(),"claude_dir":str(cd),"app_dir":str(ad),"tools":tool_status(),"changes":[]}
    try:
        print(f"{product} V{VERSION}")
        print("Claude user scope:",cd)
        print("Runtime:",ad)
    except UnicodeEncodeError:
        print(f"{product.encode('ascii','replace').decode()} V{VERSION}")

    if not args.verify_only:
        report["changes"].append({"skill":install_skill()})
        report["changes"].append({"commands":install_commands()})
        report["changes"].append({"global_CLAUDE_md":install_user_claude_md()})
        report["changes"].append({"settings":install_settings(ad)})
        report["changes"].append({"auto_update":register_updates(ad)})

    report["checks"]=verify(ad)
    report["success"]=all(report["checks"].values())
    rpt=ad/"install-report.json"
    rpt.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))
    return 0 if report["success"] else 1

if __name__=="__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(f"INSTALL FAILED: {e}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""
NexaForge SecureCode (Org AI Secure AppSec Gate), see VERSION below.
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
import argparse, json, os, platform, shutil, stat, sys, time
from pathlib import Path

VERSION="7.1.0"
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

MIN_PYTHON=(3,10)

def check_python_version(version_info=None, exe: str|None=None):
    """Refuse an interpreter older than MIN_PYTHON with a message that says what was found and what to do."""
    vi=tuple((version_info or sys.version_info)[:3])
    if vi[:2]<MIN_PYTHON:
        want=f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"
        raise RuntimeError(
            f"Python {want} or newer is needed, but this is Python {'.'.join(str(x) for x in vi)} ({exe or sys.executable}). "
            f"Install a current Python 3 from https://www.python.org/downloads/ (Windows: winget install Python.Python.3.12, "
            f"or the python.org installer), then run the installer with it, for example: py -3.12 -I install-global.py "
            f"on Windows or python3.12 -I install-global.py on macOS and Linux.")

# ---------- <PY>: the Python that installed SecureCode, written into the skill, commands and rules ----------
# On Windows a bare "python" is often missing or the Microsoft Store alias, so the installed text names the
# exact interpreter, the same one the hooks use.
PY_TOKEN="<PY>"
_UNSAFE_CMD_CHARS=set('"$`%!')

def console_python(exe: str|None=None) -> str:
    # The update task runs pythonw.exe, which has no console; an agent running the gate needs its output.
    p=Path(exe or sys.executable)
    if p.name.lower()=="pythonw.exe" and p.with_name("python.exe").is_file():
        return str(p.with_name("python.exe"))
    return str(p)

def cmd_path(p, system: str|None=None) -> str:
    """A path for a double-quoted command line that works in bash, PowerShell and cmd: forward slashes on Windows,
    and refused (ValueError) when it holds a quote, $, backtick, %, ! or a control character."""
    s=str(p)
    if (system or SYSTEM)=="windows":
        s=s.replace("\\","/")
    elif "\\" in s:
        raise ValueError(f"path holds a backslash: {s!r}")
    if not s or any(c in _UNSAFE_CMD_CHARS or ord(c)<32 or ord(c)==127 for c in s):
        raise ValueError(f"path holds a quote, $, backtick, %, ! or a control character: {s!r}")
    return s

def py_command(exe: str|None=None) -> str:
    """What replaces <PY>: the quoted interpreter plus -I. Falls back to the launcher name when the path cannot be
    quoted safely (the text then still works on a normal machine)."""
    try:
        return f'"{cmd_path(console_python(exe))}" -I'
    except ValueError:
        return "py -3 -I" if SYSTEM=="windows" else "python3 -I"

def fill_tokens(text: str, exe: str|None=None) -> str:
    return text.replace(PY_TOKEN,py_command(exe))

def fill_tokens_in_file(f: Path, exe: str|None=None) -> bool:
    if f.is_symlink() or not f.is_file():
        return False
    b=f.read_bytes()   # bytes, so the file keeps its own line endings
    tok=PY_TOKEN.encode("ascii")
    if tok not in b:
        return False
    f.write_bytes(b.replace(tok,py_command(exe).encode("utf-8")))
    return True

def fill_tokens_in_tree(root: Path, exe: str|None=None) -> int:
    """Replace <PY> in every Markdown file under root (an installed skill or command folder)."""
    return sum(fill_tokens_in_file(f,exe) for f in Path(root).rglob("*.md"))

def install_file(src: Path, dst: Path, overwrite=True):
    dst.parent.mkdir(parents=True,exist_ok=True)
    existed=dst.exists()   # recorded before the copy, or a fresh install would always report "updated"
    if existed and overwrite:
        backup_path(dst)
    if overwrite or not existed:
        shutil.copy2(src,dst)
        if dst.suffix==".md":
            fill_tokens_in_file(dst)
        return "updated" if existed else "created"
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
        fill_tokens_in_file(ad/"AGENTS.md")

def install_skill():
    src=PKG/".claude/skills/security-review"
    dst=claude_dir()/"skills"/"org-appsec-security"
    if not src.exists(): raise RuntimeError("Security skill is missing from package")
    n=copy_tree(src,dst)
    fill_tokens_in_tree(dst)   # every run, so an update (which re-runs this installer) fills the new text too
    return n

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
    newblock=fill_tokens(src.read_text(encoding="utf-8").strip())
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
    check_python_version()
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

# Tools whose output can carry a secret into the model: shell output, file reads, search hits, web pages, MCP.
SHIELD_MATCHER="Bash|BashOutput|PowerShell|Read|Grep|WebFetch|mcp__.*"

GUARD_MODES=("owner","managed")
POLICY_NAME="guard-policy.json"
# Claude Code permission rules that deny what owner mode turns into an "ask" (deny beats every hook "ask",
# so in owner mode they move to the ask list; in managed mode they stay in deny).
OWNER_ASK_RULES=["Bash(git push --force*)","Bash(git push -f*)","Bash(git reset --hard*)"]

def read_guard_mode(ad: Path):
    """The mode in <app>/config/guard-policy.json, or None when missing or not a valid policy."""
    try:
        f=Path(ad)/"config"/POLICY_NAME
        if f.is_symlink() or f.stat().st_size>4096: return None
        data=json.loads(f.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return data.get("mode") if isinstance(data,dict) and data.get("mode") in GUARD_MODES else None

def install_guard_policy(ad: Path, mode: str|None=None) -> str:
    """Per-user installs default to owner mode. A valid existing policy is kept unless --guard-mode is given,
    so an organization that set "managed" for a user is not undone by an update."""
    if mode is not None and mode not in GUARD_MODES:
        raise RuntimeError(f"--guard-mode must be one of {', '.join(GUARD_MODES)}")
    current=read_guard_mode(ad)
    if mode is None and current:
        return current
    mode=mode or "owner"
    f=Path(ad)/"config"/POLICY_NAME
    f.parent.mkdir(parents=True,exist_ok=True)
    keep={}
    if mode=="owner" and current=="owner":
        # the owner's own "command guard off" setting (scripts/guard_switch.py) survives a repair or a re-run, but only
        # from a policy that passes the guard's own strict checks (plain file, small, no duplicate or unknown keys)
        try:
            st=os.lstat(f)
            if stat.S_ISREG(st.st_mode) and not getattr(st,"st_file_attributes",0)&0x400 and st.st_size<=4096:
                def _nodupes(pairs):
                    if len({k for k,_ in pairs})!=len(pairs): raise ValueError("duplicate key")
                    return dict(pairs)
                old=json.loads(f.read_text(encoding="utf-8-sig"),object_pairs_hook=_nodupes)
                if set(old)<={"mode","version","note","guard"} and old.get("mode")=="owner" and old.get("guard")=="off":
                    keep={"guard":"off","note":str(old.get("note",""))[:200]}
        except Exception:
            keep={}
    if f.is_symlink(): f.unlink()
    f.write_text(json.dumps({"mode":mode,"version":1,**keep},indent=2)+"\n",encoding="utf-8")
    return mode

def align_permissions(data: dict, mode: str) -> dict:
    """Owner mode: the force-push and hard-reset rules move from deny to ask, or the guard's ask could never be
    reached. Managed mode: they stay in deny (and are added there if missing)."""
    perms=data.setdefault("permissions",{})
    deny=list(perms.get("deny",[])) if isinstance(perms.get("deny"),list) else []
    ask=list(perms.get("ask",[])) if isinstance(perms.get("ask"),list) else []
    if mode=="owner":
        deny=[x for x in deny if x not in OWNER_ASK_RULES]
        ask+=[x for x in OWNER_ASK_RULES if x not in ask]
    else:
        deny+=[x for x in OWNER_ASK_RULES if x not in deny]
    perms["deny"]=deny; perms["ask"]=ask
    return data

def install_settings(ad: Path, mode: str="managed"):
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
    # Every tool goes through the guard (7.0): an allowlist matcher let new tools (Artifact and others) skip it.
    put_hook(hooks,"PreToolUse",".*",
             hook_command(ad,"agent_guard.py"),"org-ai-agent-guard",20)
    put_hook(hooks,"PostToolUse","Read|WebFetch|mcp__.*",hook_command(ad,"injection_watch.py"),"org-ai-injection-watch",20)
    # 7.0 secret shield: replaces secret values in tool output before the model sees them (updatedToolOutput).
    put_hook(hooks,"PostToolUse",SHIELD_MATCHER,hook_command(ad,"secret_shield.py"),"org-ai-secret-shield",20)
    put_hook(hooks,"Stop","",hook_command(ad,"stop_gate.py"),"org-ai-stop-gate",90)
    perms_file=PKG/"config"/"agent-permissions.json"
    if perms_file.exists():
        # Adds our deny/ask rules; existing user rules are kept (merge appends unique entries).
        data=merge_preserving_list(data,json_load(perms_file))
    data=align_permissions(data,mode)
    backup_path(settings) if settings.exists() else None
    settings.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    return str(settings)

def schtasks_exe() -> str:
    # The system copy by absolute path: a bare "schtasks" is looked up in the current folder first on Windows.
    root=os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    exe=os.path.join(root,"System32","schtasks.exe")
    return exe if os.path.isabs(exe) and os.path.isfile(exe) else "schtasks"

def _task_is_ours(name: str, upd: str, run) -> bool:
    # Only a task whose action runs this app folder's updater.py counts as ours.
    p=run([schtasks_exe(),"/Query","/TN",name,"/XML"],capture_output=True)
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
    return text.replace("&quot;",'"').replace("&apos;","'").replace("&lt;","<").replace("&gt;",">").replace("&amp;","&")

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
        p=run([schtasks_exe(),"/Delete","/TN",old,"/F"],capture_output=True,text=True)
        done.append(f"removed old task {old}" if p.returncode==0 else f"could not remove old task {old}")
    return "; ".join(done) or None

# ---------- update schedule ----------
# The update check runs daily at 11:00 local time. Laptops are often off or asleep then, so every scheduler
# also catches up: Task Scheduler with StartWhenAvailable and a logon trigger, systemd with Persistent=true,
# launchd with RunAtLoad. The updater itself takes a lock, so overlapping runs are harmless.
UPDATE_HOUR=11

def _plain(v: str, what: str, limit: int=1024) -> str:
    # Paths and the user name go into XML, unit files and plists: no control characters, bounded length.
    v=str(v)
    if not v or len(v)>limit or any(ord(c)<32 or ord(c)==127 or c in "  \x85" for c in v):
        raise ValueError(f"{what} is empty, too long or holds a control character")
    return v

def _xml(v: str) -> str:
    from xml.sax.saxutils import escape
    return escape(v,{'"':"&quot;","'":"&apos;"})

def windows_user() -> str|None:
    dom,user=os.environ.get("USERDOMAIN",""),os.environ.get("USERNAME","")
    if not user: return None
    try:
        return _plain(f"{dom}\\{user}" if dom else user,"user name",256)
    except ValueError:
        return None

def windows_task_xml(py: str, upd: str, user: str|None, product: str) -> str:
    """Task Scheduler definition: daily at 11:00 with up to 30 minutes random delay, at logon (10 minutes later,
    the logon trigger has no random delay in the schema), as soon as possible after a missed start, only with a
    network, at most one hour per run, and up to 3 restarts 30 minutes apart when the task fails to start.
    Runs as the installing user without a stored password and with least privilege."""
    py=_plain(py,"Python path",259); upd=_plain(upd,"updater path",1000)
    uid=f"<UserId>{_xml(user)}</UserId>" if user else ""
    logon=(f"<LogonTrigger><Enabled>true</Enabled>{uid}<Delay>PT10M</Delay></LogonTrigger>" if user else "")
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{_xml(product)}: daily signed update check (scripts/updater.py)</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T{UPDATE_HOUR:02d}:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>PT30M</RandomDelay>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
    {logon}
  </Triggers>
  <Principals>
    <Principal id="Author">
      {uid}
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT30M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{_xml(py)}</Command>
      <Arguments>{_xml(f'-I "{upd}"')}</Arguments>
    </Exec>
  </Actions>
</Task>
"""

def unit_slug(ad: Path) -> str:
    # systemd unit and launchd label part: ASCII letters, digits and dashes only, from the brand name.
    import re
    s=re.sub(r"[^a-z0-9]+","-",read_product_name(ad).lower()).strip("-")[:40].strip("-")
    return s or "nexaforge-securecode"

def _systemd_quote(v: str) -> str:
    # systemd splits ExecStart on spaces and honours "..." with C-style escapes; % starts a specifier.
    return '"'+v.replace("\\","\\\\").replace('"','\\"').replace("%","%%").replace("$","$$")+'"'

def systemd_units(py: str, upd: str, product: str) -> tuple[str,str]:
    py=_plain(py,"Python path"); upd=_plain(upd,"updater path")
    desc=product.replace("%","%%")
    service=(f"[Unit]\nDescription={desc} signed update check\n\n"
             f"[Service]\nType=oneshot\nExecStart={_systemd_quote(py)} -I {_systemd_quote(upd)}\n"
             "TimeoutStartSec=1h\nNice=10\n")
    timer=(f"[Unit]\nDescription={desc} daily signed update check\n\n"
           f"[Timer]\nOnCalendar=*-*-* {UPDATE_HOUR:02d}:00:00\nRandomizedDelaySec=30min\nPersistent=true\n"
           "OnStartupSec=10min\n\n[Install]\nWantedBy=timers.target\n")
    return service,timer

def launchd_plist(label: str, py: str, upd: str) -> bytes:
    import plistlib
    py=_plain(py,"Python path"); upd=_plain(upd,"updater path")
    return plistlib.dumps({"Label":label,"ProgramArguments":[py,"-I",upd],"RunAtLoad":True,
                           "StartCalendarInterval":{"Hour":UPDATE_HOUR,"Minute":0},"ProcessType":"Background",
                           "LowPriorityIO":True})

def schedule_paths(ad: Path) -> dict:
    slug=unit_slug(ad)
    if SYSTEM=="darwin":
        label=f"eu.nexaforge.{slug}.update"
        return {"kind":"launchd","label":label,"plist":HOME/"Library"/"LaunchAgents"/f"{label}.plist"}
    base=Path(os.environ.get("XDG_CONFIG_HOME") or HOME/".config")/"systemd"/"user"
    unit=f"{slug}-update"
    return {"kind":"systemd","unit":unit,"service":base/f"{unit}.service","timer":base/f"{unit}.timer"}

def _tool(name: str):
    exe=shutil.which(name)
    return exe if exe and os.path.isabs(exe) else None

def register_unix_schedule(ad: Path, upd: str, run, install: bool) -> str:
    cron=f"add to crontab: 0 {UPDATE_HOUR} * * * \"{sys.executable}\" -I \"{upd}\""
    sp=schedule_paths(ad)
    ours=[sp["plist"]] if sp["kind"]=="launchd" else [sp["service"],sp["timer"]]
    # An update re-runs this installer without flags: a timer or agent we wrote before is refreshed, never dropped.
    if not install and not any(p.exists() for p in ours):
        flag=" (or re-run with --update-timer for a "+("launchd agent" if sp["kind"]=="launchd" else "systemd user timer")+" that catches up missed runs)"
        return cron+flag
    try:
        if sp["kind"]=="launchd":
            data=launchd_plist(sp["label"],sys.executable,upd)
        else:
            service,timer=systemd_units(sys.executable,upd,read_product_name(ad))
    except ValueError as e:
        return f"schedule skipped: {e}; {cron}"
    if run is None:
        import subprocess
        run=subprocess.run
    for p in ours:
        if p.is_symlink(): return f"schedule skipped: {p} is a link; {cron}"
    if sp["kind"]=="launchd":
        sp["plist"].parent.mkdir(parents=True,exist_ok=True)
        sp["plist"].write_bytes(data)
        lc=_tool("launchctl")
        if not lc: return f"launchd agent written to {sp['plist']} but launchctl was not found; {cron}"
        dom=f"gui/{os.getuid()}"
        # An update runs this installer as a child of the launchd job itself: booting that job out would kill the
        # update half way. A loaded agent is left running; launchd reads the rewritten plist at the next login.
        if run([lc,"print",f"{dom}/{sp['label']}"],capture_output=True,text=True).returncode==0:
            return f"scheduled daily (launchd agent {sp['label']}: {UPDATE_HOUR}:00 and at login; already loaded)"
        p=run([lc,"bootstrap",dom,str(sp["plist"])],capture_output=True,text=True)
        if p.returncode!=0:
            return f"launchd agent written but launchctl bootstrap failed: {(p.stderr or '').strip()[:200]}; {cron}"
        return f"scheduled daily (launchd agent {sp['label']}: {UPDATE_HOUR}:00 and at login)"
    sp["service"].parent.mkdir(parents=True,exist_ok=True)
    sp["service"].write_text(service,encoding="utf-8")
    sp["timer"].write_text(timer,encoding="utf-8")
    sc=_tool("systemctl")
    if not sc: return f"systemd user timer written to {sp['timer']} but systemctl was not found; {cron}"
    for args in (["--user","daemon-reload"],["--user","enable","--now",f"{sp['unit']}.timer"]):
        p=run([sc,*args],capture_output=True,text=True)
        if p.returncode!=0:
            return f"systemd user timer written but systemctl {' '.join(args)} failed: {(p.stderr or '').strip()[:200]}; {cron}"
    return f"scheduled daily (systemd user timer {sp['unit']}.timer, Persistent=true)"

UPDATE_OFF="no-update-task.json"   # in the app folder: written by --no-update-task, removed by --update-task

def update_task_off(ad: Path) -> bool:
    f=Path(ad)/UPDATE_OFF
    return f.is_file() and not f.is_symlink()

def set_update_task_off(ad: Path, off: bool):
    f=Path(ad)/UPDATE_OFF
    if f.is_symlink() or (f.exists() and not off):
        f.unlink()
    if off:
        f.write_text(json.dumps({"update_task":"off","how_to_turn_on":"run install-global.py --update-task"})+"\n",encoding="utf-8")

# Result prefixes of register_updates() that mean the schedule was wanted but not set up. ("... written ... but
# launchctl/systemctl ..." is only ever returned when that tool was missing or failed.) Prefixes, not substrings,
# so a product name in a success line can never turn it into a failure.
AUTO_UPDATE_BAD=("schedule failed","schedule skipped","launchd agent written","systemd user timer written")

def auto_update_ok(result: str|None) -> bool:
    """False when the daily update schedule was wanted but could not be set up. Not configured or turned off
    on purpose (--no-update-task) is fine."""
    return not (isinstance(result,str) and result.startswith(AUTO_UPDATE_BAD))

def register_updates(ad: Path, run=None, timer: bool=False):
    # Daily signed auto-update, only when the security team configured a repo and a signing key.
    if update_task_off(ad):
        return "skipped: update task turned off (--no-update-task); run the updater by hand or re-run with --update-task"
    try:
        cfg=json.loads((ad/"config"/"update.json").read_text(encoding="utf-8-sig"))
        signers=(ad/"config"/"allowed_signers").read_text(encoding="utf-8")
    except Exception:
        return "skipped: no update config"
    if not cfg.get("repo") or "ssh-ed25519" not in signers:
        return "skipped: update repo or signing key not configured"
    upd=str(ad/"scripts"/"updater.py")
    if SYSTEM!="windows":
        return register_unix_schedule(ad,upd,run,timer)
    pyw=Path(sys.executable).with_name("pythonw.exe")
    py=str(pyw if pyw.exists() else Path(sys.executable))
    name=update_task_name(ad)
    try:
        xml=windows_task_xml(py,upd,windows_user(),read_product_name(ad))
    except ValueError as e:
        return f"schedule skipped: {e}"
    if run is None:
        import subprocess
        run=subprocess.run
    import tempfile
    tmpd=Path(tempfile.mkdtemp(prefix="nfsc-task-"))
    try:
        xf=tmpd/"task.xml"
        xf.write_text(xml,encoding="utf-16")   # schtasks /XML expects UTF-16 with a byte order mark
        # /F replaces a task of the same name, so re-running the installer never adds a second one.
        p=run([schtasks_exe(),"/Create","/F","/TN",name,"/XML",str(xf)],capture_output=True,text=True)
    finally:
        shutil.rmtree(tmpd,ignore_errors=True)
    if p.returncode!=0:
        return f"schedule failed: {(p.stderr or '').strip()[:200]}"
    old=retire_old_task(ad,name,upd,run)
    try:
        (ad/TASK_RECORD).write_text(json.dumps({"task_name":name,"updater":upd},ensure_ascii=False)+"\n",encoding="utf-8")
    except OSError:
        pass
    return f"scheduled daily (Task Scheduler: {name})"+(f"; {old}" if old else "")

# ---------- guard hooks for other AI agents: install-global.py --agent cursor|codex|gemini|antigravity ----------
AGENT_NAMES=("cursor","codex","gemini","antigravity")
AGENT_TEMPLATES={"cursor":"cursor/hooks.json","codex":"codex/hooks.json",
                 "gemini":"gemini/settings.hooks.json","antigravity":"antigravity/hooks.json"}
AGENT_NEXT={"cursor":"restart Cursor; keep \"failClosed\": true",
            "codex":"open Codex and trust the hooks in /hooks (Codex skips untrusted hooks)",
            "gemini":"restart Gemini CLI and check with /hooks",
            "antigravity":"restart Antigravity and check with /hooks"}
AGENT_RECORD="agent-adapters.json"   # in the app folder: adapters this installer wrote, refreshed by later runs
AGENT_MAX_BYTES=5_000_000

def agent_config_path(agent: str, home: Path|None=None) -> Path:
    """Where each tool reads its user-level hook config (docs/AI-AGENT-SECURITY.md)."""
    h=Path(home) if home is not None else HOME
    if agent=="cursor": return h/".cursor"/"hooks.json"
    if agent=="codex":
        ch=os.environ.get("CODEX_HOME")
        return (Path(ch).expanduser() if ch and os.path.isabs(os.path.expanduser(ch)) else h/".codex")/"hooks.json"
    if agent=="gemini": return h/".gemini"/"settings.json"
    if agent=="antigravity": return h/".gemini"/"config"/"hooks.json"
    raise ValueError(f"unknown agent {agent!r}; choose one of {', '.join(AGENT_NAMES)}")

def _is_ours(cmd) -> bool:
    # Our hook commands always run a script from the OrgAISecureAppSec runtime folder.
    return isinstance(cmd,str) and "/OrgAISecureAppSec/scripts/" in cmd.replace("\\","/")

import re as _re
_UNQUOTED_PY=_re.compile(r'(?<!")<PYTHON>')

def _fill(obj, py: str, app: str, bare_py=None):
    """<PYTHON> inside double quotes gets py; an unquoted <PYTHON> (a Windows line that must run in PowerShell, cmd
    and bash alike, V7L-02) gets bare_py(), which is only computed when such a line exists."""
    if isinstance(obj,dict): return {k:_fill(v,py,app,bare_py) for k,v in obj.items()}
    if isinstance(obj,list): return [_fill(v,py,app,bare_py) for v in obj]
    if isinstance(obj,str):
        if bare_py is not None and _UNQUOTED_PY.search(obj):
            obj=_UNQUOTED_PY.sub(lambda m: bare_py(),obj)
        return obj.replace("<PYTHON>",py).replace("<APP>",app)
    return obj

def _get_short_path_name(path: str) -> str:
    """Windows 8.3 short form of an existing path ("" when there is none, e.g. 8.3 names are off on that drive)."""
    try:
        import ctypes
        buf=ctypes.create_unicode_buffer(32768)
        n=ctypes.windll.kernel32.GetShortPathNameW(str(path),buf,32768)
        return buf.value if 0<n<32768 else ""
    except Exception:
        return ""

def _bare_ok(s: str) -> bool:
    # An unquoted first word has to mean the same in PowerShell, cmd and bash: letters and digits (any script) and
    # _ . ~ - / : only. No space, & ^ % " and nothing else a shell treats as syntax.
    return bool(s) and all(c.isalnum() or c in "_.~-/:" for c in s) and not s.startswith(("-","~"))

def bare_python(exe: str|None=None, get_short=None) -> str:
    """The Python path for an unquoted Windows hook line: forward slashes, the 8.3 short form when the real path has
    a space or another special character. RuntimeError, never a broken line, when no such form exists."""
    real=console_python(exe)
    cand=real.replace("\\","/")
    if not _bare_ok(cand):
        short=(get_short or _get_short_path_name)(real)
        cand=short.replace("\\","/") if short else ""
    if not _bare_ok(cand):
        raise RuntimeError(
            f"this tool runs the hook line on Windows without quotes, so the Python path must have no spaces and none of "
            f"& ^ % \" or other special characters, and Windows gave no usable short (8.3) name for {real} (short names "
            f"can be turned off for a drive; 'fsutil 8dot3name query C:' shows it). Install Python to a folder without "
            f"spaces, for example C:\\Python312, and run the installer with that Python. Nothing was written.")
    return cand

def agent_template_file(agent: str, pkg: Path|None=None, system: str|None=None) -> Path:
    """The template for this OS. On Windows a "<name>.windows.json" next to the template wins when it exists:
    some tools run hook commands in PowerShell there, where a line starting with a quoted path needs "&" (V7L-01).
    Fields such as "commandWindows" inside a template are filled like every other string."""
    base=(pkg or PKG)/"templates"/AGENT_TEMPLATES[agent]
    win=base.with_name(base.stem+".windows.json")
    return win if (system or SYSTEM)=="windows" and win.is_file() else base

def agent_template(agent: str, ad: Path, exe: str|None=None, pkg: Path|None=None, get_short=None) -> dict:
    """The tool's template with <PYTHON> and <APP> filled in. Paths use forward slashes and are refused when they
    hold characters a shell would expand inside double quotes. On Windows an unquoted <PYTHON> (Codex's
    commandWindows, Antigravity's hooks.windows.json) gets the space-free 8.3 form, or the adapter is refused."""
    tpl=json.loads(agent_template_file(agent,pkg).read_text(encoding="utf-8-sig"))
    tpl.pop("description",None)   # a how-to-fill-in note for people, not a setting
    try:
        py=cmd_path(console_python(exe)); app=cmd_path(Path(ad))
    except ValueError as e:
        raise RuntimeError(f"cannot write the {agent} hook: {e}. Install Python and SecureCode under a plain path, "
                           "or fill in the template by hand (docs/AI-AGENT-SECURITY.md).")
    if SYSTEM=="windows":
        def bare():
            try:
                return bare_python(exe,get_short)
            except RuntimeError as e:
                raise RuntimeError(f"cannot write the {agent} hook: {e}") from None
    else:
        bare=lambda: py   # commandWindows is not used off Windows; the quoted-safe path keeps the file readable
    return _fill(tpl,py,app,bare)

def _strip_ours(items: list) -> list:
    out=[]
    for it in items:
        if isinstance(it,dict) and isinstance(it.get("hooks"),list):        # Claude-style group: {matcher, hooks:[...]}
            kept=[h for h in it["hooks"] if not (isinstance(h,dict) and _is_ours(h.get("command")))]
            if kept or not it["hooks"]:
                g=dict(it); g["hooks"]=kept; out.append(g)
        elif isinstance(it,dict) and _is_ours(it.get("command")):           # Cursor-style flat entry
            continue
        else:
            out.append(it)
    return out

def merge_agent_config(existing: dict, filled: dict, where: str="the file") -> dict:
    """Our entries replace our earlier ones; every other key, event and hook in the file stays as it was."""
    out=dict(existing)
    for k,v in filled.items():
        if k=="hooks":
            cur=out.get("hooks",{})
            if not isinstance(cur,dict):
                raise RuntimeError(f"\"hooks\" in {where} is not a JSON object; nothing was changed. Fix it and run again.")
            cur=dict(cur)
            for ev,items in v.items():
                old=cur.get(ev,[])
                if not isinstance(old,list):
                    raise RuntimeError(f"\"hooks.{ev}\" in {where} is not a JSON list; nothing was changed. Fix it and run again.")
                cur[ev]=_strip_ours(old)+items
            out["hooks"]=cur
        elif k.startswith("org-ai-"):
            out[k]=v                     # a block that is ours by name (Antigravity)
        else:
            out.setdefault(k,v)          # e.g. Cursor's "version": never overrides the user's value
    return out

def read_json_object(path: Path) -> dict:
    if path.is_symlink():
        raise RuntimeError(f"{path} is a link; refusing to write through it. Nothing was changed.")
    if not path.exists():
        return {}
    if not path.is_file():
        raise RuntimeError(f"{path} is not a file. Nothing was changed.")
    if path.stat().st_size>AGENT_MAX_BYTES:
        raise RuntimeError(f"{path} is larger than {AGENT_MAX_BYTES} bytes. Nothing was changed.")
    raw=path.read_text(encoding="utf-8-sig")
    if not raw.strip():
        return {}
    try:
        data=json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{path} is not valid JSON ({e.msg}, line {e.lineno} column {e.colno}). Nothing was changed. "
                           "Fix the file (comments are not allowed) or move it away, then run again.")
    if not isinstance(data,dict):
        raise RuntimeError(f"{path} does not hold a JSON object. Nothing was changed.")
    return data

def _agent_backup(path: Path, ad: Path, agent: str) -> str:
    # Own name per agent: Cursor, Codex and Antigravity all use "hooks.json", and backup_path() keys on the name only.
    d=Path(ad)/"backups"/time.strftime("%Y%m%d-%H%M%S"); d.mkdir(parents=True,exist_ok=True)
    dest=d/f"{agent}-{path.name}"; n=1
    while dest.exists():
        n+=1; dest=d/f"{agent}-{n}-{path.name}"
    shutil.copy2(path,dest)
    return str(dest)

def read_agent_record(ad: Path) -> list:
    try:
        f=Path(ad)/AGENT_RECORD
        if f.is_symlink() or f.stat().st_size>4096: return []
        got=json.loads(f.read_text(encoding="utf-8")).get("agents",[])
    except Exception:
        return []
    return [a for a in AGENT_NAMES if isinstance(got,list) and a in got]

def _record_agent(ad: Path, agent: str):
    have=read_agent_record(ad)
    if agent not in have:
        f=Path(ad)/AGENT_RECORD
        if f.is_symlink(): f.unlink()
        f.write_text(json.dumps({"agents":[a for a in AGENT_NAMES if a in have+[agent]]})+"\n",encoding="utf-8")

def has_our_hook(data) -> bool:
    if isinstance(data,dict): return any(has_our_hook(v) for v in data.values())
    if isinstance(data,list): return any(has_our_hook(v) for v in data)
    return _is_ours(data)

def install_agent(agent: str, ad: Path, home: Path|None=None, exe: str|None=None, pkg: Path|None=None,
                  refresh_only: bool=False) -> str:
    """Write or refresh one tool's guard hook config. Backs up an existing file, merges into it (other settings and
    hooks are kept), refuses a file that is not valid JSON, and writes nothing when the result is unchanged."""
    if agent not in AGENT_NAMES:
        raise RuntimeError(f"unknown agent {agent!r}; choose one of {', '.join(AGENT_NAMES)}")
    target=agent_config_path(agent,home)
    existing=read_json_object(target)
    if refresh_only and not has_our_hook(existing):
        return f"{agent}: {target} no longer has our hook; left as it is"
    filled=agent_template(agent,ad,exe,pkg)
    merged=merge_agent_config(existing,filled,str(target))
    _record_agent(ad,agent)
    if target.exists() and merged==existing:
        return f"{agent}: {target} already up to date"
    bak=_agent_backup(target,ad,agent) if target.exists() else None
    target.parent.mkdir(parents=True,exist_ok=True)
    tmp=target.with_name(target.name+".nfsc-tmp")
    if tmp.exists() or tmp.is_symlink(): tmp.unlink()
    tmp.write_text(json.dumps(merged,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    os.replace(tmp,target)
    return (f"{agent}: wrote {target}" + (f" (backup: {bak})" if bak else " (new file)") + f"; next: {AGENT_NEXT[agent]}")

def install_agents(ad: Path, wanted, home: Path|None=None) -> list:
    """Agents named with --agent, plus a refresh of the ones an earlier run wrote (so an update brings new template
    changes). A refresh never re-adds a hook the user removed and never fails the install."""
    out=[]
    wanted=[a for a in AGENT_NAMES if a in (wanted or [])]
    for a in wanted:
        try:
            out.append(install_agent(a,ad,home))
        except (RuntimeError,OSError) as e:
            out.append(f"FAILED {a}: {e}")
    for a in read_agent_record(ad):
        if a in wanted: continue
        try:
            out.append(install_agent(a,ad,home,refresh_only=True))
        except (RuntimeError,OSError) as e:
            out.append(f"{a}: refresh skipped: {e}")
    return out

def adapter_status(home: Path|None=None) -> dict:
    """For each other AI tool: the config file path when it holds our guard hook, else None."""
    res={}
    for a in AGENT_NAMES:
        p=agent_config_path(a,home)
        try:
            res[a]=str(p) if has_our_hook(read_json_object(p)) else None
        except RuntimeError:
            res[a]=None
    return res

def tool_status():
    return {x:bool(shutil.which(x)) for x in ["claude","python","git","semgrep","trivy","gitleaks","docker"]}

def verify(ad:Path, auto_update: str|None=None):
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
        "guard_policy":read_guard_mode(ad) is not None,
    }
    if auto_update is not None:
        # A schedule that was wanted but failed (schtasks, systemctl, launchctl) is a failed check, not a footnote.
        checks["auto_update"]=auto_update_ok(auto_update)
    return checks

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument("--verify-only",action="store_true")
    ap.add_argument("--guard-mode",choices=GUARD_MODES,
                    help="owner (default for a new per-user install): force push, hard reset, public repo and publish ask "
                         "with the exact command; managed: they are denied. An existing policy is kept unless this is given.")
    ap.add_argument("--update-timer",action="store_true",
                    help="macOS and Linux: install a launchd agent or a systemd user timer for the daily signed update "
                         "check (catches up missed runs) instead of only printing a crontab line. Windows always uses "
                         "Task Scheduler.")
    task=ap.add_mutually_exclusive_group()
    task.add_argument("--no-update-task",action="store_true",
                      help="do not create the daily update task, timer or agent (remembered for later runs; an existing "
                           "task is not removed, see ENTERPRISE_DEPLOYMENT.md). Update by hand with scripts/updater.py.")
    task.add_argument("--update-task",action="store_true",help="turn the daily update task back on after --no-update-task")
    ap.add_argument("--agent",action="append",choices=AGENT_NAMES,
                    help="also write the guard hook config for this AI tool (repeatable): Cursor ~/.cursor/hooks.json, "
                         "Codex ~/.codex/hooks.json, Gemini CLI ~/.gemini/settings.json, Antigravity "
                         "~/.gemini/config/hooks.json. Existing files are backed up and merged, never replaced.")
    args=ap.parse_args(argv)
    check_python_version()
    if args.verify_only and (args.agent or args.no_update_task or args.update_task):
        ap.error("--verify-only changes nothing; leave out --agent, --no-update-task and --update-task")
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
        mode=install_guard_policy(ad,args.guard_mode)
        report["changes"].append({"guard_mode":mode})
        report["changes"].append({"settings":install_settings(ad,mode)})
        if args.no_update_task or args.update_task:
            set_update_task_off(ad,args.no_update_task)
        auto=register_updates(ad,timer=args.update_timer)
        report["changes"].append({"auto_update":auto})
        agents=install_agents(ad,args.agent)
        if agents:
            report["changes"].append({"agents":agents})
            for line in agents:
                try: print(line)
                except UnicodeEncodeError: print(line.encode("ascii","replace").decode())
    else:
        auto,agents=None,[]

    report["checks"]=verify(ad,auto)
    if auto is not None and not report["checks"]["auto_update"]:
        print(f"WARNING: the daily update task was not set up ({auto}). Updates will not arrive by themselves; "
              "fix the cause and run the installer again, or update by hand with scripts/updater.py.", file=sys.stderr)
    report["success"]=all(report["checks"].values()) and not any(x.startswith("FAILED") for x in agents)
    rpt=ad/"install-report.json"
    rpt.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))
    return exit_code(report["checks"],agents)

EXIT_SCHEDULE_ONLY=4   # everything installed, only the daily update task failed (scripts/updater.py knows this code)

def exit_code(checks: dict, agents=()) -> int:
    """0 all good; 4 when the only failure is the update schedule (the updater then reports "updated" with a schedule
    warning instead of "install-failed"); 1 for anything else."""
    others=all(v for k,v in checks.items() if k!="auto_update") and not any(x.startswith("FAILED") for x in agents)
    if others and checks.get("auto_update",True):
        return 0
    return EXIT_SCHEDULE_ONLY if others else 1

if __name__=="__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(f"INSTALL FAILED: {e}", file=sys.stderr)
        raise SystemExit(1)

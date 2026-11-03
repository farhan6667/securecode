#!/usr/bin/env python3
import os, platform, json, re, shutil, subprocess, sys, time
from pathlib import Path
home=Path.home()
cd=Path(os.environ.get("CLAUDE_CONFIG_DIR",home/".claude"))
if platform.system()=="Windows":
    ad=Path(os.environ.get("LOCALAPPDATA",home/"AppData/Local"))/"OrgAISecureAppSec"
elif platform.system()=="Darwin":
    ad=home/"Library/Application Support/OrgAISecureAppSec"
else:
    ad=Path(os.environ.get("XDG_DATA_HOME",home/".local/share"))/"OrgAISecureAppSec"

def product_name(app):
    # Same rules as install-global.py (brand overlay in <app>/config/brand.json), loaded from the package
    # next to this script; the default name if that module is missing.
    try:
        import importlib.util
        spec=importlib.util.spec_from_file_location("orginstall_brand",Path(__file__).resolve().parent/"install-global.py")
        g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
        return g.read_product_name(app)
    except Exception:
        return "NexaForge SecureCode"

def hooks_with(marker):
    try:
        data=json.loads((cd/"settings.json").read_text(encoding="utf-8"))
    except Exception:
        return False
    return marker in json.dumps(data.get("hooks",{}))

def version(cmd):
    exe=shutil.which(cmd[0])
    if not exe: return None
    try:
        out=subprocess.run([exe,*cmd[1:]],capture_output=True,text=True,timeout=60,encoding="utf-8",errors="replace")
        m=re.search(r"\d+\.\d+\.\d+",out.stdout+out.stderr)
        return m.group(0) if m else "unknown"
    except Exception:
        return "unknown"

def hook_cmd(marker):
    try:
        data=json.loads((cd/"settings.json").read_text(encoding="utf-8"))
        for groups in data.get("hooks",{}).values():
            for g in groups:
                for h in g.get("hooks",[]):
                    if marker in str(h.get("description","")): return h.get("command")
    except Exception:
        return None

def guard_really_works():
    # Run the installed guard command the way Claude Code does (through a shell) on two events.
    cmd=hook_cmd("org-ai-agent-guard")
    if not cmd: return False
    if platform.system()=="Windows":
        # Claude Code runs hooks with Git Bash; System32\bash.exe is WSL and cannot run Windows paths.
        cands=[os.path.join(os.environ.get(v,""),"Git","bin","bash.exe") for v in ("ProgramFiles","ProgramFiles(x86)","LOCALAPPDATA")]
        cands.append(shutil.which("bash") or "")
        sh=next((c for c in cands if c and os.path.exists(c) and "system32" not in c.lower()),None)
    else:
        sh="/bin/sh"
    runner=[sh,"-c",cmd] if sh else cmd
    def rc(ev):
        try:
            return subprocess.run(runner,input=json.dumps(ev),text=True,capture_output=True,timeout=30,shell=not sh).returncode
        except Exception:
            return None
    ok=rc({"tool_name":"Read","tool_input":{"file_path":"README.md"},"cwd":str(home)})
    bad=rc({"tool_name":"Read","tool_input":{"file_path":".env"},"cwd":str(home)})
    return ok==0 and bad==2

checks={
 "claude_config": cd.exists(),
 "global_skill": (cd/"skills/org-appsec-security/SKILL.md").exists(),
 "user_settings": (cd/"settings.json").exists(),
 "runtime": (ad/"scripts/secgate.py").exists(),
 "global_hook": (ad/"scripts/global_hook.py").exists(),
 "agent_guard": (ad/"scripts/agent_guard.py").exists() and hooks_with("org-ai-agent-guard"),
 "injection_watch": (ad/"scripts/injection_watch.py").exists() and hooks_with("org-ai-injection-watch"),
 "agent_rules": (ad/"AGENTS.md").exists(),
 "guard_runs_and_blocks": guard_really_works(),
}
tools={t:version([t,"--version"]) for t in ("claude","semgrep","trivy","gitleaks")}
warnings=[]
missing=[t for t in ("semgrep","trivy","gitleaks") if not tools[t]]
if missing: warnings.append("Full scan scanners missing: "+", ".join(missing)+". ci mode will BLOCK until they are installed.")
cv=tools.get("claude")
if cv and cv!="unknown" and tuple(map(int,cv.split(".")))<(2,1,84):
    warnings.append(f"Claude Code {cv} is older than 2.1.84 (trust-dialog bypass CVE-2026-40068). Update it.")
def engine_health():
    # Per-language scanners from scripts/engines (7.0): installed or not, version. Informational only, never a failed check.
    try:
        import importlib.util
        here=Path(__file__).resolve().parent/"scripts"/"engines"
        if not here.is_dir(): here=ad/"scripts"/"engines"
        spec=importlib.util.spec_from_file_location("nfsc_engines",here/"__init__.py",submodule_search_locations=[str(here)])
        mod=importlib.util.module_from_spec(spec); sys.modules["nfsc_engines"]=mod; spec.loader.exec_module(mod)
        return {e.name:(st["version"] or "installed") if st["installed"] else None
                for e in mod.ENGINES if e.name not in ("semgrep","trivy","gitleaks","psalm") for st in [e.status()]}
    except Exception as e:
        return {"error":type(e).__name__}

def guard_mode(app):
    """The mode the installed guard really uses (owner or managed) and why, asked from the installed guard itself,
    so a managed install on the machine or a broken policy file shows up here exactly as the hook sees it."""
    try:
        import importlib.util
        spec=importlib.util.spec_from_file_location("org_installed_guard",Path(app)/"scripts"/"agent_guard.py")
        g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
        if not hasattr(g,"load_policy"):
            return {"mode":"managed","why":"installed guard is older than 7.0 (no owner mode); run the installer"}
        mode,why=g.load_policy()
        return {"mode":mode,"why":why}
    except Exception as e:
        return {"mode":"unknown","why":f"could not load the installed guard ({type(e).__name__})"}

def _installer():
    import importlib.util
    spec=importlib.util.spec_from_file_location("orginstall_sched",Path(__file__).resolve().parent/"install-global.py")
    g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
    return g

def update_status(app):
    """Last update check (time, result) from <app>/update-state.json, written by the updater from 7.0 on, and the
    next scheduled run where the scheduler can tell. Informational only, never a failed check."""
    out={"last_check":None,"result":None,"next_run":None,"scheduler":None}
    try:
        f=Path(app)/"update-state.json"
        if f.is_file() and not f.is_symlink() and f.stat().st_size<=4096:
            st=json.loads(f.read_text(encoding="utf-8"))
            if isinstance(st,dict):
                out["last_check"]=str(st.get("last_check") or "")[:40] or None
                out["result"]=str(st.get("result") or "")[:200] or None
                if isinstance(st.get("backoff_until"),(int,float)):
                    out["backoff_until"]=time.strftime("%Y-%m-%d %H:%M",time.localtime(st["backoff_until"]))
        else:
            out["result"]="no check recorded yet (the updater writes update-state.json from 7.0 on)"
    except Exception:
        out["result"]="update-state.json unreadable"
    try:
        g=_installer()
        if platform.system()=="Windows":
            name=g.update_task_name(app)
            out["scheduler"]=f"Task Scheduler: {name}"
            p=subprocess.run([g.schtasks_exe(),"/Query","/TN",name,"/FO","LIST","/V"],capture_output=True,text=True,
                             timeout=30,encoding="utf-8",errors="replace")
            if p.returncode!=0:
                out["scheduler"]+=" (task not found)"
            for line in p.stdout.splitlines():
                if line.strip().lower().startswith("next run time:"):
                    out["next_run"]=line.split(":",1)[1].strip()[:60]; break
        else:
            sp=g.schedule_paths(app)
            if sp["kind"]=="launchd":
                if sp["plist"].exists():
                    out["scheduler"]=f"launchd agent {sp['label']}"
                    out["next_run"]=f"daily at {g.UPDATE_HOUR}:00 and at login"
            elif sp["timer"].exists():
                out["scheduler"]=f"systemd user timer {sp['unit']}.timer"
                sc=shutil.which("systemctl")
                if sc:
                    p=subprocess.run([sc,"--user","show",f"{sp['unit']}.timer","-p","NextElapseUSecRealtime","--value"],
                                     capture_output=True,text=True,timeout=30,encoding="utf-8",errors="replace")
                    out["next_run"]=(p.stdout.strip()[:60] or None) if p.returncode==0 else None
            if not out["scheduler"]:
                out["scheduler"]="none installed by us (crontab line, or re-run the installer with --update-timer)"
    except Exception as e:
        out["scheduler"]=out["scheduler"] or f"unknown ({type(e).__name__})"
    return out

engines=engine_health()
updates=update_status(ad)
product=product_name(ad)
gm=guard_mode(ad)
print(json.dumps({"product_name":product,"update_task":f"{product} Update","os":platform.platform(),"guard_mode":gm,"checks":checks,
                  "tools":tools,"engines":engines,"updates":updates,"warnings":warnings,"app_dir":str(ad)},indent=2))
summary=f"{product}: {'all checks passed' if all(checks.values()) else 'some checks FAILED'} (guard mode: {gm['mode']})"
try:
    print(summary)
except UnicodeEncodeError:
    print(summary.encode("ascii","replace").decode())
raise SystemExit(0 if all(checks.values()) else 1)

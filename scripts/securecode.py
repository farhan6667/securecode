#!/usr/bin/env python3
"""NexaForge SecureCode toolchain helper.

  py -I scripts/securecode.py doctor [project] [--json]
      Which languages the project uses, which scanners it needs, which are installed and at what version.
  py -I scripts/securecode.py setup [project] [--all] [--engine NAME] [--yes]
      Prints the install plan (official source, pinned version, checksum, licence, destination). Installs
      only with --yes, which is the one consent for the whole plan. Never installs silently.

Tools go to %LOCALAPPDATA%\\NexaForgeTools (Windows) or ~/.local/share/nexaforge-tools, outside every project
(NEXAFORGE_TOOLS_DIR overrides it). A download whose SHA-256 does not match the pinned value is deleted and
refused.
"""
from __future__ import annotations
import argparse, importlib.util, json, os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_engines():
    # Loaded by path: with -I the script folder is not on sys.path.
    spec = importlib.util.spec_from_file_location("nfsc_engines", HERE / "engines" / "__init__.py",
                                                  submodule_search_locations=[str(HERE / "engines")])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["nfsc_engines"] = mod
    spec.loader.exec_module(mod)
    return mod


def say(s=""):
    try:
        print(s)
    except UnicodeEncodeError:
        print(str(s).encode("ascii", "replace").decode())


def table(rows, head):
    w = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    say("  ".join(str(h).ljust(w[i]) for i, h in enumerate(head)))
    say("  ".join("-" * w[i] for i in range(len(head))))
    for r in rows:
        say("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))


def doctor(eng, project, as_json=False):
    langs = eng.detect_languages(project)
    rows, data = [], []
    for e in eng.ENGINES:
        needed = e.detect(project, langs)
        st = e.status()
        if e.name == "psalm":
            st["installed"] = (Path(project) / "vendor" / "bin" / "psalm").is_file()
            st["path"] = "vendor/bin/psalm" if st["installed"] else ""
        note = ""
        if st["missing_runtimes"]:
            note = "needs " + ", ".join(st["missing_runtimes"])
        elif not st["installed"]:
            note = "manual: see README" if e.kind in ("manual", "builtin") else \
                f"for local DAST: {eng.setup_command()} --engine zap" if e.name == "zap" else f"install with: {eng.setup_command()}"
        elif e.name == "codeql":
            note = "runs only with SECGATE_CODEQL=1"
        elif e.name == "security-code-scan":
            note = "runs only with --run-tests"
        st.update(needed=needed, note=note, finds=e.finds)
        data.append(st)
        optional = getattr(e, "optional", False)
        st["optional"] = optional
        rows.append([e.name, ("optional" if optional else "yes") if needed else "-",
                     "yes" if st["installed"] else "MISSING" if needed and not optional else "no",
                     st["version"] or "-", st["pinned"], note])
    if as_json:
        say(json.dumps({"project": str(project), "languages": sorted(langs), "tools_dir": str(eng.tools_root()),
                        "engines": data}, indent=2))
        return 0
    say(f"Project: {project}")
    say(f"Languages found: {', '.join(sorted(langs)) or 'none'}")
    say(f"Tools folder: {eng.tools_root()}")
    say()
    table(rows, ["engine", "needed", "installed", "version", "pinned", "note"])
    missing = [r[0] for r in rows if r[2] == "MISSING"]
    say()
    if missing:
        say(f"{len(missing)} needed engine(s) missing: {', '.join(missing)}. The gate reports them as 'not run'.")
        say(f"See the plan with: {eng.setup_command()}")
    else:
        say("Every engine this project needs is installed.")
    return 0


def setup(eng, project, all_engines=False, only=None, yes=False):
    from nfsc_engines import _install
    langs = eng.detect_languages(project)
    # --engine NAME picks that engine even when the project does not need it (zap is never "needed" by a project).
    chosen = [e for e in eng.ENGINES if (all_engines or (only and e.name in only) or e.detect(project, langs))
              and (not only or e.name in only)]
    if only:
        unknown = sorted(set(only) - {e.name for e in eng.ENGINES})
        if unknown:
            say(f"Unknown engine(s): {', '.join(unknown)}. Known: {', '.join(e.name for e in eng.ENGINES)}")
            return 2
    todo, manual = [], []
    for e in chosen:
        if e.status()["installed"] or e.name == "psalm":
            continue
        plan = e.install_plan()
        (todo if plan["auto"] else manual).append((e, plan))
    say(f"Project: {project}   Languages: {', '.join(sorted(langs)) or 'none'}")
    say(f"Install folder: {eng.tools_root()} (outside the project)")
    say()
    if not todo and not manual:
        if only:            # an explicit --engine request is about that engine, not about what the project needs
            for e in chosen:
                say(f"Nothing to install: {e.name} is already installed." if e.name != "psalm" else
                    "Nothing to install: psalm comes from the project's own composer.json (vendor/bin/psalm), not from setup.")
        elif all_engines:
            say("Nothing to install: every engine is already installed.")
        else:
            say("Nothing to install: every engine this project needs is already present.")
        return 0
    for e, plan in todo:
        say(f"[{e.name}] version {plan['version']}, licence {plan['licence']}")
        missing_rt = e.missing_runtimes()
        if missing_rt:
            say(f"  note: {e.name} also needs {', '.join(missing_rt)} to run")
            if any(str(r).startswith("java") for r in missing_rt):
                say("  SecureCode never installs Java for you. Install a Java 17 or newer runtime yourself "
                    "(for example Eclipse Temurin from https://adoptium.net/), then check it with: java -version")
        say(f"  source: {plan['source']}")
        for s in plan["steps"]:
            say(f"  - {s}")
    for e, plan in manual:
        say(f"[{e.name}] not installed automatically. {plan['note']}")
    say()
    if not todo:
        return 0
    if _install.inside(eng.tools_root(), project):
        say(f"Refused: the tools folder {eng.tools_root()} is inside the project. Set NEXAFORGE_TOOLS_DIR to a folder outside it.")
        return 2
    if not yes:
        say("Nothing was installed. Show this plan to the person who owns this machine. With their yes, run:")
        say("  py -I scripts/securecode.py setup --yes" + (" --all" if all_engines else "") +
            "".join(f" --engine {n}" for n in (only or [])))
        return 0
    results = []
    for e, plan in todo:
        say(f"Installing {e.name} {plan['version']} ...")
        try:
            path = _install.install(e, log=say)
            st = e.status()
            results.append([e.name, "installed", st["version"] or plan["version"], str(path)])
        except _install.ChecksumMismatch as ex:
            results.append([e.name, "REFUSED (checksum)", "-", str(ex)[:120]])
        except Exception as ex:
            results.append([e.name, "FAILED", "-", f"{type(ex).__name__}: {str(ex)[:120]}"])
    say()
    table(results, ["engine", "result", "version", "detail"])
    bad = [r for r in results if r[1] != "installed"]
    if bad:
        say("Some engines were not installed. The gate will report them as 'not run'. Fix the detail above and run setup again.")
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="securecode.py", description="NexaForge SecureCode scanner toolchain")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("doctor", help="show which scanners this project needs and which are installed")
    d.add_argument("project", nargs="?", default=".")
    d.add_argument("--json", action="store_true")
    s = sub.add_parser("setup", help="show the install plan; install only with --yes")
    s.add_argument("project", nargs="?", default=".")
    s.add_argument("--all", action="store_true", help="every engine, not only the ones this project needs")
    s.add_argument("--engine", action="append", help="only this engine (repeatable)")
    s.add_argument("--yes", action="store_true", help="the one consent: install everything in the plan")
    a = ap.parse_args(argv)
    project = Path(a.project).resolve()
    if not project.is_dir():
        say(f"Not a folder: {project}")
        return 2
    eng = load_engines()
    if a.cmd == "doctor":
        return doctor(eng, project, a.json)
    return setup(eng, project, a.all, a.engine, a.yes)


if __name__ == "__main__":
    raise SystemExit(main())

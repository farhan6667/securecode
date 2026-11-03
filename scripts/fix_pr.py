#!/usr/bin/env python3
"""Open a pull request with the security fixes the agent applied in the working tree.

Dry run by default: it shows the branch, the files, the secret scan result and every git/gh command it
would run, and changes nothing. With --open it:
  1. creates the branch securecode/fix-<date> from the current commit (never the default branch),
  2. stages only tracked files that changed (git add -u), plus new files named one by one with --add,
  3. refuses if gitleaks finds a secret in the added lines, or if gitleaks is not installed,
  4. commits, pushes that branch only (no force; the agent guard asks the person before any push),
  5. opens a draft PR with `gh pr create`, whose body is the report summary and the retest outcomes.

Untracked files are never swept in: an untracked .env or key file cannot end up in the PR by accident.
"""
from __future__ import annotations

import argparse, datetime, json, os, re, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with python -I
from secgate import find_tool, CI_GITLEAKS_CONFIG, CI_EMPTY_IGNORE  # noqa: E402
import report  # noqa: E402

SECRET_NAMES = re.compile(r"(?i)(^|/)(\.env(\..*)?|.*\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|"
                          r"credentials(\.json)?|secrets?\.(json|ya?ml|toml)|\.npmrc|\.pypirc|\.netrc|\.git-credentials)$")
PROTECTED = {"main", "master", "trunk", "develop", "production", "release"}


class Refused(Exception):
    pass


def default_run(argv, cwd, input_text=None):
    exe = find_tool(argv[0]) if not os.path.isabs(argv[0]) else argv[0]
    if not exe:
        return 127, "", f"{argv[0]} is not installed"
    try:
        p = subprocess.run([exe, *argv[1:]], cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=300, input=input_text)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 125, "", f"{type(e).__name__}"


class Git:
    def __init__(self, root: Path, run):
        self.root, self.run = root, run

    def out(self, *args) -> str:
        rc, out, err = self.run(["git", *args], self.root)
        if rc != 0:
            raise Refused(f"git {' '.join(args[:2])} failed: {report.clean(err, 200)}")
        return out


def default_branch(git: Git) -> str:
    rc, out, _ = git.run(["git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"], git.root)
    if rc == 0 and out.strip():
        return out.strip().split("/", 1)[-1]
    rc, out, _ = git.run(["gh", "repo", "view", "--json", "defaultBranchRef", "--jq", ".defaultBranchRef.name"], git.root)
    if rc == 0 and out.strip():
        return out.strip()
    return "main"


def check_branch(name: str, default: str) -> None:
    if not re.fullmatch(r"securecode/fix-[0-9]{8}(-[0-9]{1,3})?", name):
        raise Refused(f"branch name '{report.clean(name, 80)}' is not a securecode/fix-<date> branch")
    if name == default or name.lower() in PROTECTED:
        raise Refused("refusing to commit to the default branch")


def safe_rel(root: Path, p: str) -> str:
    if not p or p.startswith("-") or re.search(r"[\x00-\x1f\x7f]", p):
        raise Refused(f"refused path: {report.clean(p, 120)}")
    q = (root / p).resolve()
    try:
        rel = q.relative_to(root.resolve()).as_posix()
    except ValueError:
        raise Refused(f"{report.clean(p, 120)} is outside the repository")
    if q.is_symlink() or not q.is_file():
        raise Refused(f"{report.clean(p, 120)} is not a regular file")
    return rel


def changed_files(git: Git, extra: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(tracked files changed vs HEAD, explicit new files, untracked files left out)."""
    tracked = [x for x in git.out("diff", "--name-only", "-z", "HEAD").split("\0") if x]
    staged_new = [x for x in git.out("diff", "--cached", "--name-only", "--diff-filter=A", "-z").split("\0") if x]
    untracked = [x for x in git.out("ls-files", "--others", "--exclude-standard", "-z").split("\0") if x]
    explicit = [safe_rel(git.root, p) for p in extra]
    stray = [x for x in staged_new if x not in explicit]
    if stray:
        raise Refused("new files are already staged that were not named with --add: " + ", ".join(report.clean(x, 80) for x in stray[:5]) +
                      ". Unstage them (git restore --staged <file>) or pass them with --add after review.")
    for x in explicit:
        rc, _, _ = git.run(["git", "check-ignore", "-q", "--", x], git.root)
        if rc == 0:
            raise Refused(f"{x} is ignored by .gitignore; it is not added")
    bad = [x for x in tracked + explicit if SECRET_NAMES.search(x)]
    if bad:
        raise Refused("these files look like secrets or credentials and are never put in a PR: " + ", ".join(bad[:5]))
    return tracked, explicit, [x for x in untracked if x not in explicit]


def added_text(git: Git, tracked: list[str], explicit: list[str]) -> str:
    """The lines this PR adds: '+' lines of the tracked diff and the full text of explicit new files."""
    parts = []
    if tracked:
        diff = git.out("diff", "--no-color", "--unified=0", "HEAD", "--", *tracked)
        parts += [ln[1:] for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    for x in explicit:
        try:
            parts.append((git.root / x).read_text(encoding="utf-8", errors="replace")[:5_000_000])
        except OSError:
            raise Refused(f"cannot read {x}")
    return "\n".join(parts)


def scan_secrets(text: str, run, cwd: Path) -> tuple[bool, str]:
    """True when clean. gitleaks is required: no scanner, no PR. The built-in patterns run as a second check."""
    if report.has_secret(text):
        return False, "the added lines contain something that looks like a secret (built-in patterns)"
    if not find_tool("gitleaks"):
        return False, "gitleaks is not installed; a PR is never opened without a secret scan of the diff"
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "src"; src.mkdir()
        (src / "added-lines.txt").write_text(text, encoding="utf-8")
        rp = Path(d) / "gitleaks.json"
        rc, out, err = run(["gitleaks", "dir", str(src), "--no-banner", "--redact", "--report-format", "json",
                            "--report-path", str(rp), "--config", str(CI_GITLEAKS_CONFIG),
                            "--gitleaks-ignore-path", str(CI_EMPTY_IGNORE), "--ignore-gitleaks-allow"], cwd)
        try:
            data = json.loads(rp.read_text(encoding="utf-8") or "[]")
        except (OSError, ValueError):
            return False, f"gitleaks did not produce a readable report (exit {rc}); refusing"
    if isinstance(data, list) and data:
        rules = sorted({str(x.get("RuleID", "secret")) for x in data if isinstance(x, dict)})
        return False, f"gitleaks found {len(data)} secret(s) in the added lines ({', '.join(rules[:5])})"
    if rc not in (0, 1):
        return False, f"gitleaks exited {rc}; refusing"
    return True, "gitleaks: no secrets in the added lines"


def pr_body(root: Path) -> str:
    sec = root / ".security"
    if not (sec / "findings.json").is_file():
        return "Security fixes from NexaForge SecureCode. No gate report was found in .security/; run the gate and report.py first."
    def opt(n):
        p = sec / n
        return p if p.is_file() else None
    m = report.build(root, sec / "findings.json", opt("findings-before.json"), opt("dast-findings.json"),
                     opt("retest.json"), opt("artifacts.json"))
    c = report.counts(m["findings"])
    lines = ["## Security fixes from NexaForge SecureCode", "",
             f"Verdict after fixes: **{m['verdict']}** ({report.md(m['why'])}). Open risk: **{m['risk']}**.", "",
             f"Findings in the report: {c['CRITICAL']} critical, {c['HIGH']} high, {c['MEDIUM']} medium, {c['LOW']} low.", "",
             "| ID | Finding | Severity | Retest | Evidence |", "|---|---|---|---|---|"]
    for f in m["findings"][:100]:
        lines.append(f"| {f['id']} | {report.md(report.title_of(f), 100)} | {f['severity']} | {f['retest']['outcome']} | "
                     f"{report.md(f['retest']['evidence'], 120)} |")
    if len(m["findings"]) > 100:
        lines.append(f"| ... | {len(m['findings']) - 100} more in .security/REPORT.md | | | |")
    lines += ["", "The full report is in `.security/REPORT.html` on the developer's machine (not committed).",
              "Review every change before merging. This PR does not claim the application is free of vulnerabilities."]
    body = "\n".join(lines)
    return body[:60000]


def plan(root: Path, run, extra: list[str], branch: str | None, today: str) -> dict:
    git = Git(root, run)
    top = Path(git.out("rev-parse", "--show-toplevel").strip()).resolve()
    if top != root.resolve():
        raise Refused("run this from the repository root")
    default = default_branch(git)
    current = git.out("rev-parse", "--abbrev-ref", "HEAD").strip()
    name = branch or f"securecode/fix-{today}"
    if not branch:
        n = 1
        while git.run(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{name}"], root)[0] == 0 and n < 50:
            n += 1; name = f"securecode/fix-{today}-{n}"
    check_branch(name, default)
    rc, _, _ = run(["git", "check-ref-format", "--branch", name], root)
    if rc != 0:
        raise Refused("invalid branch name")
    if git.run(["git", "remote", "get-url", "origin"], root)[0] != 0:
        raise Refused("this repository has no 'origin' remote")
    tracked, explicit, untracked = changed_files(git, extra)
    if not tracked and not explicit:
        raise Refused("nothing to commit: no tracked file changed")
    ok, scan = scan_secrets(added_text(git, tracked, explicit), run, root)
    if not ok:
        raise Refused(f"secret scan: {scan}")
    title = f"Security fixes from NexaForge SecureCode ({today[:4]}-{today[4:6]}-{today[6:]})"
    cmds = [["git", "switch", "-c", name],
            ["git", "add", "-u", "--", "."],
            *([["git", "add", "--", *explicit]] if explicit else []),
            ["git", "commit", "-m", title, "-m", "Fixes and regression tests from the security review. See the PR description."],
            ["git", "push", "--set-upstream", "origin", f"refs/heads/{name}:refs/heads/{name}"],
            ["gh", "pr", "create", "--draft", "--base", default, "--head", name, "--title", title, "--body-file", "<body>"]]
    return {"branch": name, "default": default, "current": current, "tracked": tracked, "explicit": explicit,
            "untracked": untracked, "scan": scan, "commands": cmds, "title": title}


def execute(root: Path, run, p: dict, body: str) -> int:
    for cmd in p["commands"]:
        if any(a == "--force" or a.startswith(("--force", "+")) or a in ("-f", "--mirror", "--delete") for a in cmd[2:] if cmd[:2] == ["git", "push"]):
            raise Refused("force pushes are never made")
        if cmd[:2] == ["git", "push"] and cmd[-1].split(":")[-1] in (f"refs/heads/{p['default']}", p["default"]):
            raise Refused("refusing to push to the default branch")
        if cmd[:2] == ["git", "commit"]:
            # Scan again what is really staged now: files may have changed since the dry-run scan.
            git = Git(root, run)
            staged = git.out("diff", "--cached", "--no-color", "--unified=0")
            added = "\n".join(ln[1:] for ln in staged.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
            new = [x for x in git.out("diff", "--cached", "--name-only", "--diff-filter=A", "-z").split("\0") if x]
            if any(SECRET_NAMES.search(x) for x in new) or set(new) - set(p["explicit"]):
                run(["git", "reset", "-q"], root)
                raise Refused("the staged files changed since the plan; nothing was committed (changes are unstaged, not lost)")
            ok, scan = scan_secrets(added, run, root)
            if not ok:
                run(["git", "reset", "-q"], root)
                raise Refused(f"secret scan of the staged change: {scan}; nothing was committed (changes are unstaged, not lost)")
        if cmd[:3] == ["gh", "pr", "create"]:
            with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as fh:
                fh.write(body); bf = fh.name
            try:
                cmd = [x if x != "<body>" else bf for x in cmd]
                rc, out, err = run(cmd, root)
            finally:
                os.unlink(bf)
        else:
            rc, out, err = run(cmd, root)
        print(report.visible(" ".join(cmd)), "->", rc)
        if rc != 0:
            print(f"STOPPED: {report.clean(err or out, 400)}")
            return 1
        if out.strip():
            print(report.clean(out, 400))
    return 0


def main(argv=None, run=default_run, today: str | None = None) -> int:
    ap = argparse.ArgumentParser(description="Create a fix branch and a draft PR for the security fixes (dry run by default).")
    ap.add_argument("--open", action="store_true", help="really create the branch, commit, push and open the PR")
    ap.add_argument("--add", action="append", default=[], help="a new file (for example a regression test) to include; repeat per file")
    ap.add_argument("--branch", help="branch name, must be securecode/fix-YYYYMMDD[-n]")
    a = ap.parse_args(argv)
    root = Path.cwd().resolve()
    today = today or datetime.date.today().strftime("%Y%m%d")
    try:
        p = plan(root, run, a.add, a.branch, today)
    except Refused as e:
        print(f"REFUSED: {e}")
        return 4
    body = pr_body(root)
    print(f"Branch: {p['branch']} (from {report.visible(p['current'])}; the default branch {report.visible(p['default'])} is not touched)")
    print("Files:", ", ".join(report.visible(x) for x in p["tracked"] + p["explicit"]))
    if p["untracked"]:
        print(f"Left out: {len(p['untracked'])} untracked file(s). Name reviewed new files with --add.")
    print("Leak scan of the added lines:", p["scan"])
    if not a.open:
        print("DRY RUN. Nothing was changed. These commands would run:")
        for c in p["commands"]:
            print("  ", report.visible(" ".join(c)))
        print("PR body preview:\n" + body[:2000])
        print("Run again with --open to create the branch and the PR. The push asks for your approval.")
        return 0
    if not find_tool("gh"):
        print("NOTE: GitHub CLI (gh) is not installed; install it from https://cli.github.com and run gh auth login.")
        return 4
    try:
        return execute(root, run, p, body)
    except Refused as e:
        print(f"REFUSED: {e}")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())

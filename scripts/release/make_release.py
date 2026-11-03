#!/usr/bin/env python3
"""Build and sign a release zip for the auto-updater (run by the security team only).

    py -I scripts/release/make_release.py --version 6.2.1 --key C:\\secure\\org-appsec-release

Writes dist/<asset> and dist/<asset>.sig. Publishing is a separate, deliberate step:
    gh release create v6.2.1 dist/<asset> dist/<asset>.sig --repo <org>/<repo> --notes-file RELEASE-NOTES-V6.2.md
The private key must stay offline or on the release officer's machine (never in the repo, never in CI).
"""
import argparse, json, re, shutil, subprocess, sys, zipfile
from pathlib import Path

PKG = Path(__file__).resolve().parents[2]
EXCLUDE_DIRS = {".git", ".security", "__pycache__", "dist", ".pytest_cache", "node_modules", ".ai-media", "org-internal",
                ".venv", "venv"}


def release_files():
    """Only files committed to git go into a public release (drafts, local images and notes never do).
    Without a git checkout, fall back to the folder walk with EXCLUDE_DIRS."""
    if (PKG / ".git").exists():
        git = shutil.which("git") or sys.exit("git not found; build releases from a git checkout")
        # The zip takes the files from disk, so the tree must match the last commit exactly.
        dirty = subprocess.run([git, "-C", str(PKG), "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True, check=True).stdout.strip()
        if dirty:
            sys.exit("uncommitted changes in tracked files; commit or stash them so the release matches a commit:\n" + dirty[:2000])
        out = subprocess.run([git, "-C", str(PKG), "ls-files", "-z"], capture_output=True, check=True).stdout
        files = [PKG / p for p in out.decode("utf-8").split("\0") if p]
        if not files:
            sys.exit("no committed files; make the first commit before building a release")
        return files
    return sorted(PKG.rglob("*"))


EXCLUDE_SUFFIX = (".pyc", ".sig", ".key", ".pem")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--key", required=True, help="path to the release signing private key (ssh-keygen ed25519)")
    a = ap.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+", a.version):
        sys.exit("version must look like 6.2.1")
    installer = (PKG / "install-global.py").read_text(encoding="utf-8")
    if f'VERSION="{a.version}"' not in installer or f"Version: {a.version}" not in (PKG / "MANIFEST.txt").read_text(encoding="utf-8"):
        sys.exit("bump VERSION in install-global.py and Version in MANIFEST.txt to the release version first")
    cfg = json.loads((PKG / "config" / "update.json").read_text(encoding="utf-8-sig"))
    signers = (PKG / "config" / "allowed_signers").read_text(encoding="utf-8")
    if signers.startswith("\ufeff"):
        sys.exit("config/allowed_signers starts with a byte order mark (Notepad's 'UTF-8 with BOM'); ssh-keygen then "
                 "misreads the signer name and manual verification fails. Save it as plain UTF-8 and run again.")
    if not cfg.get("repo") or "ssh-ed25519" not in signers:
        sys.exit("config/update.json needs the repo and config/allowed_signers the release public key")
    out = PKG / "dist"; out.mkdir(exist_ok=True)
    asset = out / cfg["asset"]
    with zipfile.ZipFile(asset, "w", zipfile.ZIP_DEFLATED) as z:
        for f in release_files():
            rel = f.relative_to(PKG)
            if f.is_dir() or set(rel.parts) & EXCLUDE_DIRS or f.name.endswith(EXCLUDE_SUFFIX) or f.is_symlink():
                continue
            z.write(f, Path("aisec") / rel)
    sig = Path(str(asset) + ".sig")
    sig.unlink(missing_ok=True)
    keygen = shutil.which("ssh-keygen") or sys.exit("ssh-keygen not found")
    subprocess.run([keygen, "-Y", "sign", "-f", a.key, "-n", "org-appsec-update", str(asset)], check=True)
    with open(asset, "rb") as fh:
        ident = cfg["signer_identity"]
        ok = subprocess.run([keygen, "-Y", "verify", "-f", str(PKG / "config" / "allowed_signers"), "-I", ident,
                             "-n", "org-appsec-update", "-s", str(sig)], stdin=fh).returncode == 0
    if not ok:
        sys.exit("signature does not verify against config/allowed_signers; wrong key?")
    print(f"built and verified {asset.name} + .sig\nnext: gh release create v{a.version} \"{asset}\" \"{sig}\" --repo {cfg['repo']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

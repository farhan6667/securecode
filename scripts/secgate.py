#!/usr/bin/env python3
"""Org AI Secure AppSec Gate (NexaForge SecureCode 7.0.0).

Modes:
 quick: lightweight changed-file heuristics only.
 full: real Semgrep + Trivy + Gitleaks + project tests/build + optional ZAP.
 ci: same as full, but fails closed when required scanners are missing.

No scanner is claimed to run in quick mode.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

GATE_VERSION="7.1.0"   # kept equal to VERSION in install-global.py (tests/test_v7_docs.py checks it)
SEV={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
SKIP={".git","node_modules","vendor","dist","build","coverage",".next","venv",".venv","__pycache__","target",".security"}
EXT={".twig",".ejs",".hbs",".php",".js",".jsx",".ts",".tsx",".py",".rb",".java",".go",".cs",".vue",".html",".htm",".sql",".sh",".bash",".yml",".yaml",".json",".xml",".tf",".tfvars",".env"}
RULES=[
("HARDCODED_SECRET","CRITICAL",r"(?i)(?:password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
("AWS_ACCESS_KEY","CRITICAL",r"\bAKIA[0-9A-Z]{16}\b"),
("PRIVATE_KEY","CRITICAL",r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----"),
("DB_CREDENTIAL_URL","CRITICAL",r"(?i)(?:mongodb|postgres(?:ql)?|mysql|redis)://[^\s:@]+:[^\s@]+@"),
("COMMAND_INJECTION","CRITICAL",r"(?i)\b(?:os\.system|os\.popen|shell_exec|passthru|child_process\.exec)\s*\("),
("PY_SUBPROCESS_SHELL","CRITICAL",r"(?i)subprocess\.(?:run|Popen|call)\([^\n]{0,250}shell\s*=\s*True"),
# SQL built from strings: the line must contain real SQL structure AND a concatenation/interpolation
# marker (string +, PHP "...$var" or " . $var, JS ${}, Python f-string/.format). DB-API "%s" placeholders are safe.
("SQL_CONCAT","CRITICAL",r"(?i)^(?=.{0,2000}\b(?:SELECT\b.{0,200}\bFROM|INSERT\s+INTO|UPDATE\s+[\w`\".\[\]]+\s+SET|DELETE\s+FROM)\b)"
 r"(?=.{0,2000}(?:[\"'`]\s*\+\s*\w|\w\s*\+\s*[\"'`]|\.format\(|\bf[\"']|\$\{|[\"']\s*\.\s*\$|\$[A-Za-z_]\w*[^\"']{0,80}[\"']|\{\$))"),
("XSS_SINK","HIGH",r"(?i)\b(?:innerHTML|outerHTML|document\.write)\s*="),
("REACT_RAW_HTML","HIGH",r"dangerouslySetInnerHTML"),
# Vue v-html has its own rule (VUE_RAW_HTML), so this one does not report the same line twice.
("XSS_RAW_TEMPLATE","HIGH",r"\{!!\s*\$|<%-\s*[\w.]|\|\s*(?:safe|raw)\s*\}\}"),
("VUE_RAW_HTML","HIGH",r"\bv-html\s*="),
("PATH_TRAVERSAL_SINK","HIGH",r"(?i)\b(?:readFile|readFileSync|writeFile|writeFileSync|open|fopen|file_get_contents)\s*\([^\n]{0,250}(?:req\.|request\.|query|params|body|_GET|_POST)"),
("INSECURE_CRYPTO","HIGH",r"(?i)\b(?:md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\b|\b(?:DES|RC4)\b"),
("INSECURE_RANDOM","HIGH",r"(?i)\b(?:Math\.random|random\.random|rand|mt_rand)\s*\("),
("CORS_WILDCARD","MEDIUM",r"(?i)(?:Access-Control-Allow-Origin[^\n]*\*|cors\s*\(\s*\)|origin\s*:\s*['\"]?\*['\"]?)"),
("OPEN_REDIRECT","MEDIUM",r"(?i)(?:res\.redirect|redirect|Location\s*:)[^\n]{0,180}(?:req\.|request\.|query|params|body)"),
("DEBUG_EXPOSURE","MEDIUM",r"(?i)\b(?:debug\s*=\s*True|app\.debug\s*=\s*True|display_errors\s*=\s*On|APP_DEBUG\s*=\s*true)\b"),
("SENSITIVE_LOG","HIGH",r"(?i)(?:console\.log|logger\.|logging\.|print)\s*\([^\n]{0,200}(?:password|passwd|authorization|cookie|token|secret)"),
("JWT_DECODE_NO_VERIFY","HIGH",r"(?i)(?:jwt\.decode|jsonwebtoken\.decode)\([^\n]{0,200}(?:verify\s*[:=]\s*False|without verification)"),
("DISABLE_TLS_VERIFY","HIGH",r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*false)")
]

def files_for(target):
    p=Path(target)
    if p.is_file(): return [p] if p.suffix.lower() in EXT else []
    out=[]
    for r,d,fs in os.walk(p):
        d[:]=[x for x in d if x not in SKIP and not is_link_dir(os.path.join(r,x))]
        for f in fs:
            fp=Path(r)/f
            if fp.is_symlink(): continue
            if fp.suffix.lower() in EXT or f in {"Dockerfile",".env"}: out.append(fp)
    return out

def is_test_path(fp,base=None):
    p=Path(fp)
    try: p=p.resolve().relative_to(Path(base or Path.cwd()).resolve())   # folders above the project don't count
    except (ValueError,OSError): p=Path(p.name)
    parts=[x.lower() for x in p.parts]
    return any(x in ("test","tests","__tests__","spec","specs","fixtures","fixture","testdata") for x in parts[:-1]) or \
        bool(re.search(r"(?i)(^test_|_test\.|\.test\.|\.spec\.|tests?\.php$)",parts[-1] if parts else ""))

# Arguments of parameter-binding calls are bound values, not SQL text: setParameter("n", "%" + note + "%") is safe.
_BIND_CALL=re.compile(r"(?i)(?:\.|->|::)\s*(?:setParameter(?:List)?|setNamedParameter|bindParam|bindValue|bind_param|bind|"
                      r"setString|setNString|setObject|setLong|setInt|addValue|addParameter|withParameter)\s*\(")

def strip_bound_args(line):
    """The line with the arguments of binding calls removed (quote-aware, parentheses balanced). An unbalanced
    call is left as it is, so a broken line is still checked, never silently cleared."""
    out=[]; i=0
    while True:
        m=_BIND_CALL.search(line,i)
        if not m: out.append(line[i:]); break
        out.append(line[i:m.end()]); j=m.end(); depth=1; q=None
        while j<len(line) and depth:
            c=line[j]
            if q:
                if c=="\\": j+=1
                elif c==q: q=None
            elif c in "\"'`": q=c
            elif c=="(": depth+=1
            elif c==")": depth-=1
            j+=1
        if depth: out.append(line[m.end():]); break        # unbalanced: keep the rest for checking
        out.append(")"); i=j
    return "".join(out)

def local_scan(target):
    findings=[]
    base=Path(target) if Path(target).is_dir() else Path.cwd()
    for fp in files_for(target):
        try: lines=fp.read_text(encoding="utf-8",errors="ignore").splitlines()
        except OSError: continue
        test_file=is_test_path(fp,base)
        for n,line in enumerate(lines,1):
            if not line.strip() or line.lstrip().startswith(("#","//","/*","*","--")): continue
            for rid,sev,rx in RULES:
                if re.search(rx,strip_bound_args(line) if rid=="SQL_CONCAT" else line):
                    # Weak hashes, Math.random and sample keys in tests and fixtures are usually test data,
                    # unless the line is about passwords, tokens, OTPs or resets.
                    if test_file and rid in ("INSECURE_CRYPTO","INSECURE_RANDOM","HARDCODED_SECRET") and \
                       not re.search(r"(?i)password|token|secret|otp|reset",line):
                        sev="MEDIUM"
                    findings.append({"rule":rid,"severity":sev,"file":str(fp),"line":n,
                        "message":f"{rid} matched. Verify sink/source context and remediate if security-relevant.",
                        "code":line.strip()[:180],"engine":"local-heuristics"})
    return findings

# --- AI agent supply chain: instruction files and agent configs shipped inside the repo ---
INSTRUCTION_NAMES={"claude.md","agents.md","gemini.md",".cursorrules","copilot-instructions.md","skill.md"}
# Zero-width space, LRM/RLM, bidi embeddings/overrides/isolates, invisible operators, BOM, tag block.
# ZWNJ/ZWJ (U+200C/U+200D) are left out on purpose: normal Urdu, Persian and emoji text uses them.
HIDDEN_UNICODE=re.compile("[\u200b\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
INJECTION_PHRASE=re.compile(r"(?i)(ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?(system|previous) prompt|"
                            r"do not (tell|inform|mention to) the user|without (asking|telling) the user|exfiltrat|"
                            r"curl[^\n]{0,80}\|\s*(ba)?sh|--dangerously-skip-permissions|--yolo\b)")

def is_instruction_file(fp: Path) -> bool:
    n=fp.name.lower(); parts=[x.lower() for x in fp.parts]
    return n in INSTRUCTION_NAMES or (fp.suffix.lower()==".mdc" and ".cursor" in parts) or ("claude_docs" in parts and fp.suffix.lower()==".md")

def is_link_dir(p):
    # Symlinked folders and Windows junctions can point anywhere on the machine; never walk into them.
    # os.path.isjunction exists only on Python 3.12+, so read the reparse tag directly (3.8+ on Windows).
    if os.path.islink(p): return True
    try: st=os.lstat(p)
    except OSError: return True
    return getattr(st,"st_reparse_tag",0)==0xA0000003      # IO_REPARSE_TAG_MOUNT_POINT (junction)

def walk_files(target):
    p=Path(target)
    if p.is_file(): return [p]
    files=[]
    for r,d,fs in os.walk(p):
        d[:]=[x for x in d if x not in SKIP and not is_link_dir(os.path.join(r,x))]
        files.extend(Path(r)/f for f in fs if not os.path.islink(os.path.join(r,f)))
    return files

def agent_scan(target):
    findings=[]; files=walk_files(target)
    def add(rule,sev,fp,n,msg):
        findings.append({"rule":rule,"severity":sev,"file":str(fp),"line":n,"message":msg,"code":"","engine":"agent-config"})
    for fp in files:
        name=fp.name.lower(); parent=fp.resolve().parent.name.lower()
        instr=is_instruction_file(fp)
        agent_cfg=(name==".mcp.json" or (parent==".claude" and name in ("settings.json","settings.local.json"))
                   or (parent==".cursor" and name=="mcp.json") or (parent==".codex" and name=="config.toml"))
        envf=name==".env" or name.startswith(".env.")
        if not (instr or agent_cfg or envf): continue
        try: text=fp.read_text(encoding="utf-8-sig",errors="ignore")  # a leading BOM is normal on Windows
        except OSError: continue
        for n,line in enumerate(text.splitlines(),1):
            if HIDDEN_UNICODE.search(line):
                add("HIDDEN_UNICODE","CRITICAL" if instr or agent_cfg else "HIGH",fp,n,
                    "Invisible or bidirectional Unicode characters found (Rules File Backdoor pattern). Remove them and review the file.")
            if instr and INJECTION_PHRASE.search(line):
                add("INSTRUCTION_INJECTION","HIGH",fp,n,"Instruction file contains prompt-injection style text. Review before any AI agent loads it.")
            if envf and re.match(r"\s*CODEX_HOME\s*=",line):
                add("AGENT_HOME_OVERRIDE","HIGH",fp,n,"CODEX_HOME set in a repo .env can make Codex load repo-supplied config (CVE-2025-61260).")
        if agent_cfg:
            low=text.lower()
            if re.search(r'"apikeyhelper"\s*:',low) or "anthropic_base_url" in low:
                add("REPO_AGENT_CREDENTIAL_ROUTE","HIGH",fp,0,"Repo-level Claude settings set apiKeyHelper or ANTHROPIC_BASE_URL, which can leak the developer's API key (CVE-2026-21852 class). Remove them.")
            if re.search(r'"hooks"\s*:\s*\{\s*"',low):   # an empty "hooks": {} is harmless
                add("REPO_AGENT_HOOKS","MEDIUM",fp,0,"Repo-level Claude settings define hooks that run on every developer's machine. Review them like code (CODEOWNERS); this is expected in repos that ship their own guard.")
            if re.search(r'"(python\w*|py_python\w*|node_options|node_path|ld_preload|ld_library_path|dyld_\w+|path|pathext|comspec|bash_env|env|perl5opt|perl5lib|rubyopt|git_ssh_command|git_config_\w+|git_exec_path|claude_config_dir|codex_home|npm_config_\w+)"\s*:',low) and '"env"' in low:
                add("REPO_AGENT_ENV","HIGH",fp,0,"Repo-level agent settings set interpreter or loader variables (PYTHON*, NODE_OPTIONS, PATH, LD_PRELOAD...) in env; "
                    "these can disarm security hooks or run code. Remove them.")
            if re.search(r'"enableallprojectmcpservers"\s*:\s*true',low):
                add("MCP_AUTO_APPROVE","HIGH",fp,0,"enableAllProjectMcpServers=true auto-starts repo MCP servers (CVE-2025-59536 class). Set it to false.")
            if re.search(r'"mcpservers"\s*:|\[mcp_servers',low):
                add("REPO_MCP_SERVERS","MEDIUM",fp,0,"Repo defines MCP servers. Confirm each is approved and pinned before enabling it.")
    return findings

# --- Vulnerable front-end libraries copied into the repo or loaded from a CDN (Trivy only sees lockfiles) ---
# lib: (minimum allowed version, advisory). Below the minimum is reported as HIGH: outdated client
# libraries are the most frequent finding in pentests of this kind of app, so the
# org policy is to upgrade, never suppress. None = end of life, every version is reported.
WEB_LIBS={
    "jquery":            ((3,5,0),"XSS in htmlPrefilter (CVE-2020-11022, CVE-2020-11023); upgrade to jQuery 3.7.x"),
    "jquery-ui":         ((1,13,2),"XSS in several widgets (CVE-2021-41182/41183/41184, CVE-2022-31160); upgrade to 1.13.3+"),
    "jquery-validation": ((1,19,5),"ReDoS (CVE-2021-43306, CVE-2022-31147); upgrade to the latest 1.x"),
    "bootstrap":         ((5,3,0),"Bootstrap 3 and 4 are end of life (3.x/4.x XSS CVE-2019-8331, CVE-2024-6531); org minimum is 5.3.x"),
    "angularjs":         (None,"AngularJS 1.x is end of life (no security fixes since 2022); migrate"),
    "moment":            ((2,29,4),"ReDoS in RFC2822 parsing (CVE-2022-31129); upgrade to 2.30.x or move to a maintained date library"),
    "lodash":            ((4,17,21),"command injection in template (CVE-2021-23337) and prototype pollution; upgrade to 4.17.21+"),
    "handlebars":        ((4,7,7),"remote code execution via templates (CVE-2021-23369, CVE-2021-23383); upgrade to 4.7.7+"),
    "datatables":        ((1,10,23),"prototype pollution and XSS in DataTables before 1.10.23 (CVE-2020-28458, CVE-2021-23445); upgrade to 2.x"),
    "highcharts":        ((9,0,0),"XSS in Highcharts before 9.0.0 (CVE-2021-29489); upgrade"),
    "tinymce":           ((6,8,1),"XSS in TinyMCE before 6.8.1/7.0 (CVE-2023-48219, CVE-2024-29881); TinyMCE 4 and 5 are end of life; upgrade"),
    "chart.js":          ((2,9,4),"prototype pollution in Chart.js before 2.9.4 (CVE-2020-7746); upgrade to 4.x"),
    "jszip":             ((3,8,0),"path traversal / prototype pollution in JSZip before 3.8.0 (CVE-2022-48285, CVE-2021-23413); upgrade"),
    "gsap":              ((3,0,0),"GSAP/TweenMax 1.x-2.x (often bundled in old slider themes) is unsupported and commonly flagged in pentests; upgrade to GSAP 3"),
    "bootstrap-tagsinput": (None,"abandoned with an XSS (CVE-2016-1000227); replace it with a maintained tag input"),
}
LIB_ALIASES={"jqueryui":"jquery-ui","jquery.ui":"jquery-ui","jquery-ui-dist":"jquery-ui","angular.js":"angularjs","angular":"angularjs",
             "moment.js":"moment","lodash.js":"lodash","handlebars.js":"handlebars","twitter-bootstrap":"bootstrap",
             "jquery.validate":"jquery-validation","jquery-validate":"jquery-validation","jquery validation plugin":"jquery-validation",
             "datatables.net":"datatables","jquery.datatables":"datatables","highcharts js":"highcharts","tinymce version":"tinymce",
             "chartjs":"chart.js","tweenmax":"gsap","tweenlite":"gsap"}
LIB_NAMES=("jquery-ui-dist|jquery-ui|jqueryui|jquery\\.ui|jquery-validation|jquery\\.validate|jquery-validate|jquery|twitter-bootstrap|"
           "bootstrap-tagsinput|bootstrap|angular\\.js|angularjs|angular|moment\\.js|moment|lodash\\.js|lodash|handlebars\\.js|handlebars|"
           "datatables\\.net|jquery\\.datatables|datatables|highcharts|tinymce|chart\\.js|chartjs|jszip|gsap|tweenmax|tweenlite")
LIB_REFS=[
    re.compile(rf"(?i)\b({LIB_NAMES})[-.@/]v?(\d+\.\d+\.\d+)\b"),                    # file names, npm CDNs, cdnjs paths
    re.compile(r"(?i)\b(jQuery UI|jQuery Validation Plugin|bootstrap-tagsinput|jQuery|Bootstrap|AngularJS|DataTables|Highcharts JS|TinyMCE version|"
               r"Chart\.js|JSZip|GSAP|TweenMax|TweenLite)\s+(?:JavaScript Library\s+)?(?:-\s+)?v?(\d+\.\d+\.\d+)"),  # banners
    re.compile(r"(?i)(?:^|\n)\s*\*\s*VERSION:\s*(\d+\.\d+\.\d+)[\s\S]{0,300}?\b(TweenMax|TweenLite)\b"),  # GreenSock banner, version first
]
WEB_EXT={".html",".htm",".php",".cshtml",".vbhtml",".aspx",".ascx",".master",".jsp",".js",".css",".vue",".twig",".erb",".hbs",".ejs"}

def library_scan(target):
    findings=[]; seen=set()
    for fp in walk_files(target):
        if fp.suffix.lower() not in WEB_EXT: continue
        try:
            if fp.stat().st_size>5_000_000: continue
            head=fp.read_text(encoding="utf-8",errors="ignore")
        except OSError: continue
        is_asset=fp.suffix.lower() in (".js",".css")
        sources=[(0,fp.name)]
        lines=head[:4000].splitlines() if is_asset else head.splitlines()
        sources+= [(n,l) for n,l in enumerate(lines,1)]
        if is_asset: sources.append((1,head[:4000]))  # multi-line banners
        if is_asset and "moment.js" in head[:600].lower():
            mv=re.search(r"//!\s*version\s*:\s*(\d+\.\d+\.\d+)",head[:600])
            if mv: sources.append((1,f"moment@{mv.group(1)}"))
        for n,text in sources:
            for i,rx in enumerate(LIB_REFS):
                if i>0 and not is_asset: continue   # banners only in .js/.css; in pages, prose like "moved from jQuery 1.12.4" is not a library
                for m in rx.finditer(text):
                    name,verstr=(m.group(2),m.group(1)) if i==2 else (m.group(1),m.group(2))
                    lib=name.lower(); lib=LIB_ALIASES.get(lib,lib.replace(" ","-")); lib=LIB_ALIASES.get(lib,lib)
                    if lib not in WEB_LIBS: continue
                    ver=tuple(int(x) for x in verstr.split("."))
                    minimum,why=WEB_LIBS[lib]
                    if lib=="angularjs" and ver[0]!=1: continue  # Angular 2+ is a different, maintained framework
                    if minimum is not None and ver>=minimum: continue
                    key=(lib,ver,str(fp))
                    if key in seen: continue
                    seen.add(key)
                    findings.append({"rule":"VULNERABLE_LIBRARY","severity":"HIGH","file":str(fp),"line":n,
                        "message":f"{lib} {verstr}: {why}. Update the library (also inside themes and templates); do not comment it out or suppress it.",
                        "code":text.strip()[:180],"engine":"library-scan"})
        # End-of-life libraries are reported even when no version is visible.
        for lib in (k for k,(minimum,_) in WEB_LIBS.items() if minimum is None and k!="angularjs"):
            if any(s[0]==lib and s[2]==str(fp) for s in seen): continue
            if lib in fp.name.lower() or lib in head[:20000].lower():
                seen.add((lib,None,str(fp)))
                findings.append({"rule":"VULNERABLE_LIBRARY","severity":"HIGH","file":str(fp),"line":0,
                    "message":f"{lib} (any version): {WEB_LIBS[lib][1]}.","code":"","engine":"library-scan"})
    return findings

# --- Production configuration checks, tuned to common repeat pentest findings ---
WEBROOTS={"public","public_html","wwwroot","htdocs","www","web"}
STRICT_WEBROOTS={"public","public_html","wwwroot","htdocs"}   # "web"/"www" are often app folders in monorepos
WEBROOT_BAD_NAMES={".env",".git",".ds_store","debug.log","error_log","phpinfo.php","info.php","web.config.bak",".htpasswd"}
WEBROOT_MANIFESTS={"composer.json","composer.lock","package.json","package-lock.json","yarn.lock","vite.config.js",
                   "vite.config.ts","webpack.config.js","docker-compose.yml"}
WEBROOT_BAD_EXT=(".map",".bak",".old",".orig",".swp",".sql",".zip",".tar",".gz",".7z",".rar",".log")
WEAK_DEFAULT_CRED=re.compile(r"(?i)['\"](admin@admin\.com|admin@example\.com|test@test\.com)['\"]|"
                             r"(?:password|bcrypt|hash::make|make_password)\s*\(?\s*['\"](12345678|123456|password|admin123|admin|secret|qwerty)['\"]")
GET_STATE_CHANGE=re.compile(r"(?i)Route::get\s*\(\s*['\"][^'\"]*\b(delete|destroy|remove|update|approve|reject|toggle)\b")
COOKIE_INSECURE=re.compile(r"(?i)['\"](secure|http_only)['\"]\s*=>\s*false\b|\b(secure|httpOnly)\s*:\s*false\b")
COOKIE_CONTEXT=re.compile(r"(?i)cookie|session")
LIVE_KEYS=re.compile(r"\b(sk_live_[0-9A-Za-z]{16,}|rk_live_[0-9A-Za-z]{16,})\b")
GOOGLE_KEY=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
SRI_EXEMPT=("fonts.googleapis.com","fonts.gstatic.com")
OLD_TLS=re.compile(r"(?i)\b(ssl_protocols|SSLProtocol)\b[^\n]*\b(TLSv1(\.1)?|SSLv3)\b(?!\.[23])")
HEADER_MARKERS=("content-security-policy","x-frame-options","frame-ancestors","strict-transport-security","x-content-type-options","helmet(")
CDN_SCRIPT=re.compile(r"(?i)<(script|link)\b[^>]{0,400}\b(src|href)\s*=\s*['\"]https?://[^'\"]+['\"][^>]{0,400}>")

def config_scan(target):
    findings=[]; p=Path(target); tree=p.is_dir()
    def add(rule,sev,fp,n,msg,code=""):
        findings.append({"rule":rule,"severity":sev,"file":str(fp),"line":n,"message":msg,"code":code[:180],"engine":"config-scan"})
    header_seen=False; web_seen=False
    base=p.resolve() if tree else Path.cwd().resolve()
    for fp in walk_files_all(target):
        name=fp.name.lower(); suf=fp.suffix.lower()
        try: parts=[x.lower() for x in fp.resolve().relative_to(base).parts]   # only folders inside the project count
        except ValueError: parts=[name]
        in_webroot=any(x in WEBROOTS for x in parts[:-1])
        in_strict=any(x in STRICT_WEBROOTS for x in parts[:-1])
        if (in_webroot and (name in WEBROOT_BAD_NAMES or name.endswith(WEBROOT_BAD_EXT) or ".git" in parts)) or \
           (in_strict and name in WEBROOT_MANIFESTS):
            add("WEBROOT_EXPOSURE","HIGH",fp,0,"Development, build or backup file inside the public web root: source maps, configs, logs, "
                "backups and .git are downloadable. Remove it from the deploy, or block it in the web server.")
        if suf not in EXT and suf not in WEB_EXT and name not in ("androidmanifest.xml",".htaccess","nginx.conf","web.config") \
           and not suf in (".kt",".swift",".dart",".conf",".gradle"):
            continue
        try:
            if fp.stat().st_size>3_000_000: continue
            text=fp.read_text(encoding="utf-8-sig",errors="ignore")
        except OSError: continue
        low=text.lower()
        if suf in WEB_EXT: web_seen=True
        if not header_seen and any(m in low for m in HEADER_MARKERS): header_seen=True
        lines_all=text.splitlines()
        for n,line in enumerate(lines_all,1):
            if len(line)>4000: continue
            if ("seed" in str(fp).lower() or "fixture" in str(fp).lower() or "migration" in str(fp).lower()) and WEAK_DEFAULT_CRED.search(line):
                add("WEAK_DEFAULT_CREDENTIAL","HIGH",fp,n,"Seeded or default account with a predictable email/password. Generate a random password at setup and force a change on first login.",line.strip())
            if GET_STATE_CHANGE.search(line):
                add("STATE_CHANGE_OVER_GET","HIGH",fp,n,"A route that changes data is reachable with GET, so it has no CSRF protection (and can be triggered by a link or image). Use POST/PATCH/DELETE with the CSRF token.",line.strip())
            if COOKIE_INSECURE.search(line) and not is_test_path(fp,base) and \
               (suf==".php" or COOKIE_CONTEXT.search(" ".join(lines_all[max(0,n-4):n]))):  # nodemailer `secure:false` is not a cookie
                add("INSECURE_COOKIE_FLAG","HIGH",fp,n,"Session or auth cookie without Secure/HttpOnly. Set secure=true, http_only=true and SameSite=Lax/Strict (Laravel: SESSION_SECURE_COOKIE=true).",line.strip())
            if LIVE_KEYS.search(line):
                add("LIVE_API_KEY","CRITICAL",fp,n,"Live payment API key in source. Rotate it now and keep it on the server only; never ship it in a web or mobile app.","[redacted]")
            if GOOGLE_KEY.search(line):
                add("GOOGLE_API_KEY_IN_CODE","MEDIUM",fp,n,"Google API key in source. Browser/app keys are allowed only when restricted by HTTP referrer or app signature and to the needed APIs; confirm the restriction in Google Cloud Console.","[redacted]")
            m_tls=re.match(r"(?i)\s*(ssl_protocols|SSLProtocol)\s+([^;#\n]*)",line)
            if m_tls and any(t.lstrip("+").lower() in ("tlsv1","tlsv1.1","sslv3","sslv2") for t in m_tls.group(2).split() if not t.startswith("-")):
                add("OLD_TLS_PROTOCOL","HIGH",fp,n,"TLS 1.0/1.1 or SSLv3 enabled. Allow only TLSv1.2 and TLSv1.3 with AEAD ciphers (no CBC) and add HSTS.",line.strip())
            opts=re.match(r"(?i)^\s*Options\s+([^#\n]*)",line)
            if (opts and any(t.lower() in ("indexes","+indexes") for t in opts.group(1).split())) or re.search(r"(?i)\bautoindex\s+on\b",line):
                add("DIRECTORY_LISTING","MEDIUM",fp,n,"Directory listing is enabled. Use 'Options -Indexes' (Apache) or 'autoindex off' (nginx).",line.strip())
        if suf in (".html",".htm",".php",".cshtml",".twig",".ejs",".hbs",".vue",".jsp",".aspx"):
            for m in CDN_SCRIPT.finditer(text):
                tag=m.group(0); tl=tag.lower()
                if m.group(1).lower()=="link" and "stylesheet" not in tl: continue
                if any(x in tl for x in SRI_EXEMPT): continue
                if "integrity=" not in tl:
                    add("CDN_WITHOUT_SRI","MEDIUM",fp,text.count("\n",0,m.start())+1,"Third-party script or stylesheet without Subresource Integrity. Add integrity=\"sha384-...\" and crossorigin=\"anonymous\", or self-host it.",tag)
        if name=="androidmanifest.xml":
            for rule,rx,msg in (("ANDROID_DEBUGGABLE",r'android:debuggable\s*=\s*"true"',"debuggable=true must not ship; remove it from the release manifest."),
                                ("ANDROID_CLEARTEXT",r'android:usesCleartextTraffic\s*=\s*"true"',"Cleartext HTTP allowed; use HTTPS and a network security config."),
                                ("ANDROID_BACKUP",r'android:allowBackup\s*=\s*"true"',"allowBackup=true lets app data be copied off the device; set it to false for apps with personal data.")):
                for m in re.finditer(rx,text):
                    add(rule,"HIGH" if rule!="ANDROID_BACKUP" else "MEDIUM",fp,text.count("\n",0,m.start())+1,msg)
            for m in re.finditer(r"<(activity|service|receiver|provider)\b[^>]{0,2000}>",text):
                tag=m.group(0)
                if re.search(r'android:exported\s*=\s*"true"',tag) and "android:permission" not in tag and "android.intent.action.MAIN" not in text[m.end():m.end()+400]:
                    add("ANDROID_EXPORTED_COMPONENT","HIGH",fp,text.count("\n",0,m.start())+1,"Exported component without a permission: any app can start it. Set exported=false, or protect it and validate every intent extra and deep link.",tag)
        if name=="composer.json":
            try:
                req=(json.loads(text).get("require") or {})
                php=str(req.get("php","")); fw=str(req.get("laravel/framework",""))
                mp=re.search(r"(\d+)\.(\d+)",php); ml=re.search(r"(\d+)",fw)
                if mp and (int(mp.group(1)),int(mp.group(2)))<(8,2):
                    add("UNSUPPORTED_PLATFORM","HIGH",fp,0,f"composer.json allows PHP {php}; PHP below 8.2 no longer gets security fixes. Require ^8.2 (better 8.3+) and upgrade the server.")
                if ml and int(ml.group(1))<12:
                    add("UNSUPPORTED_PLATFORM","HIGH",fp,0,f"Laravel {fw} is out of security support. Upgrade to a supported Laravel release.")
            except Exception: pass
    fw_headers=headers_global(p) if tree else None
    if fw_headers is not None:
        name,ok,where=fw_headers
        if not ok:
            add("MISSING_SECURITY_HEADERS","MEDIUM",p/where,0,f"{name}: no security headers middleware registered for every route (checked {where}). "
                "Headers set on one page or one controller fail the retest on the login and admin pages. Register the middleware globally.")
    elif tree and web_seen and not header_seen:
        add("MISSING_SECURITY_HEADERS","MEDIUM",p,0,"No Content-Security-Policy, X-Frame-Options/frame-ancestors, HSTS or X-Content-Type-Options set anywhere in code or server config. "
            "Add a headers middleware that applies to every route, including admin and login pages.")
    return findings

def _read(fp):
    try: return fp.read_text(encoding="utf-8-sig",errors="ignore") if fp.is_file() and fp.stat().st_size<2_000_000 else ""
    except OSError: return ""

HEADER_CLASS=r"[\w\\]*(?:SecurityHeaders|SecureHeaders|Headers)\w*::class"

def headers_global(root):
    """For Laravel, Express and ASP.NET Core, a header name somewhere in the code is not enough: the
    middleware must run for every route. Returns (framework, ok, file checked) or None for other stacks."""
    root=Path(root)
    if (root/"artisan").is_file():
        boot=_read(root/"bootstrap"/"app.php"); kernel=_read(root/"app"/"Http"/"Kernel.php")
        ok=bool(re.search(r"->(?:append|prepend|use)\(\s*\[?[^;]{0,400}?"+HEADER_CLASS,boot)) or \
           (bool(re.search(r"->web\([^;]{0,400}?"+HEADER_CLASS,boot)) and bool(re.search(r"->api\([^;]{0,400}?"+HEADER_CLASS,boot))) or \
           bool(re.search(r"protected\s+\$middleware\s*=\s*\[[^\]]{0,3000}?"+HEADER_CLASS,kernel)) or \
           (bool(re.search(r"'web'\s*=>\s*\[[^\]]{0,3000}?"+HEADER_CLASS,kernel)) and bool(re.search(r"'api'\s*=>\s*\[[^\]]{0,3000}?"+HEADER_CLASS,kernel)))
        return "Laravel",ok,"bootstrap/app.php" if boot or not kernel else "app/Http/Kernel.php"
    pkg=_read(root/"package.json")
    if re.search(r'"express"\s*:',pkg):
        ok=False; where="package.json"
        for fp in walk_files(root):
            if fp.suffix.lower() in (".js",".mjs",".cjs",".ts") and "node_modules" not in fp.parts:
                t=_read(fp)
                if re.search(r"\b(?:app|server|router)\.use\(\s*helmet\s*\(",t) or \
                   re.search(r"\.use\(\s*\([^)]*\)\s*=>[^;]{0,600}(?:Content-Security-Policy|X-Content-Type-Options)",t,re.I|re.S):
                    ok=True; where=str(fp.relative_to(root)); break
        return "Express",ok,where
    if any(root.glob("*.csproj")) or any(root.glob("*/*.csproj")) or any(root.glob("*.sln")):
        progs=[fp for fp in list(root.glob("Program.cs"))+list(root.glob("*/Program.cs"))]
        t="\n".join(_read(fp) for fp in progs)
        ok=bool(re.search(r"\bUseHsts\s*\(",t)) and bool(re.search(r"(?i)UseSecurityHeaders|X-Content-Type-Options|Content-Security-Policy",t))
        return "ASP.NET Core",ok,"Program.cs"
    return None

def walk_files_all(target):
    # Like walk_files, but enters build folders (dist/build) because exposure checks need them.
    p=Path(target)
    if p.is_file(): return [p]
    skip=SKIP-{"dist","build"}; files=[]
    for r,d,fs in os.walk(p):
        d[:]=[x for x in d if x not in skip and not is_link_dir(os.path.join(r,x))]
        files.extend(Path(r)/f for f in fs if not os.path.islink(os.path.join(r,f)))
    return files

# =====================================================================================================
# 7.0 checks: legacy audit (webshells, backdoors, obfuscation), code-level pentest heuristics, PHP
# upgrade readiness and database configuration. The patterns avoid nested unbounded quantifiers, gaps
# are bounded ({0,200}), names are bounded ({0,80}) and long-blob searches start only at a run boundary.
# Lines longer than CODE_LINE_MAX are skipped by the line rules; the blob rules search at most
# BLOB_LINE_MAX characters of a line. File-level loops use precomputed line offsets and running
# counters (no rescans), and every scanner stops at MAX_PER_FILE findings per file.
# tests/test_v7_rules.py times every pattern on hostile lines and every scanner on hostile 1-3 MB files;
# the first review round found three quadratic loops that the per-line tests had missed.
# =====================================================================================================
CODE_LINE_MAX=4000
BLOB_LINE_MAX=200_000
MAX_PER_FILE=50          # findings per file and scanner; a hostile file must not flood the report
# Cheap prefilter: a line with none of these words cannot match a malware line rule.
_MAL_PREFILTER=re.compile(r"(?i)eval|assert|create_function|system|exec|passthru|popen|proc_open|include|require|\$_|`|call_user_func|"
                          r"array_map|register_|preg_replace|function|spawn|runtime|processbuilder|process|request")

def _line_starts(text):
    # Offsets of every line start, so a match offset maps to a line number with bisect in O(log n).
    out=[0]; i=text.find("\n")
    while i!=-1:
        out.append(i+1); i=text.find("\n",i+1)
    return out

def _line_at(starts,pos):
    import bisect
    return bisect.bisect_right(starts,pos)
PHP_EXT={".php",".phtml",".php3",".php4",".php5",".php7",".php8",".phar",".pht",".inc"}
SERVER_SCRIPT_EXT=PHP_EXT|{".jsp",".jspx",".asp",".aspx",".ashx",".asmx",".cer",".cgi",".pl"}
JS_EXT={".js",".mjs",".cjs",".jsx",".ts",".tsx"}
MALWARE_EXT=SERVER_SCRIPT_EXT|JS_EXT|{".py",".java",".cs",".cshtml",".vbhtml",".rb",".sh"}
IMAGE_EXT={".jpg",".jpeg",".png",".gif",".ico",".bmp",".webp"}
MALWARE_SKIP={".git","node_modules",".venv","venv","__pycache__",".security",".next"}   # vendor/ is swept on purpose
UPLOAD_DIRS={"uploads","upload","userfiles","user_uploads","user-uploads","attachments","avatars"}
WEB_ASSET_DIRS={"images","image","img","media"}

def _lang(fp):
    s=fp.suffix.lower()
    if s in PHP_EXT: return "php"
    if s in JS_EXT: return "js"
    if s==".py": return "py"
    if s in (".jsp",".jspx",".java"): return "java"
    if s in (".asp",".aspx",".ashx",".asmx",".cs",".cshtml",".vbhtml",".cer"): return "net"
    return "other"

_PHP_DECODERS=r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode|strrev|rawurldecode)"
_PHP_REQ=r"(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['\"]HTTP_|\bgetallheaders\s*\(|\bapache_request_headers\s*\(|php://input)"
_JS_REQ=r"\breq(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies)\b"
_PY_REQ=r"\brequest\s*\.\s*(?:args|form|values|data|json|get_json|GET|POST|body|headers|cookies|query_params)\b"
_JAVA_REQ=r"\b(?:request|req)\s*\.\s*(?:getParameter|getParameterValues|getHeader|getQueryString)\s*\("
_NET_REQ=r"\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Item|Headers|Cookies)\b|\[)"
MALWARE_LINE_RULES={
  # (rule, severity, regex) per language family
  "php":[
    ("WEBSHELL_OBFUSCATED_EVAL","CRITICAL",re.compile(r"(?i)(?<![\w>:$])(?:eval|assert|create_function)\s{0,10}\([^\n;]{0,200}?\b"+_PHP_DECODERS+r"\s*\(")),
    # Functions need "(" right after the name; include/require take "(", a quote or a variable. Plain words
    # in templates ("required", "System status", "Please include") are not calls.
    ("BACKDOOR_REQUEST_EXEC","CRITICAL",re.compile(r"(?i)(?<![\w>:$])(?:(?:eval|assert|create_function|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s{0,10}\(|"
                                                    r"(?:include|include_once|require|require_once)\b\s{0,10}[('\"$])[^\n;]{0,200}?"+_PHP_REQ)),
    ("BACKDOOR_REQUEST_EXEC","CRITICAL",re.compile(r"`[^`\n]{0,200}?\$_(?:GET|POST|REQUEST|COOKIE)\b")),
    ("REQUEST_DYNAMIC_CALL","CRITICAL",re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]\n]{0,80}\]\s*\(")),
    ("REQUEST_DYNAMIC_CALL","CRITICAL",re.compile(r"(?i)\b(?:call_user_func|call_user_func_array|array_map|register_shutdown_function|register_tick_function)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b")),
    ("PREG_REPLACE_EVAL","HIGH",re.compile(r"(?i)\bpreg_replace\s*\(\s*(['\"])([/#~!|@%])[^\n]{0,300}?\2[a-df-z]*e[a-z]*\1")),
  ],
  "js":[
    ("WEBSHELL_OBFUSCATED_EVAL","CRITICAL",re.compile(r"(?:(?<![\w.$])eval|\bnew\s+Function|(?<![\w.$])Function)\s{0,10}\([^\n;]{0,200}?\b(?:atob|unescape|decodeURIComponent|String\.fromCharCode|Buffer\.from)\s*\(")),
    ("BACKDOOR_REQUEST_EXEC","CRITICAL",re.compile(r"(?:(?<![\w.$])eval|\bnew\s+Function|(?<![\w.$])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)|\b(?:child_process|cp|shell)\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile)|child_process['\"]\s*\)\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile))\s{0,10}\([^\n;]{0,200}?"+_JS_REQ)),
  ],
  "py":[
    ("WEBSHELL_OBFUSCATED_EVAL","CRITICAL",re.compile(r"(?<![\w.])(?:exec|eval)\s{0,10}\([^\n]{0,200}?\b(?:base64\.b64decode|b64decode|zlib\.decompress|codecs\.decode|marshal\.loads|bytes\.fromhex|binascii\.unhexlify)\s*\(")),
    ("BACKDOOR_REQUEST_EXEC","CRITICAL",re.compile(r"(?:(?<![\w.])(?:exec|eval)|\bos\.(?:system|popen)|\bsubprocess\.\w+|\bcommands\.getoutput)\s{0,10}\([^\n]{0,200}?"+_PY_REQ)),
  ],
  "java":[
    ("BACKDOOR_REQUEST_EXEC","CRITICAL",re.compile(r"(?:Runtime\.getRuntime\(\)\s*\.\s*exec|\bnew\s+ProcessBuilder)\s{0,10}\([^\n;]{0,200}?"+_JAVA_REQ)),
  ],
  "net":[
    ("BACKDOOR_REQUEST_EXEC","CRITICAL",re.compile(r"(?i)(?:\bProcess\.Start|\bProcessStartInfo|(?<![\w.])eval)\s{0,10}\([^\n;]{0,200}?"+_NET_REQ)),
  ],
}
# Shared by every language: encoded payloads. A run of 1000+ base64 characters, hex-escape chains and
# char-code chains; decoder chains without an eval are reported too, since they usually feed one.
OBF_RULES=[
  re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{1000,}={0,2}"),
  re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}"),
  re.compile(r"(?i)(?:\bchr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){12,}"),
  re.compile(r"\bString\.fromCharCode\s*\(\s*(?:\d{1,5}\s*,\s*){24,}"),
  re.compile(r"(?i)\b(?:gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|strrev)\s*\(\s*(?:base64_decode|str_rot13|gzinflate|strrev|hex2bin)\s*\("),
]
PLACEHOLDER_PHP=re.compile(r"(?is)^\s*<\?php\s*(?://[^\n]*|#[^\n]*|/\*.*?\*/|\s)*(?:\?>)?\s*$")

def _rel_parts(fp,base):
    try: return [x for x in fp.resolve().relative_to(base).parts]
    except (ValueError,OSError): return [fp.name]

def _walk(target,skip):
    p=Path(target)
    if p.is_file(): return [p]
    out=[]
    for r,d,fs in os.walk(p):
        d[:]=[x for x in d if x not in skip and not is_link_dir(os.path.join(r,x))]
        out.extend(Path(r)/f for f in fs if not os.path.islink(os.path.join(r,f)))
    return out

def malware_scan(target):
    """Legacy audit: webshells, request-driven backdoors, PHP where only uploads belong, encoded blobs.
    Findings are for the owner to review; nothing is deleted or changed."""
    findings=[]; p=Path(target); base=p.resolve() if p.is_dir() else Path.cwd().resolve()
    def add(rule,sev,fp,n,msg,code=""):
        findings.append({"rule":rule,"severity":sev,"file":str(fp),"line":n,"message":msg+" Show it to the owner before deleting anything.",
                         "code":code.strip()[:180],"engine":"malware-scan"})
    for fp in _walk(target,MALWARE_SKIP):
        suf=fp.suffix.lower(); name=fp.name.lower()
        parts=_rel_parts(fp,base); dirs=parts[:-1]; low_dirs=[x.lower() for x in dirs]
        try: size=fp.stat().st_size
        except OSError: continue
        if suf in IMAGE_EXT:
            if size<=5_000_000:
                try:
                    with open(fp,"rb") as fh: blob=fh.read(5_000_000)
                except OSError: continue
                # <?php, or the short echo tag <?= followed soon by a variable, backtick or ?> (a bare 3-byte "<?="
                # turns up by chance in large binaries, so it needs the second marker).
                if re.search(rb"(?i)<\?php|<\?=[^\x00\n]{0,200}?(?:\$\w|`|\?>)",blob):
                    add("PHP_IN_IMAGE_FILE","HIGH",fp,0,"An image file contains PHP code (<?php or <?=). This is how upload webshells hide; "
                        "an include or a server that runs it turns it into code execution.")
            continue
        if suf not in MALWARE_EXT or size>3_000_000: continue
        try: text=fp.read_text(encoding="utf-8",errors="ignore")
        except OSError: continue
        if suf in SERVER_SCRIPT_EXT:
            webroot_idx=[i for i,x in enumerate(low_dirs) if x in WEBROOTS|{"pub"}]
            joined="/".join(low_dirs)
            # Lowercase upload folder names count anywhere. Under the web root or at the top level, any casing
            # counts (Uploads/, Images/ are the same folder on IIS and Windows); deeper in the source tree a
            # capitalised folder such as app/Uploads/ is a PSR-4 namespace, not an upload folder.
            exposed=lambda i: bool((webroot_idx and i>webroot_idx[0]) or i==0)
            in_upload=any(x in UPLOAD_DIRS for x in dirs) or "wp-content/uploads" in joined or "storage/app/public" in joined \
                or "public/storage" in joined or \
                any((d in UPLOAD_DIRS or d in WEB_ASSET_DIRS) and exposed(i) for i,d in enumerate(low_dirs))
            if in_upload and not (len(text)<=2000 and PLACEHOLDER_PHP.match(text)):
                add("PHP_IN_UPLOAD_DIR","HIGH",fp,0,"A server-side script sits in an upload, image or media folder. Real apps never "
                    "keep code there; it is the usual place for an uploaded webshell. Also block script execution in that folder.")
        lang=_lang(fp); rules=MALWARE_LINE_RULES.get(lang,[])
        in_vendor="vendor" in low_dirs
        minified=name.endswith((".min.js",".min.mjs",".bundle.js"))
        per_file=0
        for n,line in enumerate(text.splitlines(),1):
            if per_file>=MAX_PER_FILE: break
            if not line.strip(): continue
            seg=line[:BLOB_LINE_MAX]
            stripped=seg.lstrip()
            comment=stripped.startswith(("//","#","*","/*","--"))
            if not comment and len(seg)<=CODE_LINE_MAX and _MAL_PREFILTER.search(seg):
                for rid,sev,rx in rules:
                    m=rx.search(seg)
                    if not m: continue
                    s=sev
                    if rid=="BACKDOOR_REQUEST_EXEC" and re.search(r"(?i)escapeshellarg|escapeshellcmd|\(int\)|intval\s*\(",seg):
                        s="HIGH"
                    # An argument list (spawn('ls', ['-l', req.query.d]), subprocess.run([... request.args ...])) is
                    # argument injection, not a shell or eval of the whole value.
                    if rid=="BACKDOOR_REQUEST_EXEC" and lang in ("js","py") and "[" in m.group(0):
                        s="HIGH"
                    per_file+=1
                    add(rid,s,fp,n,{"WEBSHELL_OBFUSCATED_EVAL":"Code execution (eval/assert/exec/Function) fed by a decoder chain: the classic obfuscated webshell or injected backdoor.",
                                    "BACKDOOR_REQUEST_EXEC":"A request value (query, body, cookie, header) reaches a code or command execution function. Remote code execution, or a planted backdoor.",
                                    "REQUEST_DYNAMIC_CALL":"The request chooses which function runs ($_GET['f'](...)). This is a one-line webshell pattern.",
                                    "PREG_REPLACE_EVAL":"preg_replace with the /e modifier evaluates the replacement as PHP (removed in PHP 7). In legacy code this is a backdoor or an RCE."}[rid],seg)
                    break
            if in_vendor or minified: continue
            for rx in OBF_RULES:
                m=rx.search(seg)
                if not m: continue
                if rx is OBF_RULES[0] and "base64," in seg[max(0,m.start()-40):m.start()]: continue   # data: URI
                # Only a short excerpt: the blob may be a key or a token, so the report does not copy it.
                add("SUSPICIOUS_OBFUSCATION","MEDIUM",fp,n,"Encoded or obfuscated content in code (a long base64 run, hex or char-code chains, or a decoder chain). "
                    "Decode it and check what it does; legitimate code rarely ships payloads like this.",
                    seg[:m.start()][-60:]+seg[m.start():m.start()+16]+("..." if m.end()-m.start()>16 else ""))
                per_file+=1
                break
    return findings

# --- code-level heuristics from pentest findings ---
_INPUT_LARAVEL=re.compile(r"(?:\$request|\brequest\(\))\s*->\s*(?:input|all|get|query|post|only|except|json|string|integer|float|boolean|date|collect|file|array)\s*\(|\$_(?:GET|POST|REQUEST)\s*\[|\bRequest::(?:input|all|get|query|post)\s*\(")
_VALIDATED_LARAVEL=re.compile(r"->\s*validate(?:WithBag)?\s*\(|\bValidator::make\s*\(|->\s*validated\s*\(|\bvalidator\s*\(|->\s*safe\s*\(|\$this->validate\s*\(")
_FORM_REQUEST=re.compile(r"\b(?!Request\b)[A-Z]\w*Request\s+\$\w+")
_METHOD=re.compile(r"\bfunction\s+(\w+)\s*\(([^)]{0,600})\)")
_EXPRESS_ROUTE=re.compile(r"\b(?:app|router|\w*[Rr]outer|api|server)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(")
_EXPRESS_BODY=re.compile(r"\breq\s*\.\s*body\b")
_VALIDATOR_LIBS=re.compile(r"(?:require\s*\(\s*|from\s+|import\s+)['\"](?:zod|joi|@hapi/joi|express-validator|celebrate|yup|ajv|class-validator|superstruct|valibot|fastest-validator|@sinclair/typebox|io-ts|express-joi-validation|@vinejs/vine)['\"]|\b(?:z\.object|Joi\.object|checkSchema|celebrate\s*\(|\.safeParse\s*\(|ajv\.compile|validationResult\s*\()")

_DEBUG_ACCESSOR=re.compile(r"(?i)(?:\$request\s*->\s*(?:input|query|get|header|boolean|has|filled|cookie)\s*\(|\brequest\(\)\s*->\s*\w+\s*\(|\brequest\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[|\breq\s*\.\s*(?:query|body|headers|params|cookies)\s*(?:\.|\[|\.get\s*\()|\brequest\s*\.\s*(?:args|form|values|GET|POST|headers|cookies|query_params)\s*(?:\.\s*get\s*\(|\[)|\bget(?:Parameter|Header)\s*\(|@Request(?:Param|Header)\s*\(\s*(?:(?:value|name)\s*=\s*)?)"
                          r"\s*['\"]?(?:http_x_|x[-_])?(?:debug|verbose|trace|dev|devmode|dev_mode|test|testmode|test_mode|internal|admin|is_admin|isadmin|show_?errors|diag|diagnostics)['\"]?(?![\w-])")
_DEBUG_SINK=re.compile(r"(?i)\b(?:config|env|getenv|phpinfo|var_dump|print_r|var_export|debug_backtrace|getTraceAsString|getTrace|printStackTrace|getStackTrace|traceback|System\.getenv|System\.getProperties|dump_settings)\s*\(|process\.env|os\.environ|\.stack\b|ini_set\s*\(\s*['\"]display_errors|error_reporting\s*\(\s*E_ALL|\bapp\.config\b|settings\.__dict__|\bis_?admin\b|\$_SESSION\s*\[|->setRole\s*\(|\brole\s*=")
_LOGLEVEL_SINK=re.compile(r"(?i)setLevel\s*\(|log_?level|logger\.level")
_LOCAL_ONLY=re.compile(r"(?i)isLocal\s*\(|environment\s*\(\s*['\"](?:local|testing)|APP_ENV|NODE_ENV\s*[!=]==?\s*['\"]development|settings\.DEBUG\b|isDevelopment\s*\(")

# The name is bounded ({0,80}) and must start right after a non-word, non-$ character, so a line like
# "a$a$a$..." cannot restart a long scan at every letter (that was quadratic per line).
_ASSIGN=re.compile(r"(?<![\w$])\$?([A-Za-z_]\w{0,80})['\"]?\]?\s*(?:=>|=(?![=>])|:(?![:=]))\s*([^\n]{1,300})")
_WEAK_TOKEN_SRC=re.compile(r"(?i)\b(?:base64_encode|btoa|md5|sha1|hash|crc32|uniqid|microtime|time|b64encode|strrev|str_rot13|encodeURIComponent)\s*\(|\bDate\.now\s*\(|\bhashlib\.\w+\s*\(|\bBuffer\.from\s*\(|\bDigestUtils\.\w+\s*\(|\bgetEncoder\s*\(")
_USER_MARKER=re.compile(r"(?i)\b(?:id|user_?id|uid|email|username|user|role|name|phone|mobile)\b|time\s*\(|Date\.now|microtime|uniqid|new\s+Date")
_CSPRNG=re.compile(r"(?i)random_bytes|openssl_random_pseudo_bytes|Str::random|Str::uuid|random_int|crypto\.randomBytes|randomUUID|getRandomValues|\bsecrets\.|SecureRandom|token_urlsafe|token_hex|urandom|uuid4|bin2hex\s*\(\s*random|nanoid|hash_hmac|\bhmac\.|createHmac|csrf_token\s*\(|Str::password")
_SHORT_RANGE=re.compile(r"\b(?:random_int|rand|mt_rand|randint|randrange|randomInt)\s*\(\s*(\d{1,9})\s*,\s*(\d{1,9})\s*\)|\bnextInt\s*\(\s*(\d{1,9})\s*\)|Math\.random\s*\(\s*\)\s*\*\s*(\d{1,9})\b")
_SHORT_TOKEN=re.compile(r"(?:\bStr::random|\brandom_bytes|\bcrypto\.randomBytes|\brandomBytes|\btoken_hex|\btoken_urlsafe|\btoken_bytes)\s*\(\s*(\d{1,3})\s*\)")
_NAME_WORDS=re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_NOT_A_TOKEN={"at","time","date","expires","expiry","expire","count","attempts","until","url","link","path","route","sent","ttl","length","len","exists","valid","is","has","enabled","field","header","name","label"}

def _words(name):
    return {w.lower() for w in _NAME_WORDS.findall(name.replace("$",""))}

def _token_like(name):
    w=_words(name)
    if w & _NOT_A_TOKEN: return False
    return bool(w & {"token","csrf","otp","nonce","invite","verification","verify","apikey","reset","remember"}) or \
        {"api","key"}<=w or {"session","id"}<=w

def _code_like(name):
    w=_words(name)
    if w & _NOT_A_TOKEN: return False
    return bool(w & {"otp","code","pin","passcode","token"})

PUBLIC_ENV=re.compile(r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP|PUBLIC)_[A-Z0-9_]{0,80}")
PUBLIC_ENV_SECRET_WORD=re.compile(r"SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|SERVICE_KEY|ACCESS_KEY|ADMIN_KEY|_TOKEN$|_TOKEN_|DATABASE_URL|DB_URL|DB_PASS|SIGNING_KEY|WEBHOOK_KEY")
PUBLIC_ENV_OK=re.compile(r"PUBLISHABLE|SITE_KEY|ANON_KEY|MAPBOX|RECAPTCHA|TURNSTILE|HCAPTCHA|POSTHOG|SENTRY_DSN|MEASUREMENT|_GA_|PUBLIC_KEY|CLIENT_ID")
SOURCEMAP_CFG=re.compile(r"\bproductionSourceMap\s*:\s*true\b|\bproductionBrowserSourceMaps\s*:\s*true\b|\bsourcemap\s*:\s*(?:true\b|['\"]inline['\"])|"
                         r"\bdevtool\s*:\s*['\"](?:source-map|inline-source-map|eval-source-map|cheap-module-source-map|cheap-source-map|eval)['\"]|\bGENERATE_SOURCEMAP\s*=\s*true\b")
BUILD_DIRS={"dist","build","out"}

_AUTH_PATH=re.compile(r"(?i)log-?in|sign-?in|password|passwd|reset|forgot|otp|verify|verification|2fa|two-factor|mfa|register|sign-?up|/pin\b|auth/code")
_CODE_PATH=re.compile(r"(?i)otp|2fa|two-factor|mfa|verify|verification|/pin\b|code")
_LARAVEL_ROUTE=re.compile(r"Route::(post|put|patch|any|match)\s*\(\s*(?:\[[^\]\n]{0,80}\]\s*,\s*)?['\"]([^'\"\n]{0,200})['\"]")
_EXPRESS_AUTH_ROUTE=re.compile(r"\b(?:app|router|\w*[Rr]outer|api|server)\s*\.\s*(post|put|patch|all)\s*\(\s*['\"`]([^'\"`\n]{0,200})['\"`]([^\n]{0,400})")
_LIMITER_WORD=re.compile(r"(?i)throttle|limit|slowdown|slow_down|brute|ratelimit")
_EXPRESS_GLOBAL_LIMIT=re.compile(r"(?i)\.use\s*\([^\n]{0,200}?(?:limit|throttle|slowdown|brute)")
_LARAVEL_LIMITER=re.compile(r"RateLimiter::|ensureIsNotRateLimited|ThrottlesLogins|->middleware\(\s*['\"]throttle")

_DENY_CHECK=re.compile(r"(?i)(?:\bstr_contains|\bstripos|\bstrpos|\bstrstr|\bstristr|\bpreg_match|\.includes|\.indexOf|\.contains|\.startsWith|\.endsWith|\bin_array|\bre\.(?:search|match)|\.test)\s*\(")
_ATTACK_LITERAL=re.compile(r"""(?i)(['"])(?:'|\\'|"|<script>?|</script>|union(?:\s+select)?|select|drop(?:\s+table)?|\.\./|--|or\s+1\s*=\s*1|javascript:|onerror|;|\||&&|%27|sleep\()\1""")
_PY_IN_CHECK=re.compile(r"""(?i)(['"])(?:'|"|<script>?|union(?:\s+select)?|select|drop|\.\./|--|or\s+1\s*=\s*1|;|\|)\1\s+(?:not\s+)?in\s+\w""")
# Sinks still built from strings. SQL is stricter than SQL_CONCAT here: a quote directly followed by a
# concatenation operator, ${...}, {$...} or an f-string, so a bound parameter list ("?', [$q]") is not a sink.
_DENY_SINKS=[re.compile(r) for k,_,r in RULES if k in ("XSS_SINK","XSS_RAW_TEMPLATE","VUE_RAW_HTML","COMMAND_INJECTION")]+[
    re.compile(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]{0,300}?(?:[\"'`]\s*(?:\.|\+)\s*[$\w(]|\$\{|\{\$|\bf[\"'])")]
_DENY_SINK_EXTRA=re.compile(r"(?i)\b(?:echo|print)\s+[^\n;]{0,200}?\$\w|\b(?:system|exec|passthru|shell_exec|popen)\s*\([^\n)]{0,200}?\$|\.query\s*\(\s*[`'\"][^\n]{0,300}?(?:\+|\$\{)|\bres\.send\s*\([^\n]{0,200}?\+")

# PHP upgrade readiness. Each entry: (deprecated in, removed in or "", replacement). Verified on
# 2026-11-03 against php.net migration guides (migration70.incompatible, migration70.removed-exts-sapis,
# migration70..85.deprecated, migration80.incompatible, migration84.removed-extensions) and php-src
# PHP-8.5 UPGRADING. https://www.php.net/manual/en/migration85.deprecated.php
PHP_DEPRECATED_FUNCS={
  "call_user_method":("","7.0","call_user_func"),"call_user_method_array":("","7.0","call_user_func_array"),
  "set_magic_quotes_runtime":("","7.0","remove it"),"magic_quotes_runtime":("","7.0","remove it"),
  "set_socket_blocking":("","7.0","stream_set_blocking"),"datefmt_set_timezone_id":("","7.0","datefmt_set_timezone"),
  "ereg":("","7.0","preg_match"),"eregi":("","7.0","preg_match with /i"),"ereg_replace":("","7.0","preg_replace"),
  "eregi_replace":("","7.0","preg_replace with /i"),"ldap_sort":("7.0","8.0","sort the results in PHP"),
  "create_function":("7.2","8.0","an anonymous function"),"each":("7.2","8.0","foreach"),
  "png2wbmp":("7.2","8.0","imagewbmp"),"jpeg2wbmp":("7.2","8.0","imagewbmp"),"gmp_random":("7.2","8.0","gmp_random_bits or gmp_random_range"),
  "read_exif_data":("7.2","8.0","exif_read_data"),"image2wbmp":("7.3","8.0","imagewbmp"),"fgetss":("7.3","8.0","fgets plus strip_tags"),
  "gzgetss":("7.3","8.0","gzgets plus strip_tags"),"is_real":("7.4","8.0","is_float"),"get_magic_quotes_gpc":("7.4","8.0","remove it (always false)"),
  "get_magic_quotes_runtime":("7.4","8.0","remove it (always false)"),"hebrevc":("7.4","8.0","nl2br(hebrev(...))"),
  "convert_cyr_string":("7.4","8.0","mb_convert_encoding or iconv"),"money_format":("7.4","8.0","NumberFormatter"),
  "ezmlm_hash":("7.4","8.0","remove it"),"restore_include_path":("7.4","8.0","ini_restore('include_path')"),
  "ldap_control_paged_result":("7.4","8.0","controls in ldap_search"),"ldap_control_paged_result_response":("7.4","8.0","controls in ldap_search"),
  "libxml_disable_entity_loader":("8.0","","nothing (libxml 2.9+ blocks external entities by default; never pass LIBXML_NOENT)"),
  "date_sunrise":("8.1","","date_sun_info"),"date_sunset":("8.1","","date_sun_info"),"strptime":("8.1","","date_parse_from_format"),
  "strftime":("8.1","","date() or IntlDateFormatter"),"gmstrftime":("8.1","","gmdate() or IntlDateFormatter"),
  "mhash":("8.1","","hash()"),"mhash_keygen_s2k":("8.1","","hash_pbkdf2"),"mhash_count":("8.1","","hash_algos"),
  "mhash_get_block_size":("8.1","","hash functions"),"mhash_get_hash_name":("8.1","","hash functions"),"odbc_result_all":("8.1","","fetch rows yourself"),
  "utf8_encode":("8.2","","mb_convert_encoding"),"utf8_decode":("8.2","","mb_convert_encoding"),"assert_options":("8.3","","zend.assertions / exceptions"),
  "lcg_value":("8.4","","Random\\Randomizer::getFloat()"),"mysqli_ping":("8.4","","reconnect on error"),"mysqli_kill":("8.4","","SQL KILL"),
  "mysqli_refresh":("8.4","","SQL FLUSH"),"xml_set_object":("8.4","","closures as handlers"),
  "curl_close":("8.5","","nothing (the handle is freed automatically)"),"curl_share_close":("8.5","","nothing"),"finfo_close":("8.5","","nothing"),
  "imagedestroy":("8.5","","nothing (GdImage is freed automatically)"),"xml_parser_free":("8.5","","nothing"),
  "mysqli_execute":("8.5","","mysqli_stmt_execute"),"socket_set_timeout":("8.5","","stream_set_timeout"),"pg_service":("","8.5","remove it"),
}
PHP_DEPRECATED_PREFIX={"mysql_":("","7.0","mysqli or PDO"),"mssql_":("","7.0","PDO_SQLSRV"),"mcrypt_":("7.1","7.2","OpenSSL or sodium"),
                       "zip_entry_":("8.0","","ZipArchive"),"imap_":("","8.4 (moved to PECL)","a maintained mail library"),
                       "pspell_":("","8.4 (moved to PECL)","PECL pspell or another checker")}
PHP_DEPRECATED_RX=re.compile(r"(?<![\w>:$.])\\?(" + "|".join(sorted((re.escape(k) for k in PHP_DEPRECATED_FUNCS),key=len,reverse=True)) +
                             r"|(?:mysql_|mssql_|mcrypt_|zip_entry_|imap_|pspell_)\w{1,40})\s*\(")
PHP_DEPRECATED_SYNTAX=[
  (re.compile(r"\((?:boolean|integer|double|binary)\)\s*[$(\w'\"]"),"8.5","","non-canonical cast; use (bool), (int), (float), (string)"),
  (re.compile(r"\((?:real|unset)\)\s*[$(\w'\"]"),"7.4/7.2","8.0","(real) and (unset) casts; use (float) or unset()"),
  (re.compile(r"\"[^\"\n]{0,300}?\$\{[A-Za-z_]"),"8.2","","\"${var}\" interpolation; use \"{$var}\""),
  (re.compile(r"(?<![\w>:$])get_(?:parent_)?class\s*\(\s*\)"),"8.3","","get_class() without an argument; use static::class or self::class"),
  (re.compile(r"\btrigger_error\s*\([^\n]{0,200}?\bE_USER_ERROR\b"),"8.4","","trigger_error with E_USER_ERROR; throw an exception"),
  (re.compile(r"\bE_STRICT\b"),"8.4","","E_STRICT; remove it"),
  (re.compile(r"\bFILTER_SANITIZE_(?:STRING|STRIPPED)\b"),"8.1","","FILTER_SANITIZE_STRING; use htmlspecialchars on output"),
  (re.compile(r"\bFILTER_SANITIZE_MAGIC_QUOTES\b|\bFILTER_FLAG_(?:SCHEME|HOST)_REQUIRED\b"),"7.3/7.4","8.0","removed filter constant"),
  (re.compile(r"\bDATE_RFC7231\b"),"8.5","","DATE_RFC7231; use DATE_RFC1123 or a format string"),
  (re.compile(r"\bMT_RAND_PHP\b"),"8.3","","MT_RAND_PHP; use the default MT_RAND_MT19937"),
  (re.compile(r"\bCURLOPT_BINARYTRANSFER\b"),"8.4","","CURLOPT_BINARYTRANSFER; remove it (no effect)"),
  (re.compile(r"\$HTTP_RAW_POST_DATA\b"),"","7.0","$HTTP_RAW_POST_DATA; read php://input"),
  (re.compile(r"\$php_errormsg\b"),"7.2","8.0","$php_errormsg; use error_get_last()"),
  (re.compile(r"\$http_response_header\b"),"8.5","","$http_response_header; use http_get_last_response_headers()"),
  (re.compile(r"\bfunction\s+__autoload\s*\("),"7.2","8.0","__autoload(); use spl_autoload_register"),
  (re.compile(r"\bfunction\s+&?\w*\s*\((?:[^)\n]{0,400}?,)?\s*(?:(?:public|private|protected|readonly)\s+){0,3}(?!(?:mixed|null)\b)[A-Za-z_\\][\w\\]{0,80}\s+&?(?:\.\.\.)?\$\w+\s*=\s*null\b"),"8.4","",
   "implicitly nullable parameter (Type $x = null); write ?Type $x = null"),
]

def _is_example(name):
    n=name.lower()
    return any(x in n for x in (".example",".sample",".dist",".template","example.","sample.")) or n.endswith((".example",".sample",".dist"))

def code_scan(target):
    """Code-level heuristics from repeat pentest findings: missing input validation, client-controlled
    debug switches, weak tokens, secrets in public env names, source maps in production builds, no
    throttle on auth routes, deny-list "fixes" and PHP upgrade blockers. Test files are skipped."""
    findings=[]; p=Path(target); base=p.resolve() if p.is_dir() else Path.cwd().resolve()
    per_file={}
    def add(rule,sev,fp,n,msg,code=""):
        k=str(fp); per_file[k]=per_file.get(k,0)+1
        if per_file[k]>MAX_PER_FILE: return
        # Quoted literals of 8+ characters (salts, keys) are masked; credentials too.
        code=_redact(re.sub(r"(['\"])[^'\"\n]{8,300}\1",r"\1[literal]\1",code.strip()))
        findings.append({"rule":rule,"severity":sev,"file":str(fp),"line":n,"message":msg,"code":code[:180],"engine":"code-scan"})
    files=walk_files_all(target)
    laravel_limiter=False
    # A linked app/ folder can point anywhere on the machine; never walk it.
    if p.is_dir() and (p/"app").is_dir() and not is_link_dir(str(p/"app")):
        for fp in _walk(p/"app",SKIP):
            if fp.suffix.lower()==".php" and _LARAVEL_LIMITER.search(_read(fp)): laravel_limiter=True; break
    for fp in files:
        name=fp.name.lower(); suf=fp.suffix.lower()
        parts=_rel_parts(fp,base); low_dirs=[x.lower() for x in parts[:-1]]
        if suf==".map" and any(d in BUILD_DIRS for d in low_dirs) and not any(d in WEBROOTS for d in low_dirs):
            add("SOURCEMAP_IN_PROD","MEDIUM",fp,0,"Source map in a production build folder. Deployed, it gives anyone the original front-end source, "
                "including hidden routes, keys and business rules. Turn source maps off for production builds or keep them off the server.")
            continue
        envfile=name==".env" or name.startswith(".env.")
        if not (envfile or suf in EXT or suf in WEB_EXT or suf in (".mjs",".cjs",".svelte",".properties")): continue
        if is_test_path(fp,base): continue
        try:
            if fp.stat().st_size>3_000_000: continue
            text=fp.read_text(encoding="utf-8-sig",errors="ignore")
        except OSError: continue
        lines=text.splitlines()
        is_php=suf in PHP_EXT; is_js=suf in JS_EXT or suf in (".vue",".svelte")
        # Secrets under public env prefixes: the bundler inlines them into the browser bundle.
        if envfile or is_js or suf in (".json",".yml",".yaml") or name.startswith(("next.config","vite.config","nuxt.config")) or name=="dockerfile":
            if suf!=".json" or name=="package.json":
                seen=set()
                for n,line in enumerate(lines,1):
                    if len(line)>CODE_LINE_MAX: continue
                    for m in PUBLIC_ENV.finditer(line):
                        v=m.group(0)
                        if v in seen or not PUBLIC_ENV_SECRET_WORD.search(v) or PUBLIC_ENV_OK.search(v): continue
                        seen.add(v)
                        add("PUBLIC_ENV_SECRET","HIGH",fp,n,f"{v}: a secret-looking name under a public prefix. Bundlers copy these values into the "
                            "JavaScript every visitor downloads. Keep the secret on the server (no public prefix) and rotate it if it was ever built.",v)
        if name.startswith(("vite.config","webpack","vue.config","next.config","nuxt.config")) and "dev" not in name or name.startswith(".env.production"):
            for n,line in enumerate(lines,1):
                if len(line)<=CODE_LINE_MAX and SOURCEMAP_CFG.search(line) and not line.lstrip().startswith(("//","#","*")):
                    add("SOURCEMAP_IN_PROD","MEDIUM",fp,n,"Production build emits public source maps. Set it to false (or 'hidden' and upload maps "
                        "to your error tracker only).",line)
        if envfile or suf in (".json",".properties",".yml",".yaml",".xml",".sql",".md"): continue
        # --- per-line rules on code ---
        for n,line in enumerate(lines,1):
            if len(line)>CODE_LINE_MAX or not line.strip(): continue
            st=line.lstrip()
            if st.startswith(("//","#","*","/*","--")): continue
            # Client-controlled debug or admin switch.
            if _DEBUG_ACCESSOR.search(line) and not _LOCAL_ONLY.search(line):
                win="\n".join(lines[n-1:n+8])
                cond=re.search(r"\bif\b|\?|&&|\|\||==|@Request|\bwhen\s*\(|=",line)
                if cond and _DEBUG_SINK.search(win):
                    add("DEBUG_FLAG_FROM_REQUEST","HIGH",fp,n,"A request parameter or header (debug, test, admin, verbose...) switches on config, env, stack "
                        "trace or role output. Anyone can send it in production. Remove the switch, or tie it to the server environment only "
                        "(app()->isLocal(), NODE_ENV) with no request input.",line)
                elif cond and _LOGLEVEL_SINK.search(win):
                    add("DEBUG_FLAG_FROM_REQUEST","MEDIUM",fp,n,"A request parameter changes the log level. Callers can flood logs or expose detail; "
                        "control logging from server configuration only.",line)
            # Tokens built from user data or time, short codes and short tokens.
            m=_ASSIGN.search(line)
            if m:
                lhs,rhs=m.group(1),m.group(2)
                if _token_like(lhs) and _WEAK_TOKEN_SRC.search(rhs) and _USER_MARKER.search(rhs) and not _CSPRNG.search(rhs):
                    add("TOKEN_FROM_USER_DATA","HIGH",fp,n,f"{lhs} is built from user data or the clock (encode or hash of id, email, role or time). "
                        "Anyone who knows the inputs can compute it. Use a CSPRNG token of at least 128 bits (random_bytes(32), "
                        "crypto.randomBytes(32), secrets.token_urlsafe(32)), store only its hash, make it single use and expire it.",line)
                elif _code_like(lhs):
                    r=_SHORT_RANGE.search(rhs)
                    if r:
                        hi=int(next(g for g in (r.group(2),r.group(3),r.group(4)) if g))
                        if hi<100000:
                            add("SHORT_NUMERIC_CODE","MEDIUM",fp,n,f"{lhs} is a numeric code under 6 digits. Without a strict attempt limit it can be "
                                "guessed in minutes. Use 6+ digits from random_int / secrets, expire it, and throttle and lock after a few wrong tries.",line)
                if _token_like(lhs):
                    t=_SHORT_TOKEN.search(rhs)
                    if t and int(t.group(1))<16:
                        add("TOKEN_TOO_SHORT","MEDIUM",fp,n,f"{lhs} is too short to be unguessable. Use at least 16 random bytes (32 hex or "
                            "22 base64 characters), for example random_bytes(32) or Str::random(40).",line)
            # A deny-list "fix" in front of a sink that is still built from strings.
            if (_DENY_CHECK.search(line) and _ATTACK_LITERAL.search(line)) or _PY_IN_CHECK.search(line):
                win=lines[n:n+10]
                if any(len(l)<=CODE_LINE_MAX and (any(x.search(l) for x in _DENY_SINKS) or _DENY_SINK_EXTRA.search(l)) for l in win):
                    add("DENYLIST_FIX","MEDIUM",fp,n,"Deny-list fix: the code rejects one attack-looking string, but the query, output or command below "
                        "is still built from strings. Other spellings get through and the retest fails. Fix the sink itself (parameters, "
                        "output encoding, argument arrays) and drop the string check.",line)
        # Missing input validation (Laravel controllers, Express handlers).
        starts=None
        if is_php and re.search(r"\bclass\s+\w*Controller\b",text):
            starts=_line_starts(text)
            ms=list(_METHOD.finditer(text))
            for i,mm in enumerate(ms):
                if per_file.get(str(fp),0)>=MAX_PER_FILE: break
                body=text[mm.end():ms[i+1].start() if i+1<len(ms) else len(text)]
                if _FORM_REQUEST.search(mm.group(2)) or _VALIDATED_LARAVEL.search(body): continue
                iu=_INPUT_LARAVEL.search(body)
                if iu:
                    ln=_line_at(starts,mm.end()+iu.start())
                    add("MISSING_INPUT_VALIDATION","MEDIUM",fp,ln,f"{mm.group(1)}() reads request input with no validation step. Use a FormRequest "
                        "(or $request->validate([...])) with rules for type, length and format, then read only $request->validated().",lines[ln-1] if ln<=len(lines) else "")
        if is_js and _EXPRESS_ROUTE.search(text) and not _VALIDATOR_LIBS.search(text):
            mb=_EXPRESS_BODY.search(text)
            if mb:
                ln=_line_at(starts or _line_starts(text),mb.start())
                add("MISSING_INPUT_VALIDATION","MEDIUM",fp,ln,"Route handlers here read req.body, but no validator (zod, joi, express-validator, "
                    "celebrate, yup, ajv) is used in this file. Validate every body against a schema at the start of the handler and use "
                    "only the parsed result.",lines[ln-1] if ln<=len(lines) else "")
        # No throttle on login, OTP, reset and verify routes.
        if is_php and "routes" in low_dirs:
            depth=0; stack=[]; thr_open=0      # thr_open: throttled groups currently open (no list scans)
            for n,line in enumerate(lines,1):
                if len(line)>CODE_LINE_MAX: continue
                if "group(" in line or "Route::group" in line:
                    header=" ".join(lines[max(0,n-4):n])
                    thr="throttle" in header.lower()
                    opened=line.count("{")-line.count("}")
                    if opened>0 and len(stack)<500: stack.append((depth+1,thr)); thr_open+=thr
                    depth+=opened
                else:
                    depth+=line.count("{")-line.count("}")
                while stack and stack[-1][0]>depth: thr_open-=stack.pop()[1]
                m=_LARAVEL_ROUTE.search(line)
                if not m or not _AUTH_PATH.search(m.group(2)): continue
                if per_file.get(str(fp),0)>=MAX_PER_FILE: break
                stmt=line
                k=n
                while ";" not in stmt and k<len(lines) and k<n+6: stmt+=lines[k]; k+=1
                if "throttle" in stmt.lower() or thr_open>0 or "public-object" in stmt: continue
                sev="LOW" if laravel_limiter else ("HIGH" if _CODE_PATH.search(m.group(2)) else "MEDIUM")
                add("AUTH_ROUTE_NO_THROTTLE",sev,fp,n,f"'{m.group(2)}' takes credentials or codes but has no throttle middleware. Add "
                    "->middleware('throttle:5,1') (or a RateLimiter::for named limiter) and lock out after repeated failures."+
                    (" A RateLimiter is used elsewhere in app/; confirm it covers this route." if laravel_limiter else ""),line)
        if is_js and not _EXPRESS_GLOBAL_LIMIT.search(text):
            for n,line in enumerate(lines,1):
                if len(line)>CODE_LINE_MAX: continue
                m=_EXPRESS_AUTH_ROUTE.search(line)
                if not m or not _AUTH_PATH.search(m.group(2)) or _LIMITER_WORD.search(m.group(3)): continue
                add("AUTH_ROUTE_NO_THROTTLE","HIGH" if _CODE_PATH.search(m.group(2)) else "MEDIUM",fp,n,f"'{m.group(2)}' takes credentials "
                    "or codes but no rate limiter is applied (express-rate-limit or similar, on the route or with app.use). Add one and lock "
                    "out after repeated failures.",line)
        # PHP upgrade readiness (LOW): one finding per function or construct per file.
        if is_php:
            seen={}
            blade=name.endswith(".blade.php")
            for n,line in enumerate(lines,1):
                if len(line)>CODE_LINE_MAX: continue
                st=line.lstrip()
                if st.startswith(("//","#","*","/*")): continue
                for m in PHP_DEPRECATED_RX.finditer(line):
                    fn=m.group(1).lower()
                    if re.search(r"function\s+&?$",line[:m.start()]): continue
                    if fn in PHP_DEPRECATED_FUNCS: dep,rem,rep=PHP_DEPRECATED_FUNCS[fn]
                    else: dep,rem,rep=next(v for k,v in PHP_DEPRECATED_PREFIX.items() if fn.startswith(k))
                    seen.setdefault(fn,(n,dep,rem,rep,line))
                for rx,dep,rem,what in PHP_DEPRECATED_SYNTAX:
                    if blade and "${" in rx.pattern: continue
                    if rx.search(line): seen.setdefault(what,(n,dep,rem,"",line))
            for key,(n,dep,rem,rep,line) in seen.items():
                when=(f"deprecated in PHP {dep}" if dep else "")+(", " if dep and rem else "")+(f"removed in PHP {rem}" if rem else "")
                add("PHP_DEPRECATED_API","LOW",fp,n,f"{key}: {when}. "+(f"Replace with {rep}. " if rep else "")+
                    "Fix before moving to PHP 8.5 so the upgrade does not break or reopen old code paths.",line)
    return findings

# --- database configuration and migrations ---
_DB_USER_KEY=re.compile(r"(?i)^\s*(?:export\s+)?(?:DB_USER(?:NAME)?|DATABASE_USER(?:NAME)?|MYSQL_USER|POSTGRES_USER|PGUSER|DB_ROOT_USER|spring\.datasource\.username|username)\s*(?:=|:)\s*['\"]?(root|sa|postgres|admin)['\"]?\s*$")
_DB_USER_PHP=re.compile(r"(?i)['\"]username['\"]\s*=>\s*(env\(\s*['\"]\w+['\"]\s*,\s*)?['\"](root|sa|postgres)['\"]")
_DB_URL_USER=re.compile(r"(?i)\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|sqlserver|jdbc:\w{1,20})://(root|sa|postgres|admin)(?::|@)|[?&;]user(?:name)?=(root|sa|postgres)\b")
_DB_EMPTY_PW=re.compile(r"(?i)^\s*(?:export\s+)?(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|PGPASSWORD|spring\.datasource\.password)\s*(?:=|:)\s*(?:''|\"\")?\s*$")
_DB_EMPTY_PW_FLAG=re.compile(r"(?i)\bMYSQL_ALLOW_EMPTY_PASSWORD\s*[=:]\s*['\"]?(?:yes|true|1)\b|\bPOSTGRES_HOST_AUTH_METHOD\s*[=:]\s*['\"]?trust\b")
_DB_EMPTY_PW_PHP=re.compile(r"(?i)['\"]password['\"]\s*=>\s*(?:''|\"\")\s*,")
_DB_URL_NOPW=re.compile(r"(?i)\b(?:mysql|mariadb|postgres(?:ql)?|mongodb)://[A-Za-z0-9_.-]{1,64}@")
_DB_NO_TLS=re.compile(r"(?i)\bsslmode['\"]?\s*(?:=|:|=>)\s*['\"]?(?:disable|allow)\b|\buseSSL\s*=\s*false\b|\brequireSSL\s*=\s*false\b|\bsslMode\s*=\s*DISABLED\b|"
                      r"[?&;](?:ssl|tls)\s*=\s*false\b|[;?&]\s*encrypt\s*=\s*false\b|\btrustServerCertificate\s*=\s*true\b|\btlsAllowInvalidCertificates\s*=\s*true\b|"
                      r"\bsslValidate\s*=\s*false\b|MYSQL_ATTR_SSL_VERIFY_SERVER_CERT\s*=>\s*false")
_DB_SSL_FALSE=re.compile(r"\bssl\s*:\s*false\b")
_LOCALHOST=re.compile(r"(?i)localhost|127\.0\.0\.1|::1|host\.docker\.internal")
_DB_BIND=re.compile(r"(?i)^\s*bind[-_]address\s*=\s*(?:0\.0\.0\.0|\*|::)\s*$|^\s*listen_addresses\s*=\s*'(?:\*|0\.0\.0\.0)'|^\s*bindIp\s*:\s*['\"]?0\.0\.0\.0|^\s*bindIpAll\s*:\s*true\b|^\s*bind\s+(?:0\.0\.0\.0|\*)(?:\s|$)")
_DB_PORT_PUBLISHED=re.compile(r"^\s*-\s*['\"]?(?:0\.0\.0\.0:)?(3306|5432|27017|1433|1521|6379):\d{2,5}['\"]?\s*$")
_DB_TRUST=re.compile(r"(?i)^\s*host\w*\s+\S+\s+\S+\s+(?!127\.0\.0\.1/32\b|::1/128\b)\S+\s+trust\b|^\s*authorization\s*:\s*['\"]?disabled\b")
_DB_GRANT=re.compile(r"(?i)\bGRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\b|\bWITH\s+GRANT\s+OPTION\b|\b(?:CREATE|ALTER)\s+(?:USER|ROLE)\b[^\n;]{0,200}?\bSUPERUSER\b|"
                     r"\bGRANT\b[^\n;]{0,300}?\bTO\s+['\"`]?\w{1,64}['\"`]?@['\"`]%['\"`]")
_DB_LOCAL_INFILE=re.compile(r"(?i)\blocal[-_]infile\s*=\s*(?:1|on|true)\b|\bLOAD\s+DATA\s+LOCAL\s+INFILE\b|MYSQL_ATTR_LOCAL_INFILE\s*=>\s*true")
_COL_PLAIN_PW=re.compile(r"(?i)\b(plain_?password|password_?plain|plaintext_?password|password_?plaintext|clear_?password|raw_?password|decrypted_?password|password_?text)\b")
_COL_CARD=re.compile(r"(?i)\b(card_?number|cc_?number|credit_?card_?number|credit_?card|card_?no|pan_?number|cvv2?|cvc2?|card_?cvv|card_?cvc)\b")
_COL_DEF=re.compile(r"(?i)\$table->|\bt\.\w+\b|models\.\w+Field|Column\s*\(|add_?column|ADD\s+COLUMN|CREATE\s+TABLE|\b(?:VARCHAR|CHAR|TEXT|INTEGER|INT|BIGINT|NUMERIC|DECIMAL|BLOB)\b|\bString\b")
_COL_SHORT_PW=re.compile(r"(?i)['\"`]?\b(?:password|passwd|pwd)['\"`]?\s*(?:,\s*|\s+(?:var)?char\s*\(\s*)(\d{1,2})\s*\)")
DB_CFG_NAMES=("my.cnf","mysqld.cnf","my.ini","postgresql.conf","pg_hba.conf","mongod.conf","redis.conf")
_REDACT_URL=re.compile(r"://[^\s'\"@/]{0,300}@")
# key=value, key: value, 'key' => 'value'; a quoted value is masked whole, spaces included.
_REDACT_KV=re.compile(r"(?i)\b(password|passwd|pwd|pass|secret|token|PGPASSWORD|[A-Z_]*PASSWORD)(['\"]?\s*(?:=>|=|:)\s*)(?:'[^'\n]{0,300}'|\"[^\"\n]{0,300}\"|[^\s;&'\",]{1,300})")
# SQL: IDENTIFIED BY '...', PASSWORD '...', WITH PASSWORD '...'
_REDACT_SQL=re.compile(r"(?i)\b(IDENTIFIED\s+(?:WITH\s+\w+\s+)?BY|PASSWORD)(\s+)(?:'[^'\n]{0,300}'|\"[^\"\n]{0,300}\")")

def _redact(line):
    # Findings show the line for context; credentials in it are masked first.
    line=_REDACT_URL.sub("://[redacted]@",line)
    line=_REDACT_SQL.sub(r"\1\2'[redacted]'",line)
    return _REDACT_KV.sub(r"\1\2[redacted]",line)

def db_config_scan(target):
    """MySQL, PostgreSQL and MongoDB configuration and migrations: root or default accounts, empty
    passwords, no TLS, listening on every interface, trust auth, GRANT ALL, plaintext password or card
    columns. MEDIUM, or LOW where the file is an example or the host is local."""
    findings=[]; p=Path(target); base=p.resolve() if p.is_dir() else Path.cwd().resolve()
    per_file={}
    def add(rule,sev,fp,n,msg,code=""):
        k=str(fp); per_file[k]=per_file.get(k,0)+1
        if per_file[k]>MAX_PER_FILE: return
        findings.append({"rule":rule,"severity":sev,"file":str(fp),"line":n,"message":msg,"code":_redact(code.strip())[:180],"engine":"db-config"})
    for fp in walk_files_all(target):
        name=fp.name.lower(); suf=fp.suffix.lower()
        envfile=name==".env" or name.startswith(".env.") or name.endswith(".env")
        if not (envfile or name in DB_CFG_NAMES or suf in (".php",".py",".js",".ts",".rb",".java",".properties",".yml",".yaml",".json",".xml",
                                                          ".sql",".conf",".cnf",".ini",".toml",".prisma") or name=="dockerfile"): continue
        if is_test_path(fp,base): continue
        parts=_rel_parts(fp,base); low="/".join(x.lower() for x in parts)
        example=_is_example(name)
        migration=suf==".sql" or "migration" in low or "/migrate/" in "/"+low or name=="schema.prisma" or name=="schema.rb"
        compose=name.startswith(("docker-compose","compose.")) and suf in (".yml",".yaml")
        dbish=re.search(r"(?i)database|\bdb\b|knexfile|ormconfig|datasource|sequelize|prisma|typeorm|mongo|mysql|postgres|settings",low) is not None
        try:
            if fp.stat().st_size>3_000_000: continue
            lines=fp.read_text(encoding="utf-8-sig",errors="ignore").splitlines()
        except OSError: continue
        for n,line in enumerate(lines,1):
            if len(line)>CODE_LINE_MAX or not line.strip(): continue
            st=line.lstrip()
            if st.startswith(("#","//","--",";","*")): continue     # comment lines in every format we read
            local=bool(_LOCALHOST.search(line))
            m=_DB_USER_KEY.search(line) if (envfile or suf in (".properties",".yml",".yaml",".conf",".ini",".toml")) else None
            if m and (envfile or "datasource" in line.lower() or dbish or "DB_" in line.upper() or compose or name.startswith(("application","bootstrap"))):
                if m.group(1).lower()!="admin" or "datasource" in line.lower():
                    add("DB_ROOT_USER","LOW" if example else "MEDIUM",fp,n,f"The app connects to the database as '{m.group(1)}', a superuser or "
                        "default account. A SQL injection then owns the whole server. Create an app user with only SELECT, INSERT, UPDATE, "
                        "DELETE on its own schema.",re.sub(r"=.*","= [user]",line))
            m=_DB_USER_PHP.search(line) if suf==".php" else None
            if m:
                add("DB_ROOT_USER","LOW" if (m.group(1) or example) else "MEDIUM",fp,n,f"Database user '{m.group(2)}' is the "+
                    ("fallback default" if m.group(1) else "configured user")+". Use a least-privilege app user and set it in the environment.",line)
            m=_DB_URL_USER.search(line)
            if m:
                add("DB_ROOT_USER","LOW" if (example or local) else "MEDIUM",fp,n,f"Connection string uses the '{m.group(1) or m.group(2)}' account. "
                    "Use a least-privilege app user.","[connection string redacted]")
            if not example:
                if _DB_EMPTY_PW.search(line) and (envfile or dbish or "datasource" in line.lower() or compose):
                    add("DB_EMPTY_PASSWORD","MEDIUM",fp,n,"Database password is empty. Set a long random password from a secret store, even for "
                        "internal networks.",line)
                elif _DB_EMPTY_PW_FLAG.search(line):
                    add("DB_EMPTY_PASSWORD","MEDIUM",fp,n,"The database container accepts logins without a password (empty password or trust). "
                        "Set a password and remove this flag.",line)
                elif suf==".php" and dbish and _DB_EMPTY_PW_PHP.search(line):
                    add("DB_EMPTY_PASSWORD","MEDIUM",fp,n,"Database password is an empty literal. Read it from the environment and set a real one.",line)
                elif _DB_URL_NOPW.search(line) and not re.search(r"(?i)://[^@\s]{0,64}:[^@\s]{0,200}@",line):
                    add("DB_EMPTY_PASSWORD","LOW" if local else "MEDIUM",fp,n,"Connection string has a user but no password.","[connection string redacted]")
            if _DB_NO_TLS.search(line) or ((dbish or "ormconfig" in name or "knexfile" in name) and suf in (".js",".ts",".yml",".yaml",".json") and _DB_SSL_FALSE.search(line)):
                add("DB_NO_TLS","LOW" if (local or example) else "MEDIUM",fp,n,"Database connection without TLS (or without certificate checks). Credentials and data "
                    "cross the network in clear text. Use sslmode=verify-full / useSSL=true with the server CA, or encrypt=true without trustServerCertificate.",
                    re.sub(r"(?i)://[^\s'\"]{0,300}@","://[redacted]@",line))
            if name in DB_CFG_NAMES or suf in (".cnf",".conf") or (name.startswith("mongod") and suf in (".yml",".yaml",".conf")):
                if _DB_BIND.search(line):
                    add("DB_BIND_ALL","MEDIUM",fp,n,"The database listens on every network interface. Bind it to 127.0.0.1 or the private interface, "
                        "and firewall the port.",line)
                if _DB_TRUST.search(line):
                    add("DB_TRUST_AUTH","MEDIUM",fp,n,"Remote logins without a password (trust) or MongoDB authorization disabled. Use scram-sha-256 "
                        "and enable authorization.",line)
            if compose and _DB_PORT_PUBLISHED.search(line):
                add("DB_BIND_ALL","LOW",fp,n,"A database port is published on every host interface. Use \"127.0.0.1:PORT:PORT\" or no ports at all "
                    "(services reach it over the compose network).",line)
            if migration or suf==".sql" or (suf==".php" and "DB::statement" in line):
                if _DB_GRANT.search(line):
                    add("DB_GRANT_ALL","MEDIUM",fp,n,"Over-broad database grant (ALL, GRANT OPTION, SUPERUSER or any host '%'). Grant only the statements "
                        "the app needs on its own schema, from its own host.",line)
            if _DB_LOCAL_INFILE.search(line) and (migration or suf in (".sql",".cnf",".ini",".php") or name in DB_CFG_NAMES):
                add("DB_LOCAL_INFILE","LOW",fp,n,"LOAD DATA LOCAL / local_infile lets a malicious or injected query read files from the client host. "
                    "Turn local_infile off unless the import truly needs it.",line)
            if migration and _COL_DEF.search(line):
                m=_COL_CARD.search(line)
                if m:
                    cvv=m.group(1).lower().replace("_","").startswith(("cvv","cvc","cardcvv","cardcvc"))
                    add("DB_SENSITIVE_COLUMN","MEDIUM",fp,n,f"Column '{m.group(1)}' stores "+("the card security code, which PCI DSS forbids storing at all. "
                        "Drop the column." if cvv else "a card number. Store the payment provider's token instead; if a PAN must be kept, "
                        "encrypt it and show only the last four digits."),line)
                m=_COL_PLAIN_PW.search(line)
                if m:
                    add("DB_SENSITIVE_COLUMN","MEDIUM",fp,n,f"Column '{m.group(1)}' suggests a password kept in plain or reversible form. Store "
                        "only a password hash (bcrypt or argon2id) and drop this column.",line)
                m=_COL_SHORT_PW.search(line)
                if m and int(m.group(1))<60:
                    add("DB_SENSITIVE_COLUMN","MEDIUM",fp,n,f"Password column is only {m.group(1)} characters wide, too short for a bcrypt or "
                        "argon2 hash, so passwords are probably stored in plain text. Use password_hash / Hash::make and a 255 column.",line)
    return findings

# --- default values: guessable passwords, placeholder secret keys, predictable admin paths, open infra ---
# A short, bundled list of the passwords seen most in default installs and leaked-password top lists.
# Nothing is downloaded. Compared case-insensitively against the whole value.
WEAK_PASSWORDS={"password","password1","password123","passw0rd","p@ssw0rd","p@ssword","pass","pass123","123456","1234567",
    "12345678","123456789","1234567890","1234","12345","111111","000000","654321","qwerty","qwerty123","qwertyuiop","abc123",
    "iloveyou","admin","admin123","admin@123","administrator","root","toor","test","test123","testing","guest","user","demo",
    "welcome","welcome1","welcome123","letmein","changeme","change_me","changeit","secret","default","master","sa","postgres",
    "mysql","mongo","redis","oracle"}
WEAK_SECRETS={"secret","changeme","change_me","changeit","your-256-bit-secret","your-secret-key","your_secret_key","yoursecretkey",
    "mysecret","my-secret","my_secret","supersecret","super-secret","keyboard cat","shhhhh","shhh","default","test","dev",
    "development","password","jwtsecret","jwt_secret","jwt-secret","secretkey","secret_key","secret-key","s3cr3t","notasecret",
    "insecure","123456","somerandomstring","abc123","qwerty"}
_KV=re.compile(r"""([A-Za-z_][\w.\-]{0,80})['"]?\s*(?:=>|=|:)\s*(?:(['"])([^'"\n]{0,200})\2|([^\s'",;#)}\]]{1,200}))""")
_PLACEHOLDER=re.compile(r"(?i)^\$\{.*\}$|^\$\w+$|^<.*>$|^%\w+%$|^\{\{.*\}\}$|^\{.*\}$|your[-_ ]|replace[-_ ]?me|^x{3,}$|\*{3,}|^\.\.\.$|^(?:null|none|nil|undefined|~)$|example|placeholder|^env\(|getenv|process\.env|os\.environ|System\.getenv")
_HASHED_LITERAL=re.compile(r"(?i)\b(?:Hash::make|bcrypt|password_hash|make_password|set_password|generate_password_hash|passwordEncoder\.encode|encoder\.encode)\s*\(\s*['\"]([^'\"\n]{1,64})['\"]")
_SUPERUSER=re.compile(r"\bcreate_superuser\s*\(([^)\n]{0,300})\)")
_SA_EMPTY=re.compile(r"(?i)\b(?:user\s*id|uid|user|username)\s*=\s*sa\s*;[^\n]{0,200}?\b(?:password|pwd)\s*=\s*(?:;|$|['\"])")
_URL_CRED=re.compile(r"://([^:/\s@'\"]{1,64}):([^@\s/'\"]{1,128})@")
_JWT_LITERAL=re.compile(r"\bjwt\s*\.\s*(?:sign|verify)\s*\([^,\n]{1,200},\s*['\"]([^'\"\n]{0,200})['\"]")
_SESSION_SECRET=re.compile(r"(?i)\b(?:session|cookieSession|expressSession)\s*\([^\n]{0,300}?\bsecret\s*:\s*['\"]([^'\"\n]{0,200})['\"]|\bcookieParser\s*\(\s*['\"]([^'\"\n]{0,200})['\"]")
SENSITIVE_SEGS_HIGH={"admin","administrator","phpmyadmin","adminer","console","actuator","_profiler","telescope","horizon"}
SENSITIVE_SEGS={"backup","debug","test"}|SENSITIVE_SEGS_HIGH
SENSITIVE_WEB_DIRS={"backup","backups","old","bak","test","tmp","temp","dump","dumps"}
_LARAVEL_ANY_ROUTE=re.compile(r"Route::(?:get|post|put|patch|delete|any|match|resource|view|redirect|prefix)\s*\(\s*(?:\[[^\]\n]{0,80}\]\s*,\s*)?['\"]([^'\"\n]{0,200})['\"]|['\"]prefix['\"]\s*=>\s*['\"]([^'\"\n]{0,200})['\"]")
_LARAVEL_AUTH_MW=re.compile(r"(?i)middleware\s*\(\s*\[?[^)\n]{0,200}?['\"](?:auth|can:|role|permission|admin|is_admin|verified|password\.confirm)|['\"]middleware['\"]\s*=>\s*\[?[^\]\n]{0,200}?['\"](?:auth|can:|role|admin|verified)")
_EXPRESS_ANY_ROUTE=re.compile(r"\b(?:app|router|\w*[Rr]outer|server)\s*\.\s*(?:use|get|post|put|patch|delete|all)\s*\(\s*['\"`]([^'\"`\n]{0,200})['\"`]([^\n]{0,400})")
_EXPRESS_AUTH_WORD=re.compile(r"(?i)auth|ensure|require(?:Login|Admin|Role|User)|isAdmin|isAuthenticated|passport|protect|guard|verifyToken|verifyJwt|jwt|basicAuth|\bacl\b|permit|hasRole|checkRole|authorize")
_SPRING_MAPPING=re.compile(r"@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*\"([^\"\n]{0,200})\"")
_SPRING_METHOD_AUTH=re.compile(r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b")
_SPRING_ANY_AUTH=re.compile(r"anyRequest\s*\(\s*\)\s*\.\s*(?:authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll|fullyAuthenticated)\b")
_SPRING_MATCHER=re.compile(r"(?:requestMatchers|antMatchers|mvcMatchers|pathMatchers)\s*\(([^)\n]{0,300})\)\s*\.\s*(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|authenticated|denyAll|access|permitAll)\b")
_REDIS_IMAGE=re.compile(r"(?i)^\s*image\s*:\s*['\"]?(?:[\w.-]+/)?(?:bitnami/)?(redis|mongo|mongodb)(?::|['\"]?\s*$)")

def _sensitive_seg(path):
    # First path segment for backup/debug/test; any of the first four for admin and console tools,
    # so /api/v1/admin is caught too. {param} and :param segments are ignored.
    segs=[s.lower() for s in path.strip().strip("/").split("/") if s and not s.startswith(("{",":"))]
    if segs and segs[0] in SENSITIVE_SEGS: return segs[0]
    return next((s for s in segs[:4] if s in SENSITIVE_SEGS_HIGH),None)

def _weak_pw(v):
    v=v.strip()
    return v.lower() in WEAK_PASSWORDS

def _pw_key(k):
    k=k.lower()
    last=re.split(r"[._\-]",k)[-1]
    return last in ("password","passwd","pwd","pass","requirepass") or k.endswith(("password","passwd"))

def _secret_key_kind(k):
    k=k.lower().replace("-","_")
    if k in ("app_key",): return "app_key"
    if k=="secret_key" or k.endswith((".secret_key","django_secret_key")): return "django"
    # A signing secret: the name says secret/key/signing AND what it signs. Lifetimes, algorithms, issuers,
    # header names and public keys are not secrets (jwt_expires_in: 3600 is not a short secret).
    if re.search(r"public|expire|ttl|lifetime|algo|issuer|audience|header|name$|path|refresh_?ttl|leeway|blacklist",k): return ""
    if re.search(r"secret|signing|_key$|\.key$|^key$",k) and re.search(r"jwt|hmac|signing|token|session|cookie|app_secret|auth|encryption|secret_key_base",k):
        return "signing"
    return ""

def default_cred_scan(target):
    """Guessable or default passwords, placeholder secret keys, admin and debug paths without auth,
    sensitive folders in the web root, and databases or caches left without auth. Values are never
    echoed in a finding."""
    findings=[]; p=Path(target); base=p.resolve() if p.is_dir() else Path.cwd().resolve()
    per_file={}
    def add(rule,sev,fp,n,msg,code=""):
        k=str(fp); per_file[k]=per_file.get(k,0)+1
        if per_file[k]>MAX_PER_FILE: return
        findings.append({"rule":rule,"severity":sev,"file":str(fp),"line":n,"message":msg,"code":_redact(code)[:180],"engine":"default-values"})
    files=walk_files_all(target)
    # Project-wide: does a Spring security config already protect a path, or every request?
    spring_any_auth=False; spring_cover=set(); spring_open=set()   # open = named in a permitAll() matcher
    for fp in files:
        if fp.suffix.lower() in (".java",".kt"):
            t=_read(fp)
            if "SecurityFilterChain" in t or "WebSecurityConfigurer" in t or "HttpSecurity" in t:
                if _SPRING_ANY_AUTH.search(t): spring_any_auth=True
                for m in _SPRING_MATCHER.finditer(t):
                    target_set=spring_open if m.group(2)=="permitAll" else spring_cover
                    for path in re.findall(r"\"([^\"\n]{0,200})\"",m.group(1)):
                        target_set.update(s.lower() for s in path.strip("/").split("/") if s and "*" not in s)
    seen_dirs=set()
    for fp in files:
        name=fp.name.lower(); suf=fp.suffix.lower()
        parts=_rel_parts(fp,base); dirs=[x.lower() for x in parts[:-1]]
        test=is_test_path(fp,base); example=_is_example(name)
        # Sensitive folders and admin tools in the web root.
        wr=[i for i,d in enumerate(dirs) if d in STRICT_WEBROOTS]
        if wr:
            for i in range(wr[0]+1,len(dirs)):
                if dirs[i] in ("vendor","plugins","node_modules","bower_components","lib","libs","assets","js","css"): break
                if dirs[i] in SENSITIVE_WEB_DIRS:
                    key="/".join(dirs[:i+1])
                    if key not in seen_dirs:
                        seen_dirs.add(key)
                        add("SENSITIVE_WEBROOT_PATH","MEDIUM",fp.parent,0,f"A '{dirs[i]}' folder is inside the public web root. Backups, old "
                            "copies, test pages and dumps there are downloadable by anyone who guesses the name. Move it out of the web root.")
                    break
        if suf==".php" and (name.startswith("adminer") or (name in ("phpinfo.php","info.php","php_info.php","test.php") and not wr and len(dirs)==0)) or \
           ("phpmyadmin" in dirs and name=="index.php" and dirs.index("phpmyadmin")<=(wr[0]+1 if wr else 0)):
            if not (name in ("info.php","test.php") and "phpinfo(" not in _read(fp)):
                add("EXPOSED_ADMIN_TOOL","HIGH",fp,0,f"{name}: a database admin tool or phpinfo page shipped with the site. Anyone can find it by its "
                    "well-known name. Remove it from the deploy; run admin tools only over a VPN or SSH tunnel.")
        textual=name==".env" or name.startswith(".env.") or name.endswith(".env") or suf in (".php",".py",".js",".mjs",".cjs",".ts",".java",".kt",
            ".rb",".go",".cs",".properties",".yml",".yaml",".json",".toml",".ini",".conf",".cnf",".xml",".sql") or name=="dockerfile"
        if not textual or name in ("package-lock.json","composer.lock","yarn.lock","pnpm-lock.yaml") or "node_modules" in dirs: continue
        try:
            if fp.stat().st_size>2_000_000: continue
            text=fp.read_text(encoding="utf-8-sig",errors="ignore")
        except OSError: continue
        lines=text.splitlines()
        # Tests, example files and model factories (Laravel's UserFactory uses 'password') are MEDIUM.
        sev_pw="MEDIUM" if (test or example or "factories" in dirs or "factory" in name) else "HIGH"
        if suf==".json" and any(d in ("lang","locales","locale","i18n","translations","messages") for d in dirs): continue
        legacy_seed=("seed" in str(fp).lower() or "fixture" in str(fp).lower() or "migration" in str(fp).lower())
        last_user=(None,0)
        envfile=name==".env" or name.startswith(".env.")
        compose=name.startswith(("docker-compose","compose.")) and suf in (".yml",".yaml")
        cfg_like=envfile or example or suf in (".properties",".yml",".yaml",".ini",".conf",".cnf",".toml") or name=="dockerfile"
        for n,line in enumerate(lines,1):
            if len(line)>CODE_LINE_MAX or not line.strip(): continue
            st=line.lstrip()
            if st.startswith(("#","//","/*","*","--",";")): continue
            if legacy_seed and WEAK_DEFAULT_CRED.search(line): continue   # already reported by config_scan
            hit=None
            for m in _KV.finditer(line):
                # In code an unquoted right-hand side is an expression (X_SECRET = re.compile(...)), not a value.
                if m.group(3) is None and not cfg_like: continue
                k=m.group(1); v=(m.group(3) if m.group(3) is not None else m.group(4) or "").strip()
                kl=k.lower()
                if re.search(r"(?i)^(?:db_|database_|mysql_|postgres_|pg|spring\.datasource\.|mongo\w*_)?user(?:name)?$|^user(?:_?name)?$",kl.split(".")[-1]) and v and not _PLACEHOLDER.search(v):
                    last_user=(v.lower(),n)
                # Known weak values win over the placeholder test ("your-256-bit-secret" is copied from docs and deployed).
                if not v or (_PLACEHOLDER.search(v) and v.lower() not in WEAK_SECRETS and v.lower() not in WEAK_PASSWORDS): continue
                if v != v.lower() and v.lower()==re.split(r"[._\-]",kl)[-1]: continue   # a label: "password": "Password"
                if _pw_key(k) and (_weak_pw(v) or (last_user[0]==v.lower() and n-last_user[1]<=5)):
                    hit=("WEAK_DEFAULT_CREDENTIAL",sev_pw,f"{k} is a guessable or default password (a common-password list entry, or the same as the "
                         "user name). Generate a long random password per environment and keep it in a secret store.",f"{k} = [weak value]"); break
                kind=_secret_key_kind(k)
                vl=v.lower()
                if kind=="app_key" and (vl in ("somerandomstring","base64:") or vl in WEAK_SECRETS):
                    hit=("DEFAULT_SECRET_KEY","MEDIUM" if test else "HIGH",f"{k} is a placeholder or example value. Anyone who knows it can forge "
                         "encrypted cookies and signed URLs. Run php artisan key:generate per environment.",f"{k} = [placeholder]"); break
                if kind=="django" and ("django-insecure" in vl or "changeme" in vl or vl in WEAK_SECRETS):
                    hit=("DEFAULT_SECRET_KEY","MEDIUM" if test else "HIGH",f"{k} is the generated development key or a placeholder. Sessions, "
                         "password reset tokens and signed data can be forged. Load a long random key from the environment in production.",f"{k} = [placeholder]"); break
                if kind=="signing" and (vl in WEAK_SECRETS or len(v)<16):
                    hit=("DEFAULT_SECRET_KEY","MEDIUM" if test else "HIGH",f"{k} is a well-known or short signing secret (under 16 characters). "
                         "Tokens signed with it can be forged offline. Use 32+ random bytes from a secret store.",f"{k} = [weak value]"); break
            if not hit and envfile and not example and re.match(r"\s*APP_KEY\s*=\s*$",line):
                hit=("DEFAULT_SECRET_KEY","HIGH","APP_KEY is empty. Laravel then cannot encrypt cookies safely; run php artisan key:generate.","APP_KEY = [empty]")
            if not hit:
                m=_HASHED_LITERAL.search(line)
                if m and _weak_pw(m.group(1)):
                    hit=("WEAK_DEFAULT_CREDENTIAL",sev_pw,"A guessable password is hashed into a seeded or created account. Generate a random "
                         "password at setup and force a change on first login.","[weak password literal]")
            if not hit:
                m=_SUPERUSER.search(line)
                if m and any(_weak_pw(x) for x in re.findall(r"['\"]([^'\"\n]{1,64})['\"]",m.group(1))):
                    hit=("WEAK_DEFAULT_CREDENTIAL",sev_pw,"Django superuser created with a guessable password. Read it from a secret at deploy time.","create_superuser([weak value])")
            if not hit and _SA_EMPTY.search(line):
                hit=("WEAK_DEFAULT_CREDENTIAL",sev_pw,"SQL Server 'sa' with an empty password. Disable sa, use a least-privilege login with a strong password.","sa / [empty]")
            if not hit:
                m=_URL_CRED.search(line)
                if m and not _PLACEHOLDER.search(m.group(2)) and (_weak_pw(m.group(2)) or m.group(1).lower()==m.group(2).lower()):
                    hit=("WEAK_DEFAULT_CREDENTIAL",sev_pw,"Connection string with a guessable or default password.","[connection string redacted]")
            if not hit:
                m=_JWT_LITERAL.search(line) or _SESSION_SECRET.search(line)
                if m:
                    v=next((g for g in m.groups() if g is not None),"")
                    if v and (v.lower() in WEAK_SECRETS or (len(v)<16 and not _PLACEHOLDER.search(v))):
                        hit=("DEFAULT_SECRET_KEY","MEDIUM" if test else "HIGH","JWT or session secret is a well-known or short literal "
                             "(for example 'keyboard cat' from the docs). Load 32+ random bytes from the environment.","[weak secret literal]")
            if hit:
                add(hit[0],hit[1],fp,n,hit[2],hit[3])
        # Admin, console and debug routes without auth.
        if test: continue
        if suf==".php" and "routes" in dirs:
            depth=0; stack=[]; auth_open=0        # auth_open: auth-guarded groups currently open
            for n,line in enumerate(lines,1):
                if len(line)>CODE_LINE_MAX: continue
                is_group="group(" in line or "Route::group" in line
                own=False                            # auth flag of a group opened on this very line
                if is_group:
                    header=" ".join(lines[max(0,n-4):n])
                    opened=line.count("{")-line.count("}")
                    if opened>0 and len(stack)<500:
                        own=bool(_LARAVEL_AUTH_MW.search(header)); stack.append((depth+1,own)); auth_open+=own
                    depth+=opened
                else:
                    depth+=line.count("{")-line.count("}")
                while stack and stack[-1][0]>depth: auth_open-=stack.pop()[1]
                m=_LARAVEL_ANY_ROUTE.search(line)
                if not m: continue
                seg=_sensitive_seg(m.group(1) if m.group(1) is not None else m.group(2))
                if not seg: continue
                # The whole route statement: up to its ';', or for a closure route up to the line that closes
                # it, so a ->middleware('auth') after "})" is seen.
                stmt=line; k=n
                if not is_group and line.count("{")>line.count("}"):
                    bal=line.count("{")-line.count("}")
                    while bal>0 and k<len(lines) and k<n+80:
                        bal+=lines[k].count("{")-lines[k].count("}"); stmt+=lines[k]; k+=1
                    if k<len(lines) and ";" not in lines[k-1]: stmt+=lines[k]
                else:
                    while ";" not in stmt and "{" not in stmt and k<len(lines) and k<n+6: stmt+=lines[k]; k+=1
                guarded=(auth_open-own)>0           # an outer group's auth; the group's own header is checked below
                if guarded or _LARAVEL_AUTH_MW.search(stmt) or "public-object" in stmt: continue
                add("EXPOSED_ADMIN_PATH","HIGH" if seg in SENSITIVE_SEGS_HIGH else "MEDIUM",fp,n,f"'/{seg}' route has no auth middleware in this "
                    "file. Admin, console and debug paths are the first thing scanners try. Put it behind auth plus a role check (can:, a policy), "
                    "or remove it from production.",line.strip())
        if suf in JS_EXT:
            file_auth=bool(re.search(r"\.use\s*\(\s*(?:['\"`][^'\"`\n]{0,100}['\"`]\s*,\s*)?[^)\n]{0,100}?(?:auth|passport|jwt|basicAuth|ensure|protect|requireLogin)",text,re.I))
            for n,line in enumerate(lines,1):
                if len(line)>CODE_LINE_MAX: continue
                m=_EXPRESS_ANY_ROUTE.search(line)
                if not m: continue
                seg=_sensitive_seg(m.group(1))
                if not seg or _EXPRESS_AUTH_WORD.search(m.group(2)) or file_auth: continue
                add("EXPOSED_ADMIN_PATH","HIGH" if seg in SENSITIVE_SEGS_HIGH else "MEDIUM",fp,n,f"'/{seg}' is mounted without an auth middleware. "
                    "Add authentication and a role check on the route or router, or remove it from production.",line.strip())
        if suf in (".java",".kt") and re.search(r"@(?:Rest)?Controller\b",text) and not _SPRING_METHOD_AUTH.search(text):
            for n,line in enumerate(lines,1):
                m=_SPRING_MAPPING.search(line)
                if not m: continue
                seg=_sensitive_seg(m.group(1))
                if not seg or seg in spring_cover or (spring_any_auth and seg not in spring_open): continue
                add("EXPOSED_ADMIN_PATH","HIGH" if seg in SENSITIVE_SEGS_HIGH else "MEDIUM",fp,n,f"'/{seg}' controller with no @PreAuthorize/@Secured "
                    "and no security rule that requires a role for it. Protect it in the SecurityFilterChain (hasRole) or on the method.",line.strip())
        # Caches and document stores published without auth (compose) or with protected mode off (redis.conf).
        if compose:
            for n,line in enumerate(lines,1):
                m=_REDIS_IMAGE.match(line)
                if not m: continue
                ind=len(line)-len(line.lstrip())
                blk=[]
                for l in lines[n:n+60]:
                    if l.strip() and (len(l)-len(l.lstrip()))<ind and not l.lstrip().startswith("-"): break
                    blk.append(l)
                b="\n".join(blk)
                published=re.search(r"(?m)^\s*-\s*['\"]?(?!127\.0\.0\.1:)(?:0\.0\.0\.0:)?\d{2,5}:\d{2,5}",b) is not None
                kind=m.group(1).lower()
                noauth=(kind=="redis" and not re.search(r"(?i)requirepass|REDIS_PASSWORD|REDIS_ARGS",b)) or \
                       (kind.startswith("mongo") and not re.search(r"(?i)MONGO_INITDB_ROOT_PASSWORD|MONGODB_ROOT_PASSWORD|--auth\b",b))
                if noauth and published:
                    add("DB_NO_AUTH","MEDIUM",fp,n,f"{kind} runs without a password and its port is published on every interface. Anyone who "
                        "reaches the host can read and change the data (and Redis can be turned into code execution). Set a password and bind the "
                        "port to 127.0.0.1 or drop it.",line.strip())
        if name=="redis.conf" and re.search(r"(?m)^\s*protected-mode\s+no\b",text) and not re.search(r"(?m)^\s*requirepass\s+\S",text):
            add("DB_NO_AUTH","MEDIUM",fp,0,"Redis has protected mode off and no requirepass. Set a password (or ACL users) and keep protected mode on.")
    return findings

def find_tool(name):
    # PATH only. On Windows both shutil.which and CreateProcess look in the current directory first, and
    # that is the repo being scanned, so a planted semgrep.bat would run and could fake a clean result.
    # Relative PATH entries and anything inside the scanned tree are skipped as well.
    if os.path.isabs(name): return name if os.path.isfile(name) else None
    here=os.path.normcase(os.path.realpath(os.getcwd()))
    exts=[""]
    if os.name=="nt" and not os.path.splitext(name)[1]:
        exts=[e for e in os.environ.get("PATHEXT",".COM;.EXE;.BAT;.CMD").split(";") if e]
    for d in os.environ.get("PATH","").split(os.pathsep):
        d=d.strip('"')
        if not d or not os.path.isabs(d): continue
        rd=os.path.normcase(os.path.realpath(d))
        if rd==here or rd.startswith(here.rstrip(os.sep)+os.sep): continue
        for e in exts:
            c=os.path.join(d,name+e)
            if os.path.isfile(c) and (os.name=="nt" or os.access(c,os.X_OK)): return c
    # Last, the copy `securecode.py setup` installed into the tools folder (outside every project).
    eng=_engines()
    if eng is not None:
        try: return eng.installed_tool_path(name)
        except Exception: return None
    return None

_ENGINES=[]
def _engines():
    """The scripts/engines package, loaded by path because the gate runs with -I (no script folder on sys.path).
    None if it is missing or broken, so the core gate keeps working."""
    if not _ENGINES:
        try:
            import importlib.util
            here=Path(__file__).resolve().parent/"engines"
            spec=importlib.util.spec_from_file_location("nfsc_engines",here/"__init__.py",submodule_search_locations=[str(here)])
            mod=importlib.util.module_from_spec(spec); sys.modules["nfsc_engines"]=mod
            spec.loader.exec_module(mod); _ENGINES.append(mod)
        except Exception:
            sys.modules.pop("nfsc_engines",None); _ENGINES.append(None)
    return _ENGINES[0]

_MCP=[]
def _mcp_scan():
    """scripts/mcp_scan.py, loaded by path (the gate runs with -I). None if missing or broken."""
    if not _MCP:
        try:
            import importlib.util
            here=Path(__file__).resolve().parent
            if str(here) not in sys.path: sys.path.insert(0,str(here))
            spec=importlib.util.spec_from_file_location("nfsc_mcp_scan",here/"mcp_scan.py")
            mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); _MCP.append(mod)
        except Exception:
            _MCP.append(None)
    return _MCP[0]

# cmd.exe re-parses the arguments of a .bat or .cmd file (the BatBadBut class); such calls are refused when an
# argument contains a character cmd.exe would interpret.
CMD_META=re.compile(r'["&|<>^%!\r\n]')

def scanner_env(cwd,hooks_dir,base=None):
    # Scanners run git inside the scanned repo (gitleaks runs git log -p, semgrep git ls-files). The repo's own
    # .git/config must not be able to run programs there (fsmonitor, hooks, textconv and filter drivers): see safe_git.py.
    # base is an engine's own environment (Go engines pin GOTOOLCHAIN, for example); the safe git settings are laid
    # over it and any GIT_* variable it carries is dropped, so an engine cannot switch them off again.
    try:
        here=os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path: sys.path.insert(0,here)
        import safe_git
        safe=safe_git.safe_git_env(find_tool("git"),cwd,hooks_dir)
    except Exception:
        return None
    if base is None: return safe
    merged={k:v for k,v in base.items() if not str(k).upper().startswith("GIT_")}
    merged.update({k:v for k,v in safe.items() if k.upper().startswith("GIT_")})
    return merged

def run(cmd,cwd,timeout=600,env=None,safe_git=True):
    # Run exactly the executable find_tool chose, never a bare name that the OS would resolve itself.
    exe=find_tool(cmd[0])
    if not exe: return 127,"",f"missing executable: {cmd[0]}"
    if exe.lower().endswith((".bat",".cmd")) and any(CMD_META.search(str(a)) for a in cmd[1:]):
        return 126,"","refused: an argument contains a character cmd.exe would interpret"
    cmd=[exe,*cmd[1:]]
    hooks=tempfile.mkdtemp(prefix="nfsc-nohooks-")
    try:
        # Scanners and engines get the safe git environment. The project's own test commands (safe_git=False) run
        # the project's code anyway, so they keep the normal one: a test suite that uses git hooks or local clones
        # must not fail because of us.
        if safe_git:
            env=scanner_env(cwd,hooks,env)
            if env is None: return 125,"","could not prepare a safe git environment for the scanner"
        p=subprocess.run(cmd,cwd=str(cwd),capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout,env=env)
        return p.returncode,p.stdout,p.stderr
    except FileNotFoundError: return 127,"",f"missing executable: {cmd[0]}"
    except subprocess.TimeoutExpired: return 124,"",f"timeout: {' '.join(cmd)}"
    except Exception as e: return 125,"",str(e)
    finally: shutil.rmtree(hooks,ignore_errors=True)

ORG_SEMGREP=Path(__file__).resolve().parent.parent/"semgrep"/"org-security.yml"

# In ci mode the scanned repo must not be able to switch its own scanners off: a pull request could add a
# .gitleaks.toml allowlist of ".*", a .gitleaksignore, a .semgrepignore, "# nosemgrep" comments or a
# .trivyignore. ci mode therefore uses package-owned settings and ignores those files. full and quick modes keep
# honouring them, because there they are the developer's own choice on their own machine.
PKG_CONFIG=Path(__file__).resolve().parent.parent/"config"
CI_GITLEAKS_CONFIG=PKG_CONFIG/"gitleaks-ci.toml"
CI_EMPTY_IGNORE=PKG_CONFIG/"ci-empty.ignore"
# Semgrep's own default ignore list, applied centrally because --x-ignore-semgrepignore-files drops it too.
SEMGREP_CI_EXCLUDES=["node_modules","build","dist","vendor",".env",".venv",".tox","*.min.js",".npm",".yarn",
                     "test","tests","*_test.go",".semgrep",".semgrep_logs",".security"]
REPO_SCANNER_FILES=(".gitleaks.toml",".gitleaksignore",".semgrepignore",".trivyignore",".trivyignore.yaml","trivy.yaml","trivy-secret.yaml")

def semgrep_configs():
    # "auto" refuses to run with metrics off, so the default is explicit: org rules + registry packs.
    env=os.environ.get("SEMGREP_CONFIGS")
    if env: return [c for c in env.split(",") if c]
    cfgs=[str(p) for p in (ORG_SEMGREP, ORG_SEMGREP.parent/"laravel-authz.yml", ORG_SEMGREP.parent/"java-spring.yml") if p.exists()]
    return cfgs+["p/default","p/owasp-top-ten","p/secrets"]

# Registry rules rate many real injection classes WARNING (for example php.laravel.security.laravel-sql-injection),
# which would map to MEDIUM and never block at --fail-on high. These classes are promoted to at least HIGH.
SEMGREP_HIGH=re.compile(r"(?i)(sqli|sql[-_.]?injection|injection|ssrf|deserializ|unserialize|xxe|jwt|path[-_.]?traversal|"
                        r"command|os[-_.]?exec|subprocess|rce|code[-_.]?exec|eval|auth[-_.]?bypass|missing[-_.]?auth|open[-_.]?redirect|"
                        r"xss|ssti|template[-_.]?injection|mass[-_.]?assign|idor)")

def semgrep_override(rid,sev,confidence=""):
    # ".audit." rules are Semgrep's own "look here" category; they are promoted only when the rule itself
    # reports MEDIUM or HIGH confidence, so low-confidence audit hits do not block every build.
    audit_ok=".audit." not in rid or str(confidence).upper() in ("HIGH","MEDIUM")
    if SEMGREP_HIGH.search(rid) and audit_ok and SEV.get(sev,9)>SEV["HIGH"]: return "HIGH"
    return sev

# Scanner output is untrusted input: a hostile repo can make a scanner echo odd text, and a broken or replaced
# scanner can print anything. Wrong types, deep nesting, huge numbers or oversized output make the whole report
# "unreadable", which the caller treats as a failed scanner (ci mode blocks). Never a traceback, never a pass.
MAX_SCANNER_OUTPUT=200_000_000

class ScannerOutputError(Exception):
    pass

def scanner_json(text,want):
    """Parse one scanner report. want is dict or list; anything else raises ScannerOutputError."""
    if not isinstance(text,str) or not text.strip(): raise ScannerOutputError("no JSON output")
    if len(text)>MAX_SCANNER_OUTPUT: raise ScannerOutputError("output too large")
    try: data=json.loads(text)
    except (ValueError,RecursionError,MemoryError,TypeError) as e: raise ScannerOutputError(type(e).__name__)
    if not isinstance(data,want):
        names="/".join(t.__name__ for t in (want if isinstance(want,tuple) else (want,)))
        raise ScannerOutputError(f"top level is {type(data).__name__}, not {names}")
    return data

def _obj(x,what):
    if not isinstance(x,dict): raise ScannerOutputError(f"{what} is {type(x).__name__}, not an object")
    return x

def _arr(x,what):
    if x is None: return []
    if not isinstance(x,list): raise ScannerOutputError(f"{what} is {type(x).__name__}, not a list")
    return x

def _txt(x,n=400,default=""):
    """A plain string field: strings as they are, numbers as text, anything else (objects, lists) refused."""
    if x is None: return default
    if isinstance(x,bool) or not isinstance(x,(str,int,float)): raise ScannerOutputError(f"a text field is {type(x).__name__}")
    s=x if isinstance(x,str) else (str(x) if not isinstance(x,int) or abs(x)<10**18 else "0")
    return s[:n]

def _lineno(x):
    if x is None or x=="": return 0
    if isinstance(x,bool) or not isinstance(x,(int,str)): raise ScannerOutputError(f"a line number is {type(x).__name__}")
    if isinstance(x,str):
        if not re.fullmatch(r"\d{1,9}",x.strip()): raise ScannerOutputError("a line number is not a number")
        x=int(x)
    return x if 0<=x<10**9 else 0

def _unreadable(name,e):
    return f"scanner output unreadable ({safe_text(str(e))[:200]}); {name} counts as failed and its findings are missing"

def collect_semgrep(root, findings, mode="full"):
    if not find_tool("semgrep"): return False,"semgrep missing"
    cmd=["semgrep","scan","--metrics","off"]
    for c in semgrep_configs(): cmd += ["--config",c]
    if mode=="ci":
        # nosemgrep comments and .semgrepignore files belong to the code under review, not to the reviewer.
        cmd += ["--disable-nosem","--x-ignore-semgrepignore-files"]
        for x in SEMGREP_CI_EXCLUDES: cmd += ["--exclude",x]
    cmd += ["--json","--quiet","."]
    rc,out,err=run(cmd,root,900)
    if not (out or "").strip():
        return False,(err or "semgrep returned no JSON").strip()[-400:]
    try:
        data=scanner_json(out,dict); new=[]
        for r in _arr(data.get("results"),"results"):
            r=_obj(r,"a result"); ex=_obj(r.get("extra") or {},"extra")
            sev=_txt(ex.get("severity"),20,"WARNING").upper()
            sev={"ERROR":"HIGH","WARNING":"MEDIUM","INFO":"LOW"}.get(sev,sev if sev in SEV else "MEDIUM")
            rid=_txt(r.get("check_id"),300,"SEMGREP")
            meta=ex.get("metadata") or {}
            conf=_txt(meta.get("confidence"),20) if isinstance(meta,dict) else ""
            sev=semgrep_override(rid,sev,conf)
            new.append({"rule":rid,"severity":sev,
                "file":_txt(r.get("path"),1000),"line":_lineno(_obj(r.get("start") or {},"start").get("line")),
                "message":_txt(ex.get("message"),2000,"Semgrep finding"),"code":_txt(ex.get("lines"),180),
                "confidence":conf,"engine":"semgrep"})
    except ScannerOutputError as e:
        return False,_unreadable("semgrep",e)
    try: new=laravel_binding_context(root,new)
    except Exception: pass      # context can only drop findings; on any error every finding stays
    findings.extend(new)
    # rc 0 = clean, 1 = findings; anything else (config or network error) is a failed scan.
    return rc in (0,1), "semgrep completed" if rc in (0,1) else f"semgrep exited {rc}: {(err or '').strip()[-300:]}"

# --- Laravel route model binding: context Semgrep cannot see (OPEN-01, benchmark L18) ------------------
# laravel-idor-route-model-binding works on one controller file. Three controls live in other files:
# authorization middleware on the route (->can(), can:, an admin role) in routes/*.php, ->scopeBindings()
# for a child whose parent the method checks, and a FormRequest whose authorize() checks the user. This
# reads only routes/*.php and app/Http/Requests under the scanned root (no symlinks or junctions, files
# under 2 MB, at most 2000 request files), strips comments first and works in one pass per file. It only
# ever drops a finding it can tie to a route or request; anything it cannot read or match stays reported.
# Not modelled: middleware registered in bootstrap/app.php or Kernel.php, Route::bind(), global scopes,
# dynamic policies, and two controllers with the same short class name.
BINDING_RULE="laravel-idor-route-model-binding"
# can:ability or can:ability,routeParam. can:viewAny,App\Models\Order (a class) checks no row, so it does not count.
_AUTHZ_MW=r"(?:can:[^'\",]{1,200}(?:,\w{1,100})?|(?:role|permission|role_or_permission):[^'\"]{0,200}?(?:admin|staff|super|manage|moderat|operator|backoffice)[^'\"]{0,200}|(?:is_?)?admin|super_?admin)"
_AUTHZ_MW_RX=re.compile(r"(?i)['\"]"+_AUTHZ_MW+r"['\"]|\b[\w\\]{0,200}Admin\w{0,80}::class")
_MW_CALL_RX=re.compile(r"(?:->|::)middleware\(([^()]{0,2000})\)|['\"]middleware['\"]\s*=>\s*(\[[^\]]{0,2000}\]|['\"][^'\"]{0,300}['\"])")
_RESOURCE_METHODS={"resource":("index","create","store","show","edit","update","destroy"),
                   "apiResource":("index","store","show","update","destroy")}

def _bounded_file(root,fp):
    """Text of a file inside root that is not a symlink and under 2 MB, else ''."""
    try:
        if os.path.islink(fp) or not os.path.isfile(fp) or os.path.getsize(fp)>=2_000_000: return ""
        real=os.path.realpath(fp); base=os.path.realpath(root)
        if os.path.commonpath([real,base])!=base: return ""
        with open(fp,encoding="utf-8-sig",errors="ignore") as fh: return fh.read()
    except (OSError,ValueError): return ""

def _php_strip_comments(t):
    """PHP source with // # and /* */ comments blanked (strings kept, newlines kept). One pass."""
    out=[]; i=0; n=len(t); q=None
    while i<n:
        c=t[i]
        if q:
            out.append(c)
            if c=="\\" and i+1<n: out.append(t[i+1]); i+=2; continue
            if c==q: q=None
            i+=1; continue
        if c in "'\"": q=c; out.append(c); i+=1; continue
        if c=="/" and t.startswith("/*",i):
            j=t.find("*/",i+2); j=n if j<0 else j+2
            out.append(re.sub(r"[^\n]"," ",t[i:j])); i=j; continue
        if (c=="/" and t.startswith("//",i)) or (c=="#" and not t.startswith("#[",i)):
            j=t.find("\n",i); j=n if j<0 else j
            out.append(" "*(j-i)); i=j; continue
        out.append(c); i+=1
    return "".join(out)

def _route_flags(text):
    """(authorization middleware, scoped bindings) present in one statement or group prefix."""
    # ->can('ability') or ->can('ability', 'routeParam'); ->can('viewAny', Order::class) checks no row.
    authz=bool(re.search(r"->can\(\s*['\"][^'\"]{1,200}['\"]\s*(?:\)|,\s*['\"])",text)) or any(_AUTHZ_MW_RX.search(m.group(1) or m.group(2) or "") for m in _MW_CALL_RX.finditer(text))
    scoped=bool(re.search(r"(?:->|::)scopeBindings\(|->scoped\(",text))
    return authz,scoped

def _uri_params(uri):
    names=[m.group(1) for m in re.finditer(r"\{(\w{1,80})(?::\w{1,80})?\??\}",uri)]
    keyed=[bool(m.group(1)) for m in re.finditer(r"\{\w{1,80}(:\w{1,80})?\??\}",uri)]
    return names,keyed

def laravel_routes(root):
    """{(controller short name, method): [{"authz":bool,"scoped":bool,"params":[...]}, ...]} from routes/*.php."""
    table={}; rdir=os.path.join(str(root),"routes")
    if is_link_dir(rdir) or not os.path.isdir(rdir): return table
    # Only route files Laravel loads: web.php, api.php, and files named in bootstrap/app.php, the
    # RouteServiceProvider or one of those two. A stray routes/x.php that nothing loads cannot add a
    # ->can() that the running app never applies.
    refs="\n".join(_bounded_file(root,os.path.join(str(root),*p)) for p in
                   (("bootstrap","app.php"),("app","Providers","RouteServiceProvider.php"),("routes","web.php"),("routes","api.php")))
    for name in sorted(os.listdir(rdir))[:200]:
        if not name.endswith(".php"): continue
        if name not in ("web.php","api.php") and not re.search(r"[/'\"]"+re.escape(name)+r"['\"]",refs): continue
        t=_php_strip_comments(_bounded_file(root,os.path.join(rdir,name)))
        # One frame per open brace: (outer statement buffer, authz, scoped, controller), each already
        # combined with the frames around it, so a statement costs O(1) however deep it sits. Group
        # flags are read from the last 2000 characters before the brace only.
        frames=[]; buf=[]; q=None; esc=False; braces=0
        for c in t:
            if q:
                buf.append(c)
                if esc: esc=False
                elif c=="\\": esc=True
                elif c==q: q=None
                continue
            if c in "'\"": q=c; buf.append(c); continue
            if c=="{":
                braces+=1
                if braces>20000: break      # no real routes file has this many; stop instead of slowing down
                prefix="".join(buf[-2000:]); a,s=_route_flags(prefix)
                ctl=re.search(r"Route::controller\(\s*\\?([\w\\]{1,200})::class",prefix)
                up=frames[-1] if frames else (None,False,False,None)
                frames.append((buf,a or up[1],s or up[2],ctl.group(1).split("\\")[-1] if ctl else up[3])); buf=[]; continue
            if c=="}":
                if frames: buf=frames.pop()[0]; buf.append("{}")
                continue
            if c==";":
                _route_statement("".join(buf[:20000]),frames[-1] if frames else None,table); buf=[]; continue
            buf.append(c)
    return table

def _route_statement(st,frame,table):
    if "Route::" not in st and "->" not in st: return
    a,s=_route_flags(st)
    if frame: a=a or frame[1]; s=s or frame[2]
    ctl=frame[3] if frame else None
    m=re.search(r"Route::(get|post|put|patch|delete|options|any|match)\(\s*(?:\[[^\]]{0,200}\]\s*,\s*)?['\"]([^'\"]{0,500})['\"]\s*,\s*(.{0,600})",st,re.S)
    if m:
        uri,rest=m.group(2),m.group(3); names,keyed=_uri_params(uri)
        # Laravel scopes a child automatically when it uses a custom key ({post:slug}) after a parent.
        scoped=s or any(keyed[1:])
        acts=[]
        x=re.match(r"\[\s*\\?([\w\\]{1,200})::class\s*,\s*['\"](\w{1,100})['\"]\s*\]",rest)
        y=re.match(r"['\"]([\w\\]{1,200})@(\w{1,100})['\"]",rest)
        z=re.match(r"\\?([\w\\]{1,200})::class\s*\)",rest)
        w=re.match(r"['\"](\w{1,100})['\"]\s*\)",rest)
        if x: acts.append((x.group(1),x.group(2)))
        elif y: acts.append((y.group(1),y.group(2)))
        elif z: acts.append((z.group(1),"__invoke"))
        elif w and ctl: acts.append((ctl,w.group(1)))
        for cls,meth in acts:
            table.setdefault((cls.split("\\")[-1],meth),[]).append({"authz":a,"scoped":scoped,"params":names})
        return
    r=re.search(r"Route::(resource|apiResource)\(\s*['\"]([\w./-]{1,300})['\"]\s*,\s*\\?([\w\\]{1,200})::class",st)
    if r:
        segs=[p for p in re.split(r"[./]",r.group(2)) if p]
        names=[p[:-3]+"y" if p.endswith("ies") else (p[:-1] if p.endswith("s") else p) for p in segs]
        names=[re.sub(r"-(\w)",lambda k:k.group(1).upper(),p) for p in names]
        for meth in _RESOURCE_METHODS[r.group(1)]:
            table.setdefault((r.group(3).split("\\")[-1],meth),[]).append({"authz":a,"scoped":s,"params":names})

def _method_signature(text,starts,line,method):
    """(class short name, [(type, var)]) of the method declared at or just above line."""
    # The finding sits on the parameter, so the declaration is the last one that starts on or before that line.
    pos=starts[min(max(line,1),len(starts))-1]
    end=text.find("\n",pos); end=len(text) if end<0 else end
    sig=None
    for m in re.finditer(r"\bfunction\s+"+re.escape(method)+r"\s*\(",text[:end]): sig=m
    if not sig: return None,[]
    cls=None
    for c in re.finditer(r"\bclass\s+(\w{1,200})",text[:sig.start()]): cls=c.group(1)
    j=sig.end(); depth=1; k=j
    while k<len(text) and depth and k-j<4000:
        if text[k]=="(": depth+=1
        elif text[k]==")": depth-=1
        k+=1
    params=[(p.group(1) or "",p.group(2)) for p in re.finditer(r"(?:\??([\w\\]{1,200})\s+)?&?(?:\.\.\.)?\$(\w{1,100})",text[j:k-1])]
    return cls,params

_REQ_SIGNAL=re.compile(r"->can\(|->cannot\(|->cant\(|Gate::|->authorize\w{0,20}\(")
_REQ_OWNER=re.compile(r"->is\(|->isNot\(|->owns\(|===|==|!==|!=")

def _form_request_authorizes(root,cls,cache):
    """True when app/Http/Requests holds class cls and its authorize() checks the user against the route."""
    if "index" not in cache:
        idx={}; base=os.path.join(str(root),"app","Http","Requests"); seen=0
        if os.path.isdir(base) and not is_link_dir(base):
            for r,d,fs in os.walk(base):
                d[:]=[x for x in d if not is_link_dir(os.path.join(r,x))]
                for f in fs:
                    seen+=1
                    if seen>2000: break
                    if f.endswith(".php"): idx.setdefault(f[:-4],os.path.join(r,f))
        cache["index"]=idx
    fp=cache["index"].get(cls)
    if not fp: return False
    t=_php_strip_comments(_bounded_file(root,fp))
    m=re.search(r"\bfunction\s+authorize\s*\(\s*\)\s*(?::\s*\??\w{1,20}\s*)?\{",t)
    if not m: return False
    j=m.end(); depth=1; k=j
    while k<len(t) and depth and k-j<20000:
        if t[k]=="{": depth+=1
        elif t[k]=="}": depth-=1
        k+=1
    body=t[j:k-1]
    if re.fullmatch(r"\s*return\s+true\s*;\s*",body,re.I): return False
    if _REQ_SIGNAL.search(body): return True
    return bool(_REQ_OWNER.search(body)) and bool(re.search(r"route\(|_id\b|->id\b|getKey\(",body)) and \
           bool(re.search(r"user\(\)|auth\(|Auth::",body))

def laravel_binding_context(root,findings):
    """findings without the route model binding results that route middleware, scopeBindings() with a checked
    parent, or a FormRequest's authorize() already cover. Every other finding is returned unchanged."""
    if not any(str(f.get("rule","")).endswith(BINDING_RULE) for f in findings): return findings
    routes=laravel_routes(root); req_cache={}; parsed={}; info={}
    # (file, class, method) -> bound variables the rule reported, to know whether a parent was checked.
    reported={}
    for i,f in enumerate(findings):
        if not str(f.get("rule","")).endswith(BINDING_RULE): continue
        m=re.search(r"\(binding: \$(\w{1,100}) in (\w{1,100})\(\)\)",str(f.get("message","")))
        if not m: continue
        rel=str(f.get("file",""))
        if rel not in parsed:
            text=_php_strip_comments(_bounded_file(root,os.path.join(str(root),rel)))
            parsed[rel]=(text,_line_starts(text))
        try: line=int(f.get("line") or 0)
        except (TypeError,ValueError): continue
        text,starts=parsed[rel]
        cls,params=_method_signature(text,starts,line,m.group(2)) if text else (None,[])
        if not cls: continue
        # Parameters whose type the file imports from a Models namespace: the rule would have reported them.
        models={v for t,v in params if t and ("\\Models\\" in t or
                re.search(r"(?m)^\s*use\s+[\w\\]{0,300}\\Models\\"+re.escape(t)+r"\s*;",text))}
        info[i]=(m.group(1),m.group(2),cls,params,models)
        reported.setdefault((rel,cls,m.group(2)),set()).add(m.group(1))
    out=[]
    for i,f in enumerate(findings):
        if i not in info: out.append(f); continue
        var,meth,cls,params,models=info[i]
        # A FormRequest whose authorize() checks the user covers the whole method.
        if any(t and t.split("\\")[-1].endswith("Request") and t.split("\\")[-1]!="Request" and
               _form_request_authorizes(root,t.split("\\")[-1],req_cache) for t,_ in params):
            continue
        rts=routes.get((cls,meth))
        if rts:
            if all(r["authz"] for r in rts): continue
            # A scoped child whose parent the method checks: the parent is the first route parameter, a
            # model parameter of this method (so the rule looked at it), and the rule did not report it.
            done=reported.get((str(f.get("file","")),cls,meth),set())
            if all(r["scoped"] and len(r["params"])>=2 and r["params"][0]!=var and r["params"][0] in models
                   and r["params"][0] not in done for r in rts):
                continue
        out.append(f)
    return out

def collect_trivy(root,findings,mode="full"):
    if not find_tool("trivy"): return False,"trivy missing"
    cmd=["trivy","fs","--scanners","vuln,misconfig,secret","--format","json"]
    if mode=="ci":
        if not CI_EMPTY_IGNORE.is_file(): return False,f"ci ignore file missing from the package: {CI_EMPTY_IGNORE.name}"
        # an empty string disables trivy.yaml and trivy-secret.yaml; the ignore file is the package's empty one
        cmd += ["--config","","--secret-config","","--ignorefile",str(CI_EMPTY_IGNORE)]
    rc,out,err=run(cmd+["."],root,1200)
    if not (out or "").strip():
        return False,(err or "trivy returned no JSON").strip()[-400:]
    try:
        data=scanner_json(out,dict); new=[]
        for res in _arr(data.get("Results"),"Results"):
            res=_obj(res,"a result"); target=_txt(res.get("Target"),1000)
            for v in _arr(res.get("Vulnerabilities"),"Vulnerabilities"):
                v=_obj(v,"a vulnerability")
                sev=_txt(v.get("Severity"),20,"UNKNOWN").upper(); sev=sev if sev in SEV else "MEDIUM"
                new.append({"rule":_txt(v.get("VulnerabilityID"),200,"TRIVY"),"severity":sev,"file":target,
                    "line":0,"message":f"{_txt(v.get('PkgName'),200,'dependency')} {_txt(v.get('InstalledVersion'),100)} -> "
                                      f"{_txt(v.get('FixedVersion'),200) or 'no fixed version'}: {_txt(v.get('Title'),500,'Known vulnerability')}",
                    "code":"","engine":"trivy"})
            for m in _arr(res.get("Misconfigurations"),"Misconfigurations"):
                m=_obj(m,"a misconfiguration")
                sev=_txt(m.get("Severity"),20,"UNKNOWN").upper(); sev=sev if sev in SEV else "MEDIUM"
                new.append({"rule":_txt(m.get("ID"),200,"TRIVY-MISCONFIG"),"severity":sev,"file":target,
                    "line":0,"message":_txt(m.get("Message"),2000,"Misconfiguration"),"code":"","engine":"trivy"})
            for s in _arr(res.get("Secrets"),"Secrets"):
                s=_obj(s,"a secret")
                new.append({"rule":_txt(s.get("RuleID"),200,"TRIVY-SECRET"),"severity":"CRITICAL","file":target,
                    "line":_lineno(s.get("StartLine")),"message":_txt(s.get("Title"),500,"Secret detected"),"code":"","engine":"trivy"})
    except ScannerOutputError as e:
        return False,_unreadable("trivy",e)
    findings.extend(new)
    return rc in (0,1), "trivy completed"

def collect_gitleaks(root,findings,mode="full"):
    if not find_tool("gitleaks"): return False,"gitleaks missing"
    ci_args=[]
    if mode=="ci":
        if not (CI_GITLEAKS_CONFIG.is_file() and CI_EMPTY_IGNORE.is_file()):
            return False,"ci gitleaks config missing from the package"
        # --config wins over the repo's .gitleaks.toml and --ignore-gitleaks-allow drops inline gitleaks:allow
        # comments. gitleaks 8.x still reads <source>/.gitleaksignore on top of --gitleaks-ignore-path, so the
        # repo's file is reported and blocks; reviewed exceptions belong in the central config instead.
        ci_args=["--config",str(CI_GITLEAKS_CONFIG),"--gitleaks-ignore-path",str(CI_EMPTY_IGNORE),"--ignore-gitleaks-allow"]
        if (root/".gitleaksignore").exists():
            findings.append({"rule":"SCANNER_SUPPRESSION_IN_REPO","severity":"HIGH","file":".gitleaksignore","line":0,
                "message":"ci mode does not accept a repo .gitleaksignore (it can hide real secrets). Remove it and ask the "
                          "security team to add reviewed exceptions to the central gitleaks config.","code":"","engine":"gitleaks"})
    sec=root/".security"; sec.mkdir(exist_ok=True)
    rp=sec/"gitleaks.json"
    if rp.exists(): rp.unlink()
    cmd=["gitleaks","detect","--source",".","--no-banner","--report-format","json","--report-path",str(rp),*ci_args]
    if not (root/".git").exists(): cmd.append("--no-git")
    rc,out,err=run(cmd,root,900)
    # Gitleaks exits 1 both for "leaks found" and for errors, so success means a readable report.
    try:
        if rp.is_symlink() or not rp.is_file(): raise OSError("no report file")
        if rp.stat().st_size>MAX_SCANNER_OUTPUT: raise ScannerOutputError("report too large")
        text=rp.read_text(encoding="utf-8",errors="replace")
    except OSError:
        return False,f"gitleaks exited {rc} without a readable report: {(err or out).strip()[-300:]}"
    except ScannerOutputError as e:
        return False,_unreadable("gitleaks",e)
    try:
        new=[]
        for x in scanner_json(text if text.strip() else "[]",list):
            x=_obj(x,"a leak")
            new.append({"rule":_txt(x.get("RuleID"),200,"GITLEAKS"),"severity":"CRITICAL","file":_txt(x.get("File"),1000),
                "line":_lineno(x.get("StartLine")),"message":_txt(x.get("Description"),500,"Secret detected"),"code":"","engine":"gitleaks"})
    except ScannerOutputError as e:
        return False,_unreadable("gitleaks",e)
    findings.extend(new)
    return rc in (0,1), "gitleaks completed"

RETIRE_SEV={"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW"}

def collect_retire(root,findings,mode="full"):
    """Retire.js (Apache-2.0) finds vulnerable client-side libraries by signature, including copies
    renamed or bundled inside themes. Returns (None, "") when it is not installed."""
    if not find_tool("retire"): return None,""
    out_dir=Path(tempfile.mkdtemp(prefix="sc-retire-")); rp=out_dir/"retire.json"
    try:
        # ci: the package's empty ignore file replaces the repo's .retireignore / .retireignore.json
        ci_args=["--ignorefile",str(CI_EMPTY_IGNORE)] if mode=="ci" and CI_EMPTY_IGNORE.is_file() else []
        rc,out,err=run(["retire","--outputformat","json","--outputpath",str(rp),"--path",".",*ci_args],root,900)
        try: data=scanner_json(rp.read_text(encoding="utf-8",errors="ignore") or "{}",(dict,list))
        except OSError: return False,f"retire exited {rc} without a readable report"
        except ScannerOutputError as e: return False,_unreadable("retire",e)
    finally:
        shutil.rmtree(out_dir,ignore_errors=True)
    items=data.get("data") if isinstance(data,dict) else data
    count=0
    for item in (items if isinstance(items,list) else []):
        if not isinstance(item,dict): continue
        for res in item.get("results") or []:
            if not isinstance(res,dict): continue
            vulns=[v for v in (res.get("vulnerabilities") or []) if isinstance(v,dict)]
            if not vulns: continue
            worst=min((RETIRE_SEV.get(str(v.get("severity","")).lower(),"MEDIUM") for v in vulns),key=lambda s:SEV[s])
            ids=sorted({i for v in vulns for i in ((v.get("identifiers") or {}).get("CVE") or [])})[:5]
            findings.append({"rule":"VULNERABLE_LIBRARY","severity":worst if worst in ("CRITICAL","HIGH","LOW") else "HIGH",
                "file":str(item.get("file","")),"line":0,"engine":"retire",
                "message":f"{res.get('component','library')} {res.get('version','')} has known vulnerabilities {', '.join(ids) or ''}. Upgrade it.".replace("  "," "),
                "code":""})
            count+=1
    return True,f"completed, {count} vulnerable components"

def collect_psalm(root,findings):
    """Psalm taint analysis (MIT) for PHP projects that already have it in vendor/bin. Returns (None, "")
    otherwise, so a project without Psalm is not slowed down or blocked."""
    psalm=root/"vendor"/"bin"/"psalm"
    php=find_tool("php")
    if not (php and psalm.is_file() and (root/"composer.json").exists()): return None,""
    rc,out,err=run([php,str(psalm),"--taint-analysis","--output-format=json","--no-progress","--no-cache"],root,1200)
    try: issues=scanner_json(out or "[]",list)
    except ScannerOutputError as e: return False,f"psalm exited {rc}: "+_unreadable("psalm",e)
    count=0
    for i in (issues if isinstance(issues,list) else []):
        if not isinstance(i,dict) or not str(i.get("type","")).startswith("Tainted"): continue
        findings.append({"rule":f"PSALM_{i.get('type')}","severity":"HIGH","file":str(i.get("file_path","")),
            "line":int(i.get("line_from") or 0),"message":str(i.get("message",""))[:300],"code":str(i.get("snippet",""))[:180],
            "engine":"psalm-taint"})
        count+=1
    return True,f"completed, {count} taint findings"

def suppression_file(root,mode,notes):
    # In ci mode the project's own file is ignored: a pull request could add a blanket suppression.
    # The security team passes an approved list instead (SECGATE_SUPPRESSIONS, from the central repo).
    env=os.environ.get("SECGATE_SUPPRESSIONS")
    if env: return Path(env)
    own=root/"config"/"security-suppressions.yaml"
    if mode=="ci":
        if own.exists(): notes.append("ci mode ignores the project's own config/security-suppressions.yaml; ask the security team to approve exceptions")
        return None
    return own

def parse_expiry(v):
    """The expiry as a date, or None. Only YYYY-MM-DD is accepted (a YAML date object too). Python 3.11+
    fromisoformat also reads 20260115 and 2026-W01, and comparing those as strings never expired them."""
    import datetime
    if isinstance(v,datetime.datetime): return None
    if isinstance(v,datetime.date): return v
    if not isinstance(v,str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}",v): return None
    try: return datetime.date.fromisoformat(v)
    except ValueError: return None

def valid_expiry(v):
    # A real calendar date at most about 12 months ahead: exceptions must come back for review.
    import datetime
    d=parse_expiry(v)
    return d is not None and d<=datetime.date.today()+datetime.timedelta(days=366)

def load_suppressions(path,notes):
    if not path or not path.exists(): return []
    try:
        import yaml
        d=yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        notes.append(f"suppressions not loaded ({type(e).__name__}); nothing is suppressed"); return []
    if not isinstance(d,dict) or not isinstance(d.get("suppressions",[]) or [],list):
        notes.append("suppressions file is not a mapping with a 'suppressions' list; nothing is suppressed"); return []
    valid=[]
    for s in d.get("suppressions",[]) or []:
        # Every entry must name an exact repo-relative file, a rule or "*" for that file only, an owner and an expiry date.
        if isinstance(s,dict) and s.get("expires") is not None and parse_expiry(s.get("expires")) is None:
            # Fail closed: an expiry that is not a plain YYYY-MM-DD date counts as already expired.
            notes.append(f"suppression treated as expired: expiry {str(s.get('expires'))[:40]!r} is not YYYY-MM-DD "
                         f"(rule {str(s.get('rule'))[:60]}, file {str(s.get('file'))[:120]})"); continue
        if not (isinstance(s,dict) and s.get("rule") and s.get("file") and s.get("owner") and s.get("reason") and
                valid_expiry(s.get("expires"))) or str(s["file"]).startswith(("/","\\")) or ".." in str(s["file"]):
            notes.append(f"ignored an incomplete suppression entry: {str(s)[:120]}"); continue
        valid.append(s)
    return valid

def apply_suppressions(findings,root,mode="quick",notes=None):
    notes=[] if notes is None else notes
    import datetime
    sups=load_suppressions(suppression_file(root,mode,notes),notes); today=datetime.date.today(); out=[]
    for f in findings:
        try: rel=Path(f["file"]).resolve().relative_to(root).as_posix()
        except Exception: rel=str(f["file"]).replace("\\","/")
        suppressed=False
        for s in sups:
            sf=str(s["file"]).replace("\\","/")
            if (sf[2:] if sf.startswith("./") else sf)!=rel: continue
            if s.get("rule","*")!="*" and s.get("rule")!=f["rule"]: continue
            exp=parse_expiry(s.get("expires"))
            if exp is None or exp<today: continue          # unparseable = expired (fail closed)
            suppressed=True; f["suppressed"]=True; f["suppression_reason"]=s.get("reason","")
            break
        if not suppressed: out.append(f)
    return out

def project_commands(root,notes):
    cmds=[]
    if (root/"package.json").exists():
        npm=find_tool("npm")
        if not npm:
            notes.append("package.json found but npm is not installed; Node tests were not run")
        try:
            if not npm: raise LookupError("npm missing")
            d=json.loads((root/"package.json").read_text(encoding="utf-8"))
            s=d.get("scripts",{})
            if not (root/"node_modules").exists():
                # Install scripts are skipped by default (malicious postinstall, s1ngularity lesson).
                install=["ci"] if (root/"package-lock.json").exists() else ["install"]
                if os.environ.get("SECGATE_NPM_SCRIPTS")!="1": install.append("--ignore-scripts")
                cmds.append([npm,*install])
            for k in ["lint","typecheck","test","build"]:
                if k in s: cmds.append([npm,"run",k])
        except Exception: pass
    elif (root/"pyproject.toml").exists() or (root/"pytest.ini").exists():
        if find_tool("pytest"): cmds.append(["pytest","-q"])
    elif (root/"go.mod").exists() and find_tool("go"):
        cmds.append(["go","test","./..."])
    if (root/"composer.json").exists():
        php=find_tool("php")
        if not php:
            notes.append("composer.json found but php is not installed; PHP tests were not run")
        elif (root/"artisan").exists():
            cmds.append([php,"artisan","test"])
        elif (root/"vendor"/"bin"/"phpunit").exists():
            cmds.append([php,str(root/"vendor"/"bin"/"phpunit")])
        else:
            notes.append("composer.json found but neither artisan nor vendor/bin/phpunit exists; run composer install first")
    if any(root.glob("*.sln")) or any(root.glob("*.csproj")) or any(root.glob("*/*.csproj")):
        if find_tool("dotnet"): cmds.append(["dotnet","test"])
        else: notes.append(".NET project found but dotnet is not installed; .NET tests were not run")
    return cmds

def write_reports(root,findings,mode,tool_status):
    sec=root/".security"; sec.mkdir(exist_ok=True)
    counts={s:sum(1 for f in findings if f["severity"]==s) for s in SEV}
    report={"mode":mode,"tool_status":tool_status,"counts":counts,"findings":findings}
    (sec/"findings.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    sarif={"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",
           "runs":[{"tool":{"driver":{"name":"Org AI Secure AppSec Gate","version":GATE_VERSION}},
                     "results":[{"ruleId":f["rule"],"level":{"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(f["severity"],"note"),
                                 "message":{"text":f["message"]},"locations":[{"physicalLocation":{"artifactLocation":{"uri":str(f["file"])},"region":{"startLine":max(1,int(f.get("line") or 1))}}}]}
                                for f in findings]}]}
    (sec/"findings.sarif").write_text(json.dumps(sarif,indent=2),encoding="utf-8")
    return counts

CONTROL=re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")

def safe_text(s):
    # A file name with a newline could print a fake "RESULT: PASS" line or a CI workflow command.
    return CONTROL.sub("?",str(s))

_REDACT=[]
def _redactor():
    """report.redact (the shared secret patterns), loaded by path; a small built-in fallback if it is missing."""
    if not _REDACT:
        try:
            import importlib.util
            spec=importlib.util.spec_from_file_location("nfsc_report_redact",Path(__file__).resolve().parent/"report.py")
            mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); _REDACT.append(mod.redact)
        except Exception:
            rx=re.compile(r"(?i)((?:password|passwd|secret|token|api[_\-]?key|access[_\-]?key|authorization)[\w\-]{0,20}\s*[:=]\s*)\S+")
            _REDACT.append(lambda s: rx.sub(r"\1[REDACTED]",str(s)))
    return _REDACT[0]

def scanner_error_lines(msg,keep=4):
    """A scanner's stderr (often a Python traceback) as a few readable lines: split on real line breaks before
    control characters are neutralised (so no '?' run-together text), the home folder shown as ~, secret-looking
    values redacted, the first two and last lines kept (the last line of a traceback names the error)."""
    text=str(msg or "")
    home=str(Path.home())
    if len(home)>3:
        for h in {home,home.replace("\\","/")}: text=text.replace(h,"~")
    try: text=_redactor()(text)
    except Exception: text="(error text withheld: it could not be redacted)"
    lines=[safe_text(l.rstrip())[:200] for l in text.splitlines() if l.strip()]
    if len(lines)>keep: lines=lines[:2]+["..."]+lines[-(keep-2):]
    return lines or ["(no error text)"]

def scanner_fix_hint(name,msg):
    """The next step for a required scanner that is on PATH but failed (not for a missing ci config file)."""
    if str(msg).startswith(("ci ","scanner output unreadable")): return ""
    cmd="py -I scripts/securecode.py setup"
    try:
        eng=_engines()
        if eng is not None: cmd=eng.setup_command()      # the installed path, so it works from any project (V7F-D)
    except Exception: pass
    return f"{name} is installed but failed to run; reinstall it or run: {cmd} --engine {name}"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("target",nargs="?",default=".")
    ap.add_argument("--changed-file")
    ap.add_argument("--mode",choices=["quick","full","ci"],default="quick")
    ap.add_argument("--fail-on",choices=["critical","high","medium","low","never"],default="high")
    ap.add_argument("--run-tests",action="store_true")
    ap.add_argument("--report",action="store_true",help="also write .security/ reports in quick mode")
    args=ap.parse_args()
    root=Path(".").resolve(); target=args.changed_file or args.target
    findings=local_scan(target)+agent_scan(target)+library_scan(target)+config_scan(target)+malware_scan(target)+code_scan(target)+db_config_scan(target)+default_cred_scan(target)
    status={}; errors={}; notes=[]; engine_status={}; ran_tests=[]; fixes=[]
    required=["semgrep","trivy","gitleaks"]
    if args.mode in ("full","ci"):
        for t in required: status[t]=bool(find_tool(t))
        if args.mode=="ci" and not all(status.values()):
            print("RESULT: BLOCKED (ci) required security scanner missing:",[t for t,v in status.items() if not v])
            return 3
        own=[n for n in REPO_SCANNER_FILES if (root/n).exists()]
        if own:
            notes.append(("ci mode ignored the repo's own scanner settings: " if args.mode=="ci" else
                          "full mode honours the repo's own scanner settings (ci mode will not): ")+", ".join(own))
        for name,fn in (("semgrep",collect_semgrep),("trivy",collect_trivy),("gitleaks",collect_gitleaks)):
            if not status[name]: continue
            try:
                ok,msg=fn(root,findings,mode=args.mode)
            except Exception as e:      # a required scanner that cannot be read is a failed scanner, never a pass
                ok,msg=False,_unreadable(name,type(e).__name__)
            if not ok:
                errors[name]=" | ".join(scanner_error_lines(msg)); status[name]=False
                hint=scanner_fix_hint(name,msg)
                if hint: fixes.append(hint)
                if "output unreadable" in msg: notes.append(f"{name}: {msg}")
        # Optional extra scanners: used when installed, never required. A failure is a note, not a block.
        # Psalm loads the project's own autoloader and plugins, so it runs project code: only with --run-tests,
        # like the project's test suite. Retire.js only reads files.
        optional=[("retire",collect_retire)]+([("psalm-taint",collect_psalm)] if args.run_tests else [])
        for name,fn in optional:
            try:
                ok,msg=fn(root,findings,mode=args.mode) if name=="retire" else fn(root,findings)
            except Exception as e:   # a malformed optional report is a note, never a crash or a pass
                ok,msg=False,f"report could not be read ({type(e).__name__}); its findings are missing"
            if ok is None: continue
            notes.append(f"{name}: {msg}")
        # MCP launch configs in the project (7.0): read only, never starts a server, never reads user-level files.
        mcp=_mcp_scan()
        if mcp is None:
            notes.append("mcp-scan not loaded (scripts/mcp_scan.py missing or broken); MCP configs were not checked")
        else:
            try:
                mf,mn=mcp.gate_findings(root); findings+=mf; notes+=mn
            except Exception as e:
                notes.append(f"mcp-scan stopped ({type(e).__name__}); its findings are missing")
        # Per-language engines (osv-scanner, Bandit, pip-audit, gosec, govulncheck, npm audit, ESLint security,
        # Dependency-Check, SpotBugs + FindSecBugs, Security Code Scan, CodeQL): run when installed and relevant to
        # the project's languages. Missing ones are NOTE lines, never a block, in full and ci alike.
        eng=_engines()
        if eng is None:
            notes.append("per-language engines not loaded (scripts/engines missing or broken); only the core scanners ran")
        else:
            try:
                engine_status=eng.run_engines(root,findings,notes,args.mode,args.run_tests,find=find_tool,runner=run)
            except Exception as e:
                notes.append(f"per-language engines stopped ({type(e).__name__}); their findings are missing")
        if args.run_tests:
            for cmd in project_commands(root,notes):
                rc,out,err=run(cmd,root,1200,safe_git=False)
                ran_tests.append({"command":" ".join([Path(str(cmd[0])).name,*map(str,cmd[1:])]),"exit":rc})
                if rc!=0:
                    findings.append({"rule":"TEST_FAILURE","severity":"HIGH","file":"","line":0,
                        "message":f"Project command failed: {' '.join(cmd)}","code":(out+err)[-1000:],"engine":"project-tests"})
    findings=apply_suppressions(findings,root,args.mode,notes)
    # Quick mode runs on every edit through the hook; it must not litter every project with .security/.
    if args.mode!="quick" or args.report:
        counts=write_reports(root,findings,args.mode,{**status,"engines":engine_status,"errors":errors,"notes":notes,"project_tests":ran_tests})
    else:
        counts={s:sum(1 for f in findings if f["severity"]==s) for s in SEV}
    missing=[t for t,v in status.items() if not v]
    print(f"=== ORG AI SECURE APPSEC GATE {GATE_VERSION} ===")
    print(safe_text(f"Mode: {args.mode} Target: {target}"))
    for name,msg in errors.items():
        print(safe_text(f"ERROR: {name} did not complete:"))
        for line in msg.split(" | "):
            print("    "+safe_text(line))
    for n in notes:
        print(safe_text(f"NOTE: {n}"))
    # A failed scanner no longer hides the rest: the built-in checks and the other scanners' findings still print.
    ci_failed=args.mode=="ci" and bool(errors)
    if missing and not ci_failed:
        print("WARNING: PARTIAL SCAN, scanners not available:",", ".join(missing),"(use --mode ci before handover)")
    print("Counts:",counts)
    for f in findings[:100]:
        print(safe_text(f"[{f['severity']}] {f['rule']} {f.get('file','')}:{f.get('line',0)} — {f['message']}"))
    threshold={"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW","never":None}[args.fail_on]
    blocked=bool(threshold and any(SEV.get(f["severity"],9)<=SEV[threshold] for f in findings))
    if ci_failed:       # fail closed: a required scanner errored, so the scan is incomplete whatever the counts say
        for h in fixes:
            print(safe_text(f"FIX: {h}"))
        print("RESULT: BLOCKED (ci) a required scanner failed (" + ", ".join(errors) + "), so the scan is incomplete. "
              "The findings above are from the checks that did run.")
        return 3
    print("RESULT: BLOCKED" if blocked else ("RESULT: PASS (PARTIAL)" if missing else "RESULT: PASS"))
    return 2 if blocked else 0
if __name__=="__main__": raise SystemExit(main())

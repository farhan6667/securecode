#!/usr/bin/env python3
"""Org AI Secure AppSec Gate V6.

Modes:
 quick: lightweight changed-file heuristics only.
 full: real Semgrep + Trivy + Gitleaks + project tests/build + optional ZAP.
 ci: same as full, but fails closed when required scanners are missing.

No scanner is claimed to run in quick mode.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

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
("XSS_RAW_TEMPLATE","HIGH",r"\{!!\s*\$|<%-\s*[\w.]|\|\s*(?:safe|raw)\s*\}\}|v-html\s*="),
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
                if re.search(rx,line):
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
    return None

def scanner_env(cwd,hooks_dir):
    # Scanners run git inside the scanned repo (gitleaks runs git log -p, semgrep git ls-files). The repo's own
    # .git/config must not be able to run programs there (fsmonitor, hooks, textconv and filter drivers): see safe_git.py.
    try:
        here=os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path: sys.path.insert(0,here)
        import safe_git
        return safe_git.safe_git_env(find_tool("git"),cwd,hooks_dir)
    except Exception:
        return None

def run(cmd,cwd,timeout=600):
    # Run exactly the executable find_tool chose, never a bare name that the OS would resolve itself.
    exe=find_tool(cmd[0])
    if not exe: return 127,"",f"missing executable: {cmd[0]}"
    cmd=[exe,*cmd[1:]]
    hooks=tempfile.mkdtemp(prefix="nfsc-nohooks-")
    try:
        env=scanner_env(cwd,hooks)
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
    cfgs=[str(p) for p in (ORG_SEMGREP, ORG_SEMGREP.parent/"laravel-authz.yml") if p.exists()]
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
    try:
        data=json.loads(out)
    except json.JSONDecodeError:
        return False,(err or "semgrep returned no JSON").strip()[-400:]
    for r in (data.get("results") or [] if isinstance(data,dict) else []):
        ex=r.get("extra",{}); sev=(ex.get("severity") or "WARNING").upper()
        sev={"ERROR":"HIGH","WARNING":"MEDIUM","INFO":"LOW"}.get(sev,sev if sev in SEV else "MEDIUM")
        rid=str(r.get("check_id","SEMGREP"))
        meta=ex.get("metadata") or {}
        sev=semgrep_override(rid,sev,meta.get("confidence","") if isinstance(meta,dict) else "")
        findings.append({"rule":rid,"severity":sev,
            "file":r.get("path",""),"line":(r.get("start") or {}).get("line",0),
            "message":ex.get("message","Semgrep finding"),"code":(ex.get("lines") or "")[:180],
            "confidence":str(meta.get("confidence","")) if isinstance(meta,dict) else "",
            "engine":"semgrep"})
    # rc 0 = clean, 1 = findings; anything else (config or network error) is a failed scan.
    return rc in (0,1), "semgrep completed" if rc in (0,1) else f"semgrep exited {rc}: {(err or '').strip()[-300:]}"

def collect_trivy(root,findings,mode="full"):
    if not find_tool("trivy"): return False,"trivy missing"
    cmd=["trivy","fs","--scanners","vuln,misconfig,secret","--format","json"]
    if mode=="ci":
        if not CI_EMPTY_IGNORE.is_file(): return False,f"ci ignore file missing from the package: {CI_EMPTY_IGNORE.name}"
        # an empty string disables trivy.yaml and trivy-secret.yaml; the ignore file is the package's empty one
        cmd += ["--config","","--secret-config","","--ignorefile",str(CI_EMPTY_IGNORE)]
    rc,out,err=run(cmd+["."],root,1200)
    try:
        data=json.loads(out)
    except Exception:
        return False,err or "trivy returned invalid JSON"
    for res in (data.get("Results") or [] if isinstance(data,dict) else []):
        for v in res.get("Vulnerabilities",[]) or []:
            sev=v.get("Severity","UNKNOWN").upper(); sev=sev if sev in SEV else "MEDIUM"
            findings.append({"rule":v.get("VulnerabilityID","TRIVY"),"severity":sev,"file":res.get("Target",""),
                "line":0,"message":f"{v.get('PkgName','dependency')} {v.get('InstalledVersion','')} -> {v.get('FixedVersion') or 'no fixed version'}: {v.get('Title','Known vulnerability')}",
                "code":"","engine":"trivy"})
        for m in res.get("Misconfigurations",[]) or []:
            sev=m.get("Severity","UNKNOWN").upper(); sev=sev if sev in SEV else "MEDIUM"
            findings.append({"rule":m.get("ID","TRIVY-MISCONFIG"),"severity":sev,"file":res.get("Target",""),
                "line":0,"message":m.get("Message","Misconfiguration"),"code":"","engine":"trivy"})
        for s in res.get("Secrets",[]) or []:
            findings.append({"rule":s.get("RuleID","TRIVY-SECRET"),"severity":"CRITICAL","file":res.get("Target",""),
                "line":s.get("StartLine",0),"message":s.get("Title","Secret detected"),"code":"","engine":"trivy"})
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
        data=json.loads(rp.read_text(encoding="utf-8",errors="ignore") or "[]")
    except Exception:
        return False,f"gitleaks exited {rc} without a readable report: {(err or out).strip()[-300:]}"
    for x in (data if isinstance(data,list) else []):
        if not isinstance(x,dict): continue
        findings.append({"rule":x.get("RuleID","GITLEAKS"),"severity":"CRITICAL","file":x.get("File",""),
            "line":x.get("StartLine",0),"message":x.get("Description","Secret detected"),"code":"","engine":"gitleaks"})
    return rc in (0,1), "gitleaks completed"

RETIRE_SEV={"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW"}

def collect_retire(root,findings):
    """Retire.js (Apache-2.0) finds vulnerable client-side libraries by signature, including copies
    renamed or bundled inside themes. Returns (None, "") when it is not installed."""
    if not find_tool("retire"): return None,""
    out_dir=Path(tempfile.mkdtemp(prefix="sc-retire-")); rp=out_dir/"retire.json"
    try:
        rc,out,err=run(["retire","--outputformat","json","--outputpath",str(rp),"--path","."],root,900)
        try: data=json.loads(rp.read_text(encoding="utf-8",errors="ignore") or "{}")
        except (OSError,json.JSONDecodeError): return False,f"retire exited {rc} without a readable report"
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
    try: issues=json.loads(out or "[]")
    except json.JSONDecodeError: return False,f"psalm exited {rc} without JSON output"
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

def valid_expiry(v):
    # A real calendar date at most about 12 months ahead: exceptions must come back for review.
    import datetime
    try: d=datetime.date.fromisoformat(str(v))
    except ValueError: return False
    return d<=datetime.date.today()+datetime.timedelta(days=366)

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
        if not (isinstance(s,dict) and s.get("rule") and s.get("file") and s.get("owner") and s.get("reason") and
                valid_expiry(s.get("expires"))) or str(s["file"]).startswith(("/","\\")) or ".." in str(s["file"]):
            notes.append(f"ignored an incomplete suppression entry: {str(s)[:120]}"); continue
        valid.append(s)
    return valid

def apply_suppressions(findings,root,mode="quick",notes=None):
    notes=[] if notes is None else notes
    sups=load_suppressions(suppression_file(root,mode,notes),notes); today=time.strftime("%Y-%m-%d"); out=[]
    for f in findings:
        try: rel=Path(f["file"]).resolve().relative_to(root).as_posix()
        except Exception: rel=str(f["file"]).replace("\\","/")
        suppressed=False
        for s in sups:
            sf=str(s["file"]).replace("\\","/")
            if (sf[2:] if sf.startswith("./") else sf)!=rel: continue
            if s.get("rule","*")!="*" and s.get("rule")!=f["rule"]: continue
            if str(s["expires"])<today: continue
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
           "runs":[{"tool":{"driver":{"name":"Org AI Secure AppSec Gate V6"}},
                     "results":[{"ruleId":f["rule"],"level":{"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(f["severity"],"note"),
                                 "message":{"text":f["message"]},"locations":[{"physicalLocation":{"artifactLocation":{"uri":str(f["file"])},"region":{"startLine":max(1,int(f.get("line") or 1))}}}]}
                                for f in findings]}]}
    (sec/"findings.sarif").write_text(json.dumps(sarif,indent=2),encoding="utf-8")
    return counts

CONTROL=re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")

def safe_text(s):
    # A file name with a newline could print a fake "RESULT: PASS" line or a CI workflow command.
    return CONTROL.sub("?",str(s))

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
    findings=local_scan(target)+agent_scan(target)+library_scan(target)+config_scan(target)
    status={}; errors={}; notes=[]
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
            ok,msg=fn(root,findings,mode=args.mode)
            if not ok:
                errors[name]=msg; status[name]=False
        # Optional extra scanners: used when installed, never required. A failure is a note, not a block.
        # Psalm loads the project's own autoloader and plugins, so it runs project code: only with --run-tests,
        # like the project's test suite. Retire.js only reads files.
        optional=[("retire",collect_retire)]+([("psalm-taint",collect_psalm)] if args.run_tests else [])
        for name,fn in optional:
            try:
                ok,msg=fn(root,findings)
            except Exception as e:   # a malformed optional report is a note, never a crash or a pass
                ok,msg=False,f"report could not be read ({type(e).__name__}); its findings are missing"
            if ok is None: continue
            notes.append(f"{name}: {msg}")
        if args.run_tests:
            for cmd in project_commands(root,notes):
                rc,out,err=run(cmd,root,1200)
                if rc!=0:
                    findings.append({"rule":"TEST_FAILURE","severity":"HIGH","file":"","line":0,
                        "message":f"Project command failed: {' '.join(cmd)}","code":(out+err)[-1000:],"engine":"project-tests"})
    findings=apply_suppressions(findings,root,args.mode,notes)
    # Quick mode runs on every edit through the hook; it must not litter every project with .security/.
    if args.mode!="quick" or args.report:
        counts=write_reports(root,findings,args.mode,{**status,"errors":errors,"notes":notes})
    else:
        counts={s:sum(1 for f in findings if f["severity"]==s) for s in SEV}
    missing=[t for t,v in status.items() if not v]
    print("=== ORG AI SECURE APPSEC GATE V6.2 ===")
    print(safe_text(f"Mode: {args.mode} Target: {target}"))
    for name,msg in errors.items():
        print(safe_text(f"ERROR: {name} did not complete: {msg}"))
    for n in notes:
        print(safe_text(f"NOTE: {n}"))
    if args.mode=="ci" and errors:
        print("RESULT: BLOCKED (ci) a required scanner failed, so the scan is incomplete. Fix the error above and re-run.")
        return 3
    if missing:
        print("WARNING: PARTIAL SCAN, scanners not available:",", ".join(missing),"(use --mode ci before handover)")
    print("Counts:",counts)
    for f in findings[:100]:
        print(safe_text(f"[{f['severity']}] {f['rule']} {f.get('file','')}:{f.get('line',0)} — {f['message']}"))
    threshold={"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW","never":None}[args.fail_on]
    blocked=bool(threshold and any(SEV.get(f["severity"],9)<=SEV[threshold] for f in findings))
    print("RESULT: BLOCKED" if blocked else ("RESULT: PASS (PARTIAL)" if missing else "RESULT: PASS"))
    return 2 if blocked else 0
if __name__=="__main__": raise SystemExit(main())

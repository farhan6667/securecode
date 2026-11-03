"""7.0 secgate checks: legacy audit (webshells and backdoors), code heuristics from pentest findings,
PHP upgrade readiness and database configuration. Every rule has positive and negative cases, and
every new pattern gets a timing test against inputs built to make a regex backtrack.

All samples are short, synthetic and inert. They are written to a temporary folder and only read by
the scanner; nothing here is executed.
"""
import importlib.util
import re
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def gate():
    spec = importlib.util.spec_from_file_location("secgate_v7", ROOT / "scripts" / "secgate.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


G = gate()


def write(tmp, files):
    for rel, text in files.items():
        f = tmp / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            f.write_bytes(text)
        else:
            f.write_text(text, encoding="utf-8")


def scan(tmp, files, which="all"):
    write(tmp, files)
    out = []
    fns = {"malware": [G.malware_scan], "code": [G.code_scan], "db": [G.db_config_scan], "defaults": [G.default_cred_scan],
           "all": [G.malware_scan, G.code_scan, G.db_config_scan, G.default_cred_scan]}[which]
    for fn in fns:
        for f in fn(str(tmp)):
            rel = Path(f["file"]).resolve().relative_to(tmp.resolve()).as_posix()
            out.append((rel, f["rule"], f["severity"], f["line"]))
    return out


def rules_for(found, rel):
    return sorted({r for p, r, _, _ in found if p == rel})


# ------------------------------------------------------------------ legacy audit: positives
MALWARE_POS = {
    "shell1.php": ("<?php @eval(gzinflate(base64_decode('SU5FUlQ=')));\n", "WEBSHELL_OBFUSCATED_EVAL"),
    "shell2.php": ("<?php\nif (isset($_POST['x'])) { eval($_POST['x']); }\n", "BACKDOOR_REQUEST_EXEC"),
    "shell3.php": ("<?php system($_GET['c']);\n", "BACKDOOR_REQUEST_EXEC"),
    "shell4.php": ("<?php $_GET['f']($_POST['a']);\n", "REQUEST_DYNAMIC_CALL"),
    "shell5.php": ("<?php call_user_func($_REQUEST['f'], 'x');\n", "REQUEST_DYNAMIC_CALL"),
    "shell6.php": ("<?php preg_replace('/.*/e', $_POST['r'], '');\n", "PREG_REPLACE_EVAL"),
    "shell7.php": ("<?php echo `ls $_GET[d]`;\n", "BACKDOOR_REQUEST_EXEC"),
    "shell8.php": ("<?php eval('?>' . file_get_contents('php://input'));\n", "BACKDOOR_REQUEST_EXEC"),
    "shell9.php": ("<?php assert(str_rot13('flfgrz'));\n", "WEBSHELL_OBFUSCATED_EVAL"),
    "shell10.php": ("<?php include($_GET['page']);\n", "BACKDOOR_REQUEST_EXEC"),
    "shell11.php": ("<?php passthru(getallheaders()['X-C']);\n", "BACKDOOR_REQUEST_EXEC"),
    "web/a.js": ("eval(atob('Y29uc29sZS5sb2coMSk='));\n", "WEBSHELL_OBFUSCATED_EVAL"),
    "web/b.js": ("const run = new Function(atob(payload));\n", "WEBSHELL_OBFUSCATED_EVAL"),
    "web/c.js": ("app.get('/x', (req, res) => { require('child_process').exec(req.query.cmd); });\n", "BACKDOOR_REQUEST_EXEC"),
    "web/d.js": ("const { exec } = require('child_process');\nexec(req.body.c, () => {});\n", "BACKDOOR_REQUEST_EXEC"),
    "py/a.py": ("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n", "WEBSHELL_OBFUSCATED_EVAL"),
    "py/b.py": ("import os\nos.system(request.args.get('c'))\n", "BACKDOOR_REQUEST_EXEC"),
    "py/c.py": ("eval(request.form['expr'])\n", "BACKDOOR_REQUEST_EXEC"),
    "jsp/cmd.jsp": ("<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>\n", "BACKDOOR_REQUEST_EXEC"),
    "jsp/pb.jsp": ("<% new ProcessBuilder(\"sh\", \"-c\", request.getParameter(\"c\")).start(); %>\n", "BACKDOOR_REQUEST_EXEC"),
    "net/a.aspx": ("<% Process.Start(\"cmd.exe\", \"/c \" + Request.QueryString[\"c\"]); %>\n", "BACKDOOR_REQUEST_EXEC"),
    "net/b.aspx": ("<% eval(Request.Item[\"k\"], \"unsafe\"); %>\n", "BACKDOOR_REQUEST_EXEC"),
}


@pytest.mark.parametrize("rel", sorted(MALWARE_POS))
def test_malware_positive(tmp_path, rel):
    text, rule = MALWARE_POS[rel]
    found = scan(tmp_path, {rel: text}, "malware")
    assert rule in rules_for(found, rel), found


def test_escaped_request_exec_is_lowered_to_high(tmp_path):
    found = scan(tmp_path, {"a.php": "<?php exec('ls ' . escapeshellarg($_GET['d']));\n"}, "malware")
    assert [(r, s) for _, r, s, _ in found] == [("BACKDOOR_REQUEST_EXEC", "HIGH")]


def test_php_in_upload_and_image_folders(tmp_path):
    files = {
        "public/uploads/avatar.php": "<?php echo 1;\n",
        "wp-content/uploads/2024/01/x.php": "<?php echo 1;\n",
        "images/thumb.php": "<?php echo 1;\n",
        "public/img/logo.png": b"GIF89a\x00\x00<?php echo 1; ?>\x00",
        "storage/app/public/doc.phtml": "<?php echo 1;\n",
        # negatives
        "public/uploads/index.php": "<?php\n// Silence is golden.\n",
        "app/Image/ImageService.php": "<?php\nclass ImageService {}\n",
        "resources/images/helper.php": "<?php\nreturn [];\n",
        "public/img/real.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        "public/index.php": "<?php require __DIR__.'/../vendor/autoload.php';\n",
    }
    found = scan(tmp_path, files, "malware")
    got = {(p, r) for p, r, _, _ in found}
    assert got == {("public/uploads/avatar.php", "PHP_IN_UPLOAD_DIR"),
                   ("wp-content/uploads/2024/01/x.php", "PHP_IN_UPLOAD_DIR"),
                   ("images/thumb.php", "PHP_IN_UPLOAD_DIR"),
                   ("public/img/logo.png", "PHP_IN_IMAGE_FILE"),
                   ("storage/app/public/doc.phtml", "PHP_IN_UPLOAD_DIR")}, got


def test_placeholder_needs_to_be_small(tmp_path):
    big = "<?php\n" + "// header\n" * 400 + "eval($x);\n"
    found = scan(tmp_path, {"public/uploads/index.php": big}, "malware")
    assert ("public/uploads/index.php", "PHP_IN_UPLOAD_DIR") in {(p, r) for p, r, _, _ in found}


def test_obfuscation(tmp_path):
    blob = "QUJD" * 300
    files = {
        "lib/loader.php": f"<?php $p = '{blob}';\n",
        "lib/chars.php": "<?php $f = " + ".".join(["chr(101)"] * 14) + ";\n",
        "lib/hex.js": "var s = '" + "\\x41" * 50 + "';\n",
        "lib/chain.php": "<?php $c = gzinflate(base64_decode($p));\n",
        # negatives: data URI, vendor code, a minified bundle, short base64, a normal hash
        "public/css/app.css.js": f"const bg = 'url(data:image/png;base64,{blob})';\n",
        "vendor/pkg/font.php": f"<?php return '{blob}';\n",
        "public/js/app.min.js": f"var x='{blob}';\n",
        "lib/ok.php": "<?php $h = hash('sha256', $data); $b = base64_encode($bytes);\n",
    }
    found = scan(tmp_path, files, "malware")
    got = {p for p, r, _, _ in found if r == "SUSPICIOUS_OBFUSCATION"}
    assert got == {"lib/loader.php", "lib/chars.php", "lib/hex.js", "lib/chain.php"}, found


CLEAN_FRAMEWORK = {
    "app/Http/Controllers/OrderController.php": """<?php
namespace App\\Http\\Controllers;
use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Support\\Facades\\Process;
class OrderController extends Controller {
    public function index(Request $request) {
        $data = $request->validate(['q' => 'string|max:50']);
        $rows = DB::select('select * from orders where note like ?', ['%'.$data['q'].'%']);
        collect($rows)->each(fn ($r) => logger()->info($r->id));
        $result = Process::run(['git', 'status']);
        $pdo->exec('SET NAMES utf8mb4');
        $h = curl_exec($ch);
        return view('orders.index', ['rows' => $rows]);
    }
}
""",
    "resources/views/orders/index.blade.php": "@include('partials.nav')\n<script>$('li').each(function () {});</script>\n{{ $title }}\n",
    "routes/web.php": "<?php\nRoute::get('/', fn () => view('home'));\nrequire __DIR__.'/auth.php';\n",
    "config/app.php": "<?php\nreturn ['key' => env('APP_KEY'), 'cipher' => 'AES-256-CBC'];\n",
    "src/main/java/demo/Api.java": """package demo;
@RestController
public class Api {
    @GetMapping("/run")
    public String run(@RequestParam String name) throws Exception {
        Process p = new ProcessBuilder("git", "status").start();
        return Pattern.compile("^[a-z]+$").matcher(name).matches() ? "ok" : "no";
    }
}
""",
    "server/app.js": """const express = require('express');
const { execFile } = require('child_process');
const app = express();
app.get('/page', (req, res) => {
  const ok = /^\\d+$/.exec(req.query.page);
  execFile('git', ['status'], () => {});
  res.json({ ok: !!ok });
});
""",
    "tools/build.py": "import re, subprocess\nPAT = re.compile(r'x')\nsubprocess.run(['ls'], check=True)\n",
}


def test_clean_framework_code_has_no_malware_hits(tmp_path):
    assert scan(tmp_path, CLEAN_FRAMEWORK, "malware") == []


def test_comment_lines_are_not_reported(tmp_path):
    found = scan(tmp_path, {"a.php": "<?php\n// eval(base64_decode($x)) was removed in 2019\n"}, "malware")
    assert found == []


# ------------------------------------------------------------------ code heuristics
def test_missing_input_validation_laravel(tmp_path):
    ctrl = """<?php
class OrderController extends Controller
{
    public function store(Request $request)
    {
        return Order::create(['note' => $request->input('note')]);
    }

    public function update(Request $request, Order $order)
    {
        $data = $request->validate(['note' => 'required|string|max:200']);
        $order->update($data);
    }

    public function save(StoreOrderRequest $request)
    {
        return Order::create(['note' => $request->input('note')]);
    }

    public function show(Order $order)
    {
        return $order;
    }
}
"""
    found = scan(tmp_path, {"app/Http/Controllers/OrderController.php": ctrl}, "code")
    hits = [(r, ln) for _, r, _, ln in found if r == "MISSING_INPUT_VALIDATION"]
    assert hits == [("MISSING_INPUT_VALIDATION", 6)], found


def test_missing_input_validation_express(tmp_path):
    bad = "const router = require('express').Router();\nrouter.post('/orders', (req, res) => {\n  db.insert(req.body);\n});\n"
    good = "const { z } = require('zod');\n" + bad
    found = scan(tmp_path, {"routes/orders.js": bad, "routes/items.js": good, "lib/util.js": "module.exports = (req) => req.body;\n"}, "code")
    assert [(p, ln) for p, r, _, ln in found if r == "MISSING_INPUT_VALIDATION"] == [("routes/orders.js", 3)], found


def test_debug_switch_from_request(tmp_path):
    files = {
        "app/Http/Controllers/A.php": "<?php\nif ($request->input('debug') == '1') {\n    return response()->json(config('app'));\n}\n",
        "server/b.js": "app.get('/s', (req, res) => {\n  if (req.query.debug) { return res.json(process.env); }\n});\n",
        "app/views.py": "def s(request):\n    if request.GET.get('test'):\n        return JsonResponse(dict(os.environ))\n",
        "app/Http/Controllers/C.php": "<?php\nif ($request->header('X-Debug')) {\n    Log::setLevel('debug');\n}\n",
        # negatives: server-side switch only, request flag bound to local env, unrelated param
        "app/Http/Controllers/N1.php": "<?php\nif (app()->isLocal()) {\n    return config('app');\n}\n",
        "app/Http/Controllers/N2.php": "<?php\nif ($request->boolean('debug') && app()->isLocal()) {\n    return config('app');\n}\n",
        "app/Http/Controllers/N3.php": "<?php\nif ($request->input('page') > 1) {\n    return config('app.per_page');\n}\n",
    }
    found = scan(tmp_path, files, "code")
    got = {(p, s) for p, r, s, _ in found if r == "DEBUG_FLAG_FROM_REQUEST"}
    assert got == {("app/Http/Controllers/A.php", "HIGH"), ("server/b.js", "HIGH"), ("app/views.py", "HIGH"),
                   ("app/Http/Controllers/C.php", "MEDIUM")}, found


def test_weak_tokens(tmp_path):
    files = {
        "app/a.php": "<?php\n$token = base64_encode($user->id . time());\n",
        "web/b.js": "const csrfToken = btoa(user.role);\n",
        "app/c.py": "reset_token = hashlib.md5(user.email.encode()).hexdigest()\n",
        "app/d.php": "<?php\n$data['invite_token'] = md5($email . uniqid());\n",
        # negatives
        "app/n1.php": "<?php\n$token = bin2hex(random_bytes(32));\n$avatar = md5($user->email);\n$tokenExpiresAt = time() + 3600;\n",
        "web/n2.js": "const token = crypto.randomBytes(32).toString('hex');\nconst sig = createHmac('sha256', key).update(user.id).digest('hex');\n",
        "app/n3.py": "token = secrets.token_urlsafe(32)\nif token == md5(user.email):\n    pass\n",
    }
    found = scan(tmp_path, files, "code")
    got = {p for p, r, _, _ in found if r == "TOKEN_FROM_USER_DATA"}
    assert got == {"app/a.php", "web/b.js", "app/c.py", "app/d.php"}, found


def test_short_codes_and_tokens(tmp_path):
    files = {
        "app/a.php": "<?php\n$otp = random_int(1000, 9999);\n$inviteToken = Str::random(8);\n",
        "web/b.js": "const code = Math.floor(1000 + Math.random() * 9000);\n",
        "app/n.php": "<?php\n$otp = random_int(100000, 999999);\n$spinner = rand(0, 3);\n$apiToken = Str::random(40);\n$codeCount = rand(1, 5);\n",
    }
    found = scan(tmp_path, files, "code")
    got = {(p, r) for p, r, _, _ in found if r in ("SHORT_NUMERIC_CODE", "TOKEN_TOO_SHORT")}
    assert got == {("app/a.php", "SHORT_NUMERIC_CODE"), ("app/a.php", "TOKEN_TOO_SHORT"), ("web/b.js", "SHORT_NUMERIC_CODE")}, found


def test_public_env_secret(tmp_path):
    files = {
        ".env": "VITE_ADMIN_API_TOKEN=x\nVITE_STRIPE_PUBLISHABLE_KEY=pk\nVITE_API_URL=https://api\n",
        ".env.local": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x\nNEXT_PUBLIC_MAPBOX_TOKEN=pk\nNEXT_PUBLIC_SUPABASE_ANON_KEY=x\n",
        "src/api.ts": "const s = import.meta.env.VITE_STRIPE_SECRET_KEY;\nconst u = import.meta.env.VITE_API_URL;\n",
        "server/env.ts": "const s = process.env.STRIPE_SECRET_KEY;\n",
    }
    found = scan(tmp_path, files, "code")
    got = {(p, ln) for p, r, _, ln in found if r == "PUBLIC_ENV_SECRET"}
    assert got == {(".env", 1), (".env.local", 1), ("src/api.ts", 1)}, found
    # the value is never echoed in the finding
    for f in G.code_scan(str(tmp_path)):
        if f["rule"] == "PUBLIC_ENV_SECRET":
            assert "=" not in f["code"]


def test_sourcemaps_in_production(tmp_path):
    files = {
        "vite.config.ts": "export default { build: { sourcemap: true } };\n",
        "vue.config.js": "module.exports = { productionSourceMap: true };\n",
        "dist/assets/app.js.map": "{}\n",
        # negatives
        "frontend/vite.config.js": "export default { build: { sourcemap: 'hidden' } };\n",
        "webpack.dev.js": "module.exports = { devtool: 'source-map' };\n",
        "src/app.js.map": "{}\n",
    }
    found = scan(tmp_path, files, "code")
    got = {p for p, r, _, _ in found if r == "SOURCEMAP_IN_PROD"}
    assert got == {"vite.config.ts", "vue.config.js", "dist/assets/app.js.map"}, found


def test_auth_routes_without_throttle_laravel(tmp_path):
    web = """<?php
Route::post('/login', [LoginController::class, 'store']);
Route::post('/otp/verify', [OtpController::class, 'verify']);
Route::post('/register', [RegisterController::class, 'store'])->middleware('throttle:5,1');
Route::middleware('throttle:login')->group(function () {
    Route::post('/password/reset', [ResetController::class, 'store']);
});
Route::post('/orders', [OrderController::class, 'store']);
Route::get('/login', [LoginController::class, 'create']);
"""
    found = scan(tmp_path, {"routes/web.php": web}, "code")
    got = {(ln, s) for _, r, s, ln in found if r == "AUTH_ROUTE_NO_THROTTLE"}
    assert got == {(2, "MEDIUM"), (3, "HIGH")}, found


def test_laravel_limiter_elsewhere_lowers_severity(tmp_path):
    files = {"routes/auth.php": "<?php\nRoute::post('login', [AuthenticatedSessionController::class, 'store']);\n",
             "app/Http/Requests/Auth/LoginRequest.php": "<?php\nclass LoginRequest { public function authenticate() { $this->ensureIsNotRateLimited(); } }\n"}
    found = scan(tmp_path, files, "code")
    assert [(r, s) for _, r, s, _ in found if r == "AUTH_ROUTE_NO_THROTTLE"] == [("AUTH_ROUTE_NO_THROTTLE", "LOW")]


def test_auth_routes_without_throttle_express(tmp_path):
    files = {
        "routes/auth.js": "router.post('/login', loginHandler);\nrouter.post('/verify-otp', otpHandler);\nrouter.post('/reset', resetLimiter, resetHandler);\nrouter.post('/orders', create);\n",
        "routes/global.js": "app.use(rateLimit({ windowMs: 60000, max: 10 }));\napp.post('/login', loginHandler);\n",
    }
    found = scan(tmp_path, files, "code")
    got = {(p, ln, s) for p, r, s, ln in found if r == "AUTH_ROUTE_NO_THROTTLE"}
    assert got == {("routes/auth.js", 1, "MEDIUM"), ("routes/auth.js", 2, "HIGH")}, found


def test_denylist_fix(tmp_path):
    bad = """<?php
if (str_contains($request->input('q'), "'")) { abort(400); }
$rows = DB::select("SELECT * FROM users WHERE name = '" . $request->input('q') . "'");
"""
    bad_js = """if (req.query.name.includes('<script>')) return res.status(400).end();
res.send('<h1>' + req.query.name + '</h1>');
"""
    good = """<?php
if (str_contains($request->input('q'), "'")) { abort(400); }
$rows = DB::select('SELECT * FROM users WHERE name = ?', [$request->input('q')]);
"""
    found = scan(tmp_path, {"app/a.php": bad, "web/b.js": bad_js, "app/c.php": good}, "code")
    got = {(p, ln) for p, r, _, ln in found if r == "DENYLIST_FIX"}
    assert got == {("app/a.php", 2), ("web/b.js", 1)}, found


def test_php_deprecations(tmp_path):
    old = """<?php
while (list($k, $v) = each($arr)) {}
$r = mysql_query($sql);
$s = utf8_encode($t);
$b = (boolean) $x;
$m = "Hello ${name}";
function f(Foo $x = null) {}
function g($a, array $opts = null) {}
$c = get_class();
curl_close($ch);
"""
    new = """<?php
$items->each(fn ($i) => $i);
Foo::each($x);
function h(?Foo $x = null, Foo|null $y = null, mixed $z = null) {}
function mysql_helper() {}
$m = "Hello {$name}";
$b = (bool) $x;
$c = get_class($obj);
"""
    found = scan(tmp_path, {"legacy/old.php": old, "app/new.php": new,
                            "legacy/nullable.php": "<?php\nfunction g($a, array $opts = null) {}\n"}, "code")
    old_hits = sorted(ln for p, r, s, ln in found if p == "legacy/old.php" and r == "PHP_DEPRECATED_API")
    # One finding per construct per file: line 8 is the second implicit-nullable signature.
    assert old_hits == [2, 3, 4, 5, 6, 7, 9, 10], found
    assert ("legacy/nullable.php", "PHP_DEPRECATED_API", "LOW", 2) in found, "non-first nullable param must be reported"
    assert all(s == "LOW" for p, r, s, _ in found if r == "PHP_DEPRECATED_API")
    assert not [f for f in found if f[0] == "app/new.php" and f[1] == "PHP_DEPRECATED_API"], found


def test_test_files_are_skipped_by_code_rules(tmp_path):
    found = scan(tmp_path, {"tests/Feature/TokenTest.php": "<?php\n$token = base64_encode($user->id . time());\n"}, "code")
    assert found == []


# ------------------------------------------------------------------ database configuration
def test_database_config(tmp_path):
    files = {
        ".env": "DB_USERNAME=root\nDB_PASSWORD=\nDATABASE_URL=postgres://postgres:pw@db.prod:5432/app\n",
        ".env.example": "DB_USERNAME=root\nDB_PASSWORD=\n",
        "config/database.php": "<?php\nreturn ['pgsql' => ['username' => env('DB_USERNAME', 'root'), 'sslmode' => 'disable'],\n 'mysql' => ['sslmode' => 'prefer']];\n",
        "src/main/resources/application.properties": "spring.datasource.url=jdbc:mysql://db.internal:3306/app?useSSL=false\nspring.datasource.username=root\n",
        "deploy/my.cnf": "[mysqld]\nbind-address = 0.0.0.0\n",
        "deploy/pg_hba.conf": "host all all 0.0.0.0/0 trust\nhost all all 127.0.0.1/32 trust\n",
        "deploy/mongod.conf": "net:\n  bindIp: 0.0.0.0\nsecurity:\n  authorization: disabled\n",
        "docker-compose.yml": "services:\n  db:\n    environment:\n      MYSQL_ALLOW_EMPTY_PASSWORD: \"yes\"\n    ports:\n      - \"3306:3306\"\n  cache:\n    ports:\n      - \"127.0.0.1:6379:6379\"\n",
        "database/migrations/2024_01_01_create_cards.php": "<?php\n$table->string('card_number');\n$table->string('cvv', 4);\n$table->string('plain_password');\n$table->string('password', 20);\n$table->string('password');\n$table->string('card_last4', 4);\n$table->string('payment_token');\n",
        "db/grants.sql": "GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';\nGRANT SELECT, INSERT ON app.* TO 'app'@'10.0.0.5';\n",
        "knexfile.js": "module.exports = { connection: { host: 'db.prod', ssl: false } };\n",
        "src/mailer.js": "const opts = { ssl: false, encrypt: false };\nlet encrypt = false;\n",
    }
    found = scan(tmp_path, files, "db")
    got = {(p, r, s, ln) for p, r, s, ln in found}
    expect = {
        (".env", "DB_ROOT_USER", "MEDIUM", 1), (".env", "DB_EMPTY_PASSWORD", "MEDIUM", 2), (".env", "DB_ROOT_USER", "MEDIUM", 3),
        (".env.example", "DB_ROOT_USER", "LOW", 1),
        ("config/database.php", "DB_ROOT_USER", "LOW", 2), ("config/database.php", "DB_NO_TLS", "MEDIUM", 2),
        ("src/main/resources/application.properties", "DB_NO_TLS", "MEDIUM", 1),
        ("src/main/resources/application.properties", "DB_ROOT_USER", "MEDIUM", 2),
        ("deploy/my.cnf", "DB_BIND_ALL", "MEDIUM", 2),
        ("deploy/pg_hba.conf", "DB_TRUST_AUTH", "MEDIUM", 1),
        ("deploy/mongod.conf", "DB_BIND_ALL", "MEDIUM", 2), ("deploy/mongod.conf", "DB_TRUST_AUTH", "MEDIUM", 4),
        ("docker-compose.yml", "DB_EMPTY_PASSWORD", "MEDIUM", 4), ("docker-compose.yml", "DB_BIND_ALL", "LOW", 6),
        ("database/migrations/2024_01_01_create_cards.php", "DB_SENSITIVE_COLUMN", "MEDIUM", 2),
        ("database/migrations/2024_01_01_create_cards.php", "DB_SENSITIVE_COLUMN", "MEDIUM", 3),
        ("database/migrations/2024_01_01_create_cards.php", "DB_SENSITIVE_COLUMN", "MEDIUM", 4),
        ("database/migrations/2024_01_01_create_cards.php", "DB_SENSITIVE_COLUMN", "MEDIUM", 5),
        ("db/grants.sql", "DB_GRANT_ALL", "MEDIUM", 1),
        ("knexfile.js", "DB_NO_TLS", "MEDIUM", 1),
    }
    assert got == expect, (sorted(got - expect), sorted(expect - got))


def test_db_findings_never_echo_connection_secrets(tmp_path):
    files = {".env": "DATABASE_URL=postgres://postgres:hunter2pw@db.prod:5432/app?sslmode=disable\n",
             "src/main/resources/application.properties":
                 "spring.datasource.url=jdbc:sqlserver://db.prod;user=sa;password=hunter2pw;encrypt=false\n",
             "config/db.yml": "production:\n  url: mysql://app:hunter2pw@db.prod/app?useSSL=false\n"}
    found = scan(tmp_path, files, "db")
    assert {r for _, r, _, _ in found} >= {"DB_ROOT_USER", "DB_NO_TLS"}, found
    for f in G.db_config_scan(str(tmp_path)):
        assert "hunter2pw" not in f["code"] and "hunter2pw" not in f["message"], f


# ------------------------------------------------------------------ default values
def test_guessable_passwords(tmp_path):
    files = {
        "docker-compose.yml": "services:\n  db:\n    environment:\n      MYSQL_ROOT_PASSWORD: root\n      POSTGRES_PASSWORD: postgres\n"
                              "      MYSQL_USER: shop\n      MYSQL_PASSWORD: shop\n",
        "src/main/resources/application.properties": "spring.datasource.username=admin\nspring.datasource.password=admin123\n",
        ".env.example": "DB_PASSWORD=password\n",
        "database/seeders/AdminUserSeeder.php": "<?php\nUser::create(['name' => 'Admin', 'role' => 'admin', 'password' => bcrypt('letmein')]);\n",
        "scripts/make_admin.py": "User.objects.create_superuser('admin', 'admin@site.test', 'admin')\n",
        "config/legacy.cs": "var cs = \"Server=db;User Id=sa;Password=;\";\n",
        "config/cache.js": "const url = 'redis://default:changeme@cache.prod:6379';\n",
        "tests/Feature/LoginTest.php": "<?php\n$this->post('/login', ['email' => 'a@b.c', 'password' => 'password']);\n",
        "database/factories/UserFactory.php": "<?php\nreturn ['password' => static::$password ??= Hash::make('password')];\n",
    }
    found = scan(tmp_path, files, "defaults")
    got = {(p, ln, s) for p, r, s, ln in found if r == "WEAK_DEFAULT_CREDENTIAL"}
    assert got == {("docker-compose.yml", 4, "HIGH"), ("docker-compose.yml", 5, "HIGH"), ("docker-compose.yml", 7, "HIGH"),
                   ("src/main/resources/application.properties", 2, "HIGH"), (".env.example", 1, "MEDIUM"),
                   ("database/seeders/AdminUserSeeder.php", 2, "HIGH"), ("scripts/make_admin.py", 1, "HIGH"),
                   ("config/legacy.cs", 1, "HIGH"), ("config/cache.js", 1, "HIGH"),
                   ("tests/Feature/LoginTest.php", 2, "MEDIUM"), ("database/factories/UserFactory.php", 2, "MEDIUM")}, found
    for f in G.default_cred_scan(str(tmp_path)):
        for weak in ("admin123", "letmein", "changeme"):
            assert weak not in f["code"] and weak not in f["message"], f


def test_password_placeholders_and_labels_are_not_findings(tmp_path):
    files = {
        "docker-compose.yml": "services:\n  db:\n    environment:\n      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}\n      MYSQL_PASSWORD: \"<password>\"\n",
        ".env.example": "DB_PASSWORD=your-password-here\nADMIN_PASSWORD=\n",
        "config/database.php": "<?php\nreturn ['password' => env('DB_PASSWORD', '')];\n",
        "src/main/resources/application.yml": "spring:\n  datasource:\n    password: ${DB_PASSWORD}\n",
        "resources/lang/en.json": "{\"password\": \"Password\"}\n",
        "app/Http/Requests/RegisterRequest.php": "<?php\nreturn ['password' => 'required|min:12|confirmed'];\n",
        "src/form.js": "const field = { type: 'password', label: 'Password', autocomplete: 'current-password' };\nif (password === 'admin') {}\n",
        "app/settings.py": "PASSWORD_MIN_LENGTH = 12\nDATABASES = {'default': {'PASSWORD': os.environ['DB_PASSWORD']}}\n",
    }
    assert scan(tmp_path, files, "defaults") == []


def test_existing_seeder_check_is_not_duplicated(tmp_path):
    seeder = "<?php\nUser::create(['email' => 'admin@admin.com', 'password' => Hash::make('12345678')]);\n"
    write(tmp_path, {"database/seeders/AdminSeeder.php": seeder})
    own = [f for f in G.config_scan(str(tmp_path)) if f["rule"] == "WEAK_DEFAULT_CREDENTIAL"]
    new = [f for f in G.default_cred_scan(str(tmp_path)) if f["rule"] == "WEAK_DEFAULT_CREDENTIAL"]
    assert len(own) == 1 and new == []


def test_default_secret_keys(tmp_path):
    files = {
        ".env": "APP_KEY=\nJWT_SECRET=secret\nSESSION_SECRET=short\n",
        "config/app.php": "<?php\nreturn ['key' => env('APP_KEY', 'SomeRandomString')];\n",
        "legacy/.env.production": "APP_KEY=SomeRandomString\n",
        "mysite/settings.py": "SECRET_KEY = 'django-insecure-abc123abc123abc123abc123abc123abc123'\n",
        "src/main/resources/application.properties": "jwt.secret=secret\njwt.expiration=3600\n",
        "server/app.js": "app.use(session({ secret: 'keyboard cat', resave: false }));\nconst t = jwt.sign({ id: user.id }, 'your-256-bit-secret');\n",
        # negatives
        ".env.example": "APP_KEY=\nJWT_SECRET=\n",
        "server/ok.js": "app.use(session({ secret: process.env.SESSION_SECRET }));\nconst t = jwt.sign({ id: 1 }, process.env.JWT_SECRET);\n",
        "config/jwt.php": "<?php\nreturn ['secret' => env('JWT_SECRET'), 'ttl' => 60, 'algo' => 'HS256', 'jwt_expires_in' => 3600];\n",
        "src/main/resources/application-prod.yml": "jwt:\n  secret: ${JWT_SECRET}\n  expiration: 3600\n",
        "app/prod_settings.py": "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\n",
        "app/patterns.py": "_SESSION_SECRET = re.compile(r'x')\nJWT_SECRET = load_secret()\nadmin_password = admin\n",
    }
    found = scan(tmp_path, files, "defaults")
    got = {(p, ln) for p, r, s, ln in found if r == "DEFAULT_SECRET_KEY"}
    assert got == {(".env", 1), (".env", 2), (".env", 3), ("legacy/.env.production", 1), ("mysite/settings.py", 1),
                   ("src/main/resources/application.properties", 1), ("server/app.js", 1), ("server/app.js", 2)}, found
    assert all(s == "HIGH" for p, r, s, _ in found if r == "DEFAULT_SECRET_KEY")
    # config/app.php has env('APP_KEY', 'SomeRandomString'): env lookups are skipped on purpose.


def test_exposed_admin_paths(tmp_path):
    files = {
        "routes/web.php": """<?php
Route::get('/admin', [AdminController::class, 'index']);
Route::get('/test', function () {
    return 'ok';
});
Route::get('/debug', function () {
    return phpinfo();
})->middleware('auth');
Route::prefix('admin')->middleware(['auth', 'can:admin'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});
Route::middleware('auth')->group(function () {
    Route::get('/telescope-proxy', fn () => 1);
    Route::get('/console', [ConsoleController::class, 'index']);
});
Route::get('/testimonials', [PageController::class, 'testimonials']);
""",
        "server/routes.js": "app.use('/admin', adminRouter);\nrouter.get('/api/v1/admin/stats', stats);\napp.use('/backup', requireAdmin, backupRouter);\n",
        "server/secured.js": "app.use(passport.authenticate('jwt'));\napp.use('/admin', adminRouter);\n",
        "src/main/java/demo/AdminController.java": "@RestController\n@RequestMapping(\"/admin\")\npublic class AdminController {}\n",
        "src/main/java/demo/OpsController.java": "@RestController\n@RequestMapping(\"/api/console\")\npublic class OpsController {}\n",
        "src/main/java/demo/Security.java": "class Security { SecurityFilterChain c(HttpSecurity http) { http.authorizeHttpRequests(a -> a.requestMatchers(\"/api/console/**\").hasRole(\"OPS\")); } }\n",
        "src/main/java/demo/GuardedController.java": "@RestController\n@PreAuthorize(\"hasRole('ADMIN')\")\n@RequestMapping(\"/administrator\")\npublic class GuardedController {}\n",
        "tests/routes/web.php": "<?php\nRoute::get('/admin', fn () => 1);\n",
    }
    found = scan(tmp_path, files, "defaults")
    got = {(p, ln, s) for p, r, s, ln in found if r == "EXPOSED_ADMIN_PATH"}
    assert got == {("routes/web.php", 2, "HIGH"), ("routes/web.php", 3, "MEDIUM"), ("server/routes.js", 1, "HIGH"),
                   ("server/routes.js", 2, "HIGH"), ("src/main/java/demo/AdminController.java", 2, "HIGH")}, found


def test_spring_permitall_overrides_any_request_authenticated(tmp_path):
    cfg = ("class Sec { SecurityFilterChain c(HttpSecurity http) { http.authorizeHttpRequests(a -> a\n"
           "  .requestMatchers(\"/admin/**\").permitAll()\n  .anyRequest().authenticated()); } }\n")
    ctrl = "@RestController\n@RequestMapping(\"/admin\")\nclass AdminController {}\n"
    other = "@RestController\n@RequestMapping(\"/console\")\nclass ConsoleController {}\n"
    found = scan(tmp_path, {"src/Sec.java": cfg, "src/AdminController.java": ctrl, "src/ConsoleController.java": other}, "defaults")
    got = {p for p, r, _, _ in found if r == "EXPOSED_ADMIN_PATH"}
    assert got == {"src/AdminController.java"}, found   # /console is covered by anyRequest().authenticated()


def test_sensitive_webroot_folders_and_admin_tools(tmp_path):
    files = {
        "public/backup/site.zip.txt": "x",
        "public/old/index.html": "x",
        "public_html/tmp/a.txt": "x",
        "public/adminer.php": "<?php // adminer\n",
        "phpinfo.php": "<?php phpinfo();\n",
        "public/phpmyadmin/index.php": "<?php\n",
        # negatives
        "public/vendor/lib/test/spec.js": "x",
        "app/test/Helper.php": "<?php\n",
        "public/build/app.js": "x",
        "info.php": "<?php echo 'contact info';\n",
        "storage/backup/db.txt": "x",
    }
    found = scan(tmp_path, files, "defaults")
    dirs = {p for p, r, _, _ in found if r == "SENSITIVE_WEBROOT_PATH"}
    tools = {p for p, r, _, _ in found if r == "EXPOSED_ADMIN_TOOL"}
    assert dirs == {"public/backup", "public/old", "public_html/tmp"}, found
    assert tools == {"public/adminer.php", "phpinfo.php", "public/phpmyadmin/index.php"}, found


def test_open_caches_and_document_stores(tmp_path):
    files = {
        "docker-compose.yml": """services:
  cache:
    image: redis:7
    ports:
      - "6379:6379"
  docs:
    image: mongo:7
    ports:
      - "27017:27017"
  safe-cache:
    image: redis:7
    command: redis-server --requirepass ${REDIS_PASSWORD}
    ports:
      - "6380:6379"
  local-only:
    image: redis:7
    ports:
      - "127.0.0.1:6381:6379"
  internal:
    image: mongo:7
""",
        "deploy/redis.conf": "bind 0.0.0.0\nprotected-mode no\n",
        "deploy/redis-safe.conf": "bind 127.0.0.1\nrequirepass ${REDIS_PASSWORD}\n",
    }
    found = scan(tmp_path, files, "defaults") + scan(tmp_path, {}, "db")
    got = {(p, r, ln) for p, r, _, ln in found if r in ("DB_NO_AUTH", "DB_BIND_ALL")}
    assert ("docker-compose.yml", "DB_NO_AUTH", 3) in got and ("docker-compose.yml", "DB_NO_AUTH", 7) in got
    assert ("deploy/redis.conf", "DB_NO_AUTH", 0) in got and ("deploy/redis.conf", "DB_BIND_ALL", 1) in got
    assert not {x for x in got if x[1] == "DB_NO_AUTH" and x[2] in (11, 16, 20)}, got
    assert not [x for x in got if x[0] == "deploy/redis-safe.conf"], got


# ------------------------------------------------------------------ regressions from the independent review
def test_template_words_are_not_backdoors(tmp_path):
    files = {
        "a.php": "<input name=\"q\" required value=\"<?php echo htmlspecialchars($_GET['q']); ?>\">\n",
        "b.php": "<?php echo \"System status for user \" . htmlspecialchars($_GET[\"id\"]);\n",
        "c.php": "<?php echo \"Evaluation of \" . e($_POST[\"name\"]);\n",
        "d.php": "<p>Please include your order id</p><?= htmlspecialchars($_GET[\"oid\"]) ?>\n",
    }
    assert [f for f in scan(tmp_path, files, "malware") if f[1] == "BACKDOOR_REQUEST_EXEC"] == []


def test_argument_lists_are_high_not_critical(tmp_path):
    files = {"a.py": "subprocess.run(['convert', request.args.get('f')])\n",
             "b.js": "spawn('ls', ['-l', req.query.dir], { shell: false });\n",
             "c.js": "exec(req.query.cmd);\n"}
    sev = {p: s for p, r, s, _ in scan(tmp_path, files, "malware") if r == "BACKDOOR_REQUEST_EXEC"}
    assert sev == {"a.py": "HIGH", "b.js": "HIGH", "c.js": "CRITICAL"}, sev


def test_upload_folder_casing_and_short_echo_tag(tmp_path):
    files = {"Uploads/shell.php": "<?php echo 1;\n", "public/Images/a.php": "<?php echo 1;\n",
             "app/Uploads/UploadService.php": "<?php\nclass UploadService {}\n",
             "pics/a.gif": b"GIF89a<?= `$_GET[c]` ?>",
             "pics/random.png": b"\x89PNG<?=\x00\x01\x02" * 10}
    got = {(p, r) for p, r, _, _ in scan(tmp_path, files, "malware")}
    assert got == {("Uploads/shell.php", "PHP_IN_UPLOAD_DIR"), ("public/Images/a.php", "PHP_IN_UPLOAD_DIR"),
                   ("pics/a.gif", "PHP_IN_IMAGE_FILE")}, got


def test_redaction_of_sql_passwords_salts_and_blobs(tmp_path):
    files = {
        "db/grants.sql": "GRANT ALL ON app.* TO 'app'@'%' IDENTIFIED BY 'S3cr3tPassw0rd!';\n"
                         "CREATE ROLE app WITH LOGIN SUPERUSER PASSWORD 'TopSecret123';\n",
        "config/db.properties": "spring.datasource.url=jdbc:sqlserver://db.prod;user=app;Password='my secret pass';encrypt=false\n",
        "app/token.php": "<?php\n$token = md5($user->email . 'hardcoded-salt-XYZ123');\n",
        "lib/blob.php": "<?php $k = '" + "QUJD" * 300 + "';\n",
    }
    write(tmp_path, files)
    out = G.db_config_scan(str(tmp_path)) + G.code_scan(str(tmp_path)) + G.malware_scan(str(tmp_path))
    assert {f["rule"] for f in out} >= {"DB_GRANT_ALL", "DB_NO_TLS", "TOKEN_FROM_USER_DATA", "SUSPICIOUS_OBFUSCATION"}, out
    text = " ".join(f["code"] + f["message"] for f in out)
    for secret in ("S3cr3tPassw0rd", "TopSecret123", "secret pass", "XYZ123", "QUJD" * 20):
        assert secret not in text, secret


def test_local_infile_has_its_own_rule(tmp_path):
    found = scan(tmp_path, {"deploy/my.cnf": "[mysqld]\nlocal_infile=1\n"}, "db")
    assert [r for _, r, _, _ in found] == ["DB_LOCAL_INFILE"]


def test_linked_app_folder_is_not_walked(tmp_path):
    import _winapi  # Windows junctions need no privilege; elsewhere a symlink would need one
    outside = tmp_path / "outside"
    (outside / "Http").mkdir(parents=True)
    (outside / "Http" / "Limiter.php").write_text("<?php RateLimiter::for('x', fn () => 1);\n", encoding="utf-8")
    proj = tmp_path / "proj"
    (proj / "routes").mkdir(parents=True)
    (proj / "routes" / "web.php").write_text("<?php\nRoute::post('/verify-otp', [OtpController::class, 'verify']);\n", encoding="utf-8")
    _winapi.CreateJunction(str(outside), str(proj / "app"))
    sev = [f["severity"] for f in G.code_scan(str(proj)) if f["rule"] == "AUTH_ROUTE_NO_THROTTLE"]
    assert sev == ["HIGH"], sev


if not hasattr(__import__("os"), "add_dll_directory"):           # not Windows
    test_linked_app_folder_is_not_walked = pytest.mark.skip(reason="junctions are Windows only")(test_linked_app_folder_is_not_walked)


def test_hostile_files_stay_fast_and_capped(tmp_path):
    files = {
        "app/dollar.php": ("a$" * 1999 + "\n") * 200,
        "app/Http/Controllers/FooController.php": "<?php class FooController {\n" + "function a(){$request->input('x');}\n" * 40000 + "}\n",
        "routes/web.php": "<?php\n" + "Route::middleware('web')->group(function(){\n" * 30000 + "Route::post('login',x);\n" * 20000,
        "server/dense.php": ("system(" * 570 + "\n") * 300,
    }
    write(tmp_path, files)
    for fn in (G.code_scan, G.malware_scan, G.default_cred_scan, G.db_config_scan):
        t = time.perf_counter()
        out = fn(str(tmp_path))
        dt = time.perf_counter() - t
        assert dt < 15, (fn.__name__, dt)
        per = {}
        for f in out:
            per[f["file"]] = per.get(f["file"], 0) + 1
        assert max(per.values(), default=0) <= G.MAX_PER_FILE, (fn.__name__, per)


# ------------------------------------------------------------------ ReDoS / timing
def _v7_patterns():
    pats = []
    for rules in G.MALWARE_LINE_RULES.values():
        pats += [rx for _, _, rx in rules]
    pats += list(G.OBF_RULES)
    pats += [rx for rx, *_ in G.PHP_DEPRECATED_SYNTAX] + [G.PHP_DEPRECATED_RX, G.PLACEHOLDER_PHP]
    for name in dir(G):
        v = getattr(G, name)
        if name.startswith(("_DB_", "_COL_", "_DEBUG", "_ASSIGN", "_WEAK", "_USER", "_CSPRNG", "_SHORT", "_INPUT", "_VALID",
                            "_FORM", "_METHOD", "_EXPRESS", "_AUTH", "_CODE_PATH", "_LARAVEL", "_LIMITER", "_DENY", "_ATTACK",
                            "_PY_IN", "_LOCAL", "_LOGLEVEL", "PUBLIC_ENV", "SOURCEMAP_CFG", "_NAME_WORDS", "_REDACT", "_KV", "_PLACEHOLDER", "_HASHED",
                            "_SUPERUSER", "_SA_EMPTY", "_URL_CRED", "_JWT_LITERAL", "_SESSION_SECRET", "_LARAVEL_ANY",
                            "_EXPRESS_ANY", "_SPRING", "_REDIS_IMAGE")) and isinstance(v, re.Pattern):
            pats.append(v)
    return pats


EVIL = [
    "a" * 100_000,
    "A" * 999 + "!" + ("A" * 999 + "!") * 100,
    "$_GET[" * 20_000,
    "eval(" * 20_000,
    "eval(" + " " * 50_000,
    "(" * 50_000,
    "\\x4" * 30_000,
    "chr(1)." * 15_000,
    "String.fromCharCode(" + "1," * 40_000,
    "token" * 20_000 + "=",
    "'" * 50_000,
    "function f(" + "Foo $x, " * 5_000,
    "preg_replace('/" + "/" * 50_000,
    "mysql_" * 20_000,
    '"' + "${" * 30_000,
    "Route::post('" + "login" * 20_000,
    "GRANT " * 20_000,
    "host all all " * 10_000,
    "-" * 50_000 + "e",
]


def test_patterns_are_linear():
    # Line rules only ever see lines up to CODE_LINE_MAX (4000) characters, so they are tested at five
    # times that. The encoded-blob rules see up to BLOB_LINE_MAX characters and get the full inputs.
    assert G.CODE_LINE_MAX == 4000
    pats = _v7_patterns()
    assert len(pats) > 60
    for rx in pats:
        cap = None if rx in G.OBF_RULES else 5 * G.CODE_LINE_MAX
        for s in EVIL:
            s = s[:cap] if cap else s
            t = time.perf_counter()
            rx.search(s)
            dt = time.perf_counter() - t
            assert dt < 0.5, (rx.pattern[:80], s[:30], dt)


def test_scanners_finish_fast_on_hostile_files(tmp_path):
    files = {f"evil{i}.php": s + "\n" for i, s in enumerate(EVIL)}
    files.update({f"evil{i}.js": s + "\n" for i, s in enumerate(EVIL)})
    files["routes/web.php"] = "<?php\n" + "Route::post('/login', fn () => 1);\n" * 2000
    t = time.perf_counter()
    scan(tmp_path, files, "all")
    assert time.perf_counter() - t < 30

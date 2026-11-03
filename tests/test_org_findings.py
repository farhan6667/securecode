"""Checks tuned to the repeat findings in the org's own pentest reports (2025-2026)."""
import json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECGATE = ROOT / "scripts" / "secgate.py"
STOP = ROOT / "scripts" / "stop_gate.py"


def scan(d):
    p = subprocess.run([sys.executable, "-I", str(SECGATE), ".", "--mode", "quick", "--fail-on", "high"], cwd=d,
                       text=True, capture_output=True, timeout=120, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout


def write(d, rel, text):
    f = Path(d, rel); f.parent.mkdir(parents=True, exist_ok=True); f.write_text(text, encoding="utf-8"); return f


def test_report_libraries_are_flagged_and_current_ones_are_not():
    with tempfile.TemporaryDirectory() as d:
        write(d, "public/js/jquery.validate.js", "/*!\n * jQuery Validation Plugin v1.14.0\n */\n")
        write(d, "public/js/jquery.dataTables.js", "/*! DataTables 1.10.19\n */\n")
        write(d, "public/js/highcharts.js", "/*\n Highcharts JS v7.1.2 (2019-06-03)\n*/\n")
        write(d, "public/js/tinymce.min.js", "// TinyMCE version 4.7.11 (2018-04-11)\n")
        write(d, "public/revslider/TweenMax.min.js", "/*!\n * VERSION: 1.18.0\n * DATE: 2015-09-05\n * TweenMax\n */\n")
        write(d, "public/js/moment.js", "//! moment.js\n//! version : 2.24.0\n")
        write(d, "public/js/bootstrap-tagsinput.js", "/* bootstrap-tagsinput v0.6.1 */\n")
        write(d, "resources/views/app.blade.php",
              '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">\n'
              '<script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>\n'
              '<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha384-x" crossorigin="anonymous"></script>\n'
              '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" integrity="sha384-y">\n'
              '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">\n')
        rc, out = scan(d)
        assert rc == 2, out
        for lib in ("jquery-validation 1.14.0", "datatables 1.10.19", "highcharts 7.1.2", "tinymce 4.7.11", "gsap 1.18.0",
                    "moment 2.24.0", "bootstrap-tagsinput 0.6.1", "bootstrap 4.6.0", "jquery 2.2.4"):
            assert lib in out, (lib, out)
        assert "3.7.1" not in out and "5.3.3" not in out
        assert "CDN_WITHOUT_SRI" in out and "fonts.googleapis" not in out


def test_production_config_findings():
    with tempfile.TemporaryDirectory() as d:
        write(d, "public/app.js.map", "{}")
        write(d, "public/.git/config", "[core]")
        write(d, "public/backup.sql", "--")
        write(d, "routes/web.php", "Route::get('/users/{id}/delete', [UserController::class, 'destroy']);\nRoute::get('/users', 'x');\n")
        write(d, "config/session.php", "<?php return ['secure' => false, 'http_only' => true];\n")
        write(d, "database/seeders/AdminSeeder.php", "User::create(['email' => 'admin@admin.com', 'password' => Hash::make('12345678')]);\n")
        write(d, "public/.htaccess", "Options +Indexes\n")
        write(d, "deploy/nginx.conf", "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n")
        write(d, "composer.json", json.dumps({"require": {"php": "^7.4", "laravel/framework": "^8.75"}}))
        write(d, "resources/views/welcome.blade.php", "<h1>hi</h1>\n")
        write(d, "app/Payments.php", "<?php $k = 'sk_live_" + "a" * 24 + "';\n")
        rc, out = scan(d)
        assert rc == 2, out
        for rule in ("WEBROOT_EXPOSURE", "STATE_CHANGE_OVER_GET", "INSECURE_COOKIE_FLAG", "WEAK_DEFAULT_CREDENTIAL",
                     "DIRECTORY_LISTING", "OLD_TLS_PROTOCOL", "UNSUPPORTED_PLATFORM", "MISSING_SECURITY_HEADERS", "LIVE_API_KEY"):
            assert rule in out, (rule, out)
        assert out.count("STATE_CHANGE_OVER_GET") == 1
        assert "sk_live_aaaa" not in out  # the key itself is redacted in the report


def test_android_manifest_findings():
    with tempfile.TemporaryDirectory() as d:
        write(d, "app/src/main/AndroidManifest.xml",
              '<manifest><application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true">\n'
              '<activity android:name=".Main" android:exported="true"><intent-filter>'
              '<action android:name="android.intent.action.MAIN"/></intent-filter></activity>\n'
              '<activity android:name=".PayWebView" android:exported="true"/>\n'
              '<service android:name=".Sync" android:exported="true" android:permission="com.x.SYNC"/>\n'
              '</application></manifest>\n')
        rc, out = scan(d)
        for rule in ("ANDROID_DEBUGGABLE", "ANDROID_CLEARTEXT", "ANDROID_BACKUP"):
            assert rule in out, (rule, out)
        assert out.count("ANDROID_EXPORTED_COMPONENT") == 1, out  # launcher and permission-protected ones are fine


def test_secure_project_passes():
    with tempfile.TemporaryDirectory() as d:
        write(d, "app/Http/Middleware/SecurityHeaders.php",
              "<?php $r->headers->set('Content-Security-Policy', \"default-src 'self'\"); $r->headers->set('X-Frame-Options', 'DENY');\n")
        write(d, "routes/web.php", "Route::delete('/users/{id}', [UserController::class, 'destroy']);\n")
        write(d, "config/session.php", "<?php return ['secure' => env('SESSION_SECURE_COOKIE', true), 'http_only' => true];\n")
        write(d, "composer.json", json.dumps({"require": {"php": "^8.3", "laravel/framework": "^12.0"}}))
        write(d, "resources/views/welcome.blade.php", "<h1>{{ $title }}</h1>\n")
        rc, out = scan(d)
        assert rc == 0 and "RESULT: PASS" in out, out


def test_stop_gate_sends_agent_back_once():
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        write(d, "app.py", "import os\nfrom flask import request\nos.system(request.args['c'])\n")
        ev = {"cwd": d, "stop_hook_active": False}
        p = subprocess.run([sys.executable, str(STOP)], input=json.dumps(ev), text=True, capture_output=True, timeout=60)
        assert p.returncode == 0 and '"decision": "block"' in p.stdout and "COMMAND_INJECTION" in p.stdout, p.stdout + p.stderr
        ev["stop_hook_active"] = True  # second stop in a row: never trap the session
        p = subprocess.run([sys.executable, str(STOP)], input=json.dumps(ev), text=True, capture_output=True, timeout=60)
        assert p.returncode == 0 and p.stdout.strip() == ""
        write(d, "app.py", "print('ok')\n")
        ev["stop_hook_active"] = False
        p = subprocess.run([sys.executable, str(STOP)], input=json.dumps(ev), text=True, capture_output=True, timeout=60)
        assert p.stdout.strip() == ""

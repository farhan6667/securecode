"""Secret shield (7.0): output-side withholding hook and the transcript sweep.

Every fake credential here is built at run time from pieces, so the source file holds no secret-shaped string
for gitleaks or the gate to find. Nothing here reads the real ~/.claude folder: the sweep runs on fixtures and
CLAUDE_CONFIG_DIR points at a temp folder."""
import base64, importlib.util, io, json, os, random, string, subprocess, sys, tempfile, time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHIELD = ROOT / "scripts" / "secret_shield.py"


def load():
    spec = importlib.util.spec_from_file_location("secret_shield_t", SHIELD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


S = load()
RND = random.Random(20261103)
ALNUM = string.ascii_letters + string.digits
UPNUM = string.ascii_uppercase + string.digits


def rnd(n, alphabet=ALNUM):
    return "".join(RND.choice(alphabet) for _ in range(n))


def j(*parts):
    return "".join(parts)


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


# One live-looking value per pattern: (type, text that holds it, the secret value itself).
def samples():
    aws_id = j("AK", "IA", rnd(16, UPNUM))
    aws_secret = rnd(40, ALNUM + "/+")
    gh = j("gh", "p_", rnd(36))
    ghf = j("github", "_pat_", rnd(82, ALNUM + "_"))
    gl = j("gl", "pat-", rnd(20))
    sl = j("xo", "xb-", rnd(12, string.digits), "-", rnd(24))
    hook = j("T", rnd(8, UPNUM), "/B", rnd(8, UPNUM), "/", rnd(24))
    st = j("sk", "_live_", rnd(24))
    gk = j("AI", "za", rnd(35, ALNUM + "_-"))
    an = j("sk-", "ant-", "api03-", rnd(90, ALNUM + "_-"))
    oa = j("sk-", "proj-", rnd(60, ALNUM + "_-"))
    npm = j("np", "m_", rnd(36))
    pypi = j("py", "pi-", "AgEIcHlwaS5vcmc", rnd(60, ALNUM + "_-"))
    az = rnd(86, ALNUM + "+/") + "=="
    jwt = ".".join([b64url({"alg": "HS256", "typ": "JWT"}), b64url({"sub": rnd(12), "role": "admin", "exp": 1999999999}),
                    rnd(43, ALNUM + "_-")])
    dbpw = rnd(20)
    urlpw = rnd(18)
    gen = rnd(28, ALNUM + "+/")
    body = "\n".join(rnd(64, ALNUM + "+/") for _ in range(6))
    pk = j("-----BEGIN ", "RSA PRIVATE", " KEY-----\n", body, "\n-----END ", "RSA PRIVATE", " KEY-----")
    return [
        ("aws-access-key-id", f"export AWS_ACCESS_KEY_ID={aws_id}\n", aws_id),
        ("aws-secret-access-key", f"aws_secret_access_key = {aws_secret}\n", aws_secret),
        ("github-token", f"remote: https://x-access:{gh}@github.com\nGH={gh}", gh),
        ("github-fine-grained-token", f"token {ghf}", ghf),
        ("gitlab-token", f"PRIVATE-TOKEN: {gl}", gl),
        ("slack-token", f"SLACK_BOT={sl}", sl),
        ("slack-webhook", j("url = https://hooks.slack", ".com/services/", hook), hook),
        ("stripe-key", f"Stripe.api_key = '{st}'", st),
        ("google-api-key", f"maps?key={gk}&v=3", gk),
        ("anthropic-key", f"ANTHROPIC={an}", an),
        ("openai-key", f"OPENAI={oa}", oa),
        ("npm-token", f"//registry.npmjs.org/:_authToken={npm}", npm),
        ("pypi-token", f"password = {pypi}", pypi),
        ("azure-storage-key", f"DefaultEndpointsProtocol=https;AccountName=x;AccountKey={az};EndpointSuffix=core", az),
        ("jwt", f"Authorization: Bearer {jwt}", jwt),
        ("db-url-password", j("DATABASE_URL=postgres", "ql://app:", dbpw, "@db.internal:5432/main"), dbpw),
        ("url-password", j("fetch https", "://deploy:", urlpw, "@files.example.org/x"), urlpw),
        ("secret-assignment", f'client_secret: "{gen}"', gen),
        ("private-key", f"$ cat id_rsa\n{pk}\n$", body),
    ]


SAMPLES = samples()


@pytest.mark.parametrize("kind,text,value", SAMPLES, ids=[s[0] for s in SAMPLES])
def test_every_pattern_finds_and_redacts(kind, text, value):
    found = [m for m in S.find_secrets(text) if not m.example]
    assert found, kind
    assert kind in {m.kind for m in found} or (kind == "pypi-token" and found), [m.kind for m in found]
    red, live = S.redact_text(text)
    assert live
    for piece in {value, value[: len(value) // 2], value[len(value) // 2:]}:
        if len(piece) >= 10:
            assert piece not in red, kind
    assert "[REDACTED by secret shield:" in red


NEGATIVES = [
    ("doc AWS key", j("AWS_ACCESS_KEY_ID=AK", "IAIOSFODNN7", "EXAMPLE")),
    ("doc AWS secret", j("aws_secret", "_access_key = ", "wJalrXUtn", "FEMI/K7MD", "ENG/bPxRfiCY", "EXAMPLEKEY")),
    ("repeated char token", j("gh", "p_", "x" * 36)),
    ("placeholder assignment", j("pass", 'word = "', "your_password_here_123", '"')),
    ("env reference", "DB_PASSWORD=${DB_PASSWORD}\napi_key = process.env.API_KEY_VALUE"),
    ("dotted config path", "api_key = settings.services.maps_api_key"),
    ("plain word", "the token: abcdefghijklmnopqrstu"),
    ("short value", "password: Summer2024"),
    ("db url placeholder", j("postgres", "://user:", "password", "@localhost/db")),
    ("db url reference", j("mysql", "://root:", "${DB_PASS}", "@db/app")),
    ("private key header only", j("match lines like -----BEGIN ", "PRIVATE", " KEY----- in logs")),
    ("f-string placeholder in url", j('f"remote: https', '://x-access:{gh_value}@github.com"')),
    ("json newline escape", j('{"content": "DB_PASS', 'WORD=\\nDB_USER', 'NAME=app_user_name_x"}')),
    ("laravel validation rule", j("'pass", "word' => 'required|min:12|confirmed'")),
    ("prose", "Rotate every secret and token after an incident; passwords must be at least 12 characters."),
]


@pytest.mark.parametrize("name,text", NEGATIVES, ids=[n for n, _ in NEGATIVES])
def test_examples_and_placeholders_are_not_withheld(name, text):
    red, live = S.redact_text(text)
    assert not live, (name, [(m.kind, m.example) for m in S.find_secrets(text)])
    assert red == text


def test_doc_examples_are_reported_low_when_asked():
    key = j("AK", "IAIOSFODNN7", "EXAMPLE")
    ms = S.find_secrets(f"id={key}")
    assert ms and all(m.example and m.severity == "low" for m in ms)


def test_jwt_io_sample_is_an_example():
    sample = ".".join([b64url({"alg": "HS256", "typ": "JWT"}),
                       b64url({"sub": "1234567890", "name": "John Doe", "iat": 1516239022}), rnd(43, ALNUM + "_-")])
    ms = S.find_secrets(sample)
    assert ms and all(m.example for m in ms)


def run_hook(event, cwd=None, env=None):
    e = dict(os.environ)
    e.pop("CLAUDE_PROJECT_DIR", None)
    e.update(env or {})
    data = event if isinstance(event, (str, bytes)) else json.dumps(event)
    p = subprocess.run([sys.executable, "-I", str(SHIELD)], input=data if isinstance(data, bytes) else data.encode(),
                       capture_output=True, timeout=60, cwd=cwd, env=e)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def test_bash_output_is_replaced_in_the_same_shape_and_audited():
    pw = rnd(22)
    with tempfile.TemporaryDirectory() as d:
        resp = {"stdout": j("APP_ENV=prod\nDATABASE_URL=postgres", "ql://app:", pw, "@db:5432/x\n"), "stderr": "",
                "interrupted": False, "isImage": False}
        ev = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": d,
              "tool_input": {"command": "cat config/app.env"}, "tool_response": resp}
        rc, out, err = run_hook(ev, cwd=d)
        assert rc == 0 and "Traceback" not in err
        assert pw not in out
        ans = json.loads(out)
        assert ans["decision"] == "block"
        assert "db-url-password" in ans["reason"] and "cat config/app.env" in ans["reason"]
        assert "ask" in ans["reason"].lower() and "stop" in ans["reason"].lower()
        new = ans["hookSpecificOutput"]["updatedToolOutput"]
        assert ans["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert set(new) == set(resp) and new["interrupted"] is False and new["isImage"] is False
        assert "APP_ENV=prod" in new["stdout"] and "[REDACTED by secret shield: db-url-password]" in new["stdout"]
        audit = Path(d, ".security", "shield-audit.jsonl").read_text(encoding="utf-8")
        assert pw not in audit
        line = json.loads(audit.splitlines()[-1])
        assert line["action"] == "withheld" and line["types"] == ["db-url-password"] and line["count"] == 1


def test_read_output_keeps_numbers_and_names_the_file():
    gh = j("gh", "p_", rnd(36))
    with tempfile.TemporaryDirectory() as d:
        resp = {"type": "text", "file": {"filePath": f"{d}/config.php", "content": f"<?php\n$token = '{gh}';\n",
                                         "numLines": 2, "startLine": 1, "totalLines": 2}}
        ev = {"tool_name": "Read", "cwd": d, "tool_input": {"file_path": f"{d}/config.php"}, "tool_response": resp}
        rc, out, _ = run_hook(ev, cwd=d)
        assert rc == 0 and gh not in out and gh[4:20] not in out
        ans = json.loads(out)
        new = ans["hookSpecificOutput"]["updatedToolOutput"]
        assert new["file"]["numLines"] == 2 and new["type"] == "text"
        assert "config.php" in ans["reason"] and "github-token" in ans["reason"]


def test_mcp_content_blocks_and_plain_strings():
    key = j("sk", "_live_", rnd(30))
    with tempfile.TemporaryDirectory() as d:
        ev = {"tool_name": "mcp__db__query", "cwd": d, "tool_input": {"sql": "select * from settings"},
              "tool_response": [{"type": "text", "text": f"stripe={key}"}]}
        rc, out, _ = run_hook(ev, cwd=d)
        assert rc == 0 and key not in out
        assert json.loads(out)["hookSpecificOutput"]["updatedToolOutput"][0]["type"] == "text"
        ev["tool_response"] = f"value {key}"
        rc, out, _ = run_hook(ev, cwd=d)
        assert key not in out and isinstance(json.loads(out)["hookSpecificOutput"]["updatedToolOutput"], str)


def test_clean_output_says_nothing():
    with tempfile.TemporaryDirectory() as d:
        ev = {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "ls"},
              "tool_response": {"stdout": "README.md\nsrc\n", "stderr": "", "interrupted": False, "isImage": False}}
        rc, out, err = run_hook(ev, cwd=d)
        assert rc == 0 and out.strip() == "" and err.strip() == ""
        assert not Path(d, ".security").exists()


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"null", b'"x"', b"{}", b'{"tool_response": null}',
                                 b'{"tool_name": 5, "tool_input": [], "tool_response": {"stdout": 7}}',
                                 b"\xff\xfe\x00garbage", b"[" * 200000 + b"]" * 200000], ids=lambda r: f"len{len(r)}")
def test_malformed_input_never_crashes_or_hangs(raw):
    t = time.monotonic()
    rc, out, err = run_hook(raw)
    assert rc == 0 and "Traceback" not in err
    assert time.monotonic() - t < 20


def test_images_and_binary_payloads_pass_through_untouched():
    blob = "iVBORw0KGgo" + rnd(3_000_000, ALNUM + "+/")          # bigger than the scan budget
    read_img = {"type": "image", "file": {"base64": blob, "type": "image/png", "originalSize": 123}}
    assert S.handle({"tool_name": "Read", "tool_response": read_img}) is None
    mcp_img = [{"type": "image", "data": blob, "mimeType": "image/png"}, {"type": "text", "text": "ok"}]
    assert S.handle({"tool_name": "mcp__x__shot", "tool_response": mcp_img}) is None
    bash_img = {"stdout": blob, "stderr": "", "interrupted": False, "isImage": True}
    assert S.handle({"tool_name": "Bash", "tool_response": bash_img}) is None
    gh = j("gh", "p_", rnd(36))
    mixed = [{"type": "image", "data": blob, "mimeType": "image/png"}, {"type": "text", "text": f"t={gh}"}]
    ans = S.handle({"tool_name": "mcp__x__shot", "tool_response": mixed})
    new = ans["hookSpecificOutput"]["updatedToolOutput"]
    assert new[0]["data"] == blob and gh not in new[1]["text"]


def test_secret_in_the_command_itself_is_not_echoed_in_the_reason():
    gh = j("gh", "p_", rnd(36))
    ev = {"tool_name": "Bash", "tool_input": {"command": f"curl -H 'Authorization: token {gh}' api"},
          "tool_response": {"stdout": f"echo {gh}", "stderr": "", "interrupted": False, "isImage": False}}
    ans = S.handle(ev)
    assert ans and gh not in json.dumps(ans)


def test_deep_nesting_is_withheld_not_walked():
    gh = j("gh", "p_", rnd(36))
    x = {"text": gh}
    for _ in range(200):
        x = {"n": x}
    ans = S.handle({"tool_name": "mcp__x__y", "tool_response": x})
    assert ans and gh not in json.dumps(ans)


def test_huge_output_is_fast_and_the_unscanned_tail_is_withheld():
    tail_key = j("AK", "IA", rnd(16, UPNUM))
    early = j("gh", "p_", rnd(36))
    filler = ("2026-11-03 INFO request served in 12ms path=/api/items?id=42 user=alice\n" * 30000)[: S.SCAN_MAX - 200]
    out = f"{early}\n{filler}{'x' * 1000}{tail_key}\n"
    t = time.monotonic()
    ans = S.handle({"tool_name": "Bash", "tool_response": {"stdout": out, "stderr": "", "interrupted": False, "isImage": False}})
    took = time.monotonic() - t
    assert took < 8, took
    s = json.dumps(ans)
    assert early not in s and tail_key not in s
    assert "withheld" in ans["reason"]


@pytest.mark.parametrize("bomb", ["a" * 1_500_000, j("pass", "word=") * 150_000, "eyJ" * 400_000, "eyJaaaaaaaa." * 100_000,
                                  j("-----BEGIN ", "PRIVATE", " KEY-----") * 40_000, "postgres://a:" * 100_000,
                                  "x" * 40 + "=" * 1_000_000, "AKIA" * 300_000, "secret" * 200_000 + ":" + "Ab1" * 100],
                         ids=lambda b: f"{b[:12]!r}x{len(b)}")
def test_regex_bombs_stay_within_budget(bomb):
    t = time.monotonic()
    S.handle({"tool_name": "Bash", "tool_response": {"stdout": bomb, "stderr": "", "interrupted": False, "isImage": False}})
    assert time.monotonic() - t < 10


def test_deadline_fails_closed_for_what_was_not_scanned():
    gh = j("gh", "p_", rnd(36))
    ans = S.handle({"tool_name": "Bash", "tool_response": {"stdout": f"x {gh}", "stderr": "", "interrupted": False,
                                                           "isImage": False}}, deadline_s=-1)
    assert ans and gh not in json.dumps(ans) and "withheld" in ans["reason"]


def test_internal_error_fails_open_with_a_warning(monkeypatch, capsys):
    def boom(event, *a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(S, "handle", boom)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(
        {"tool_name": "Read", "tool_input": {"file_path": "/x/app.cfg"}, "tool_response": {"a": "b"}}).encode())))
    assert S.hook_main() == 0
    msg = json.loads(capsys.readouterr().out)
    assert "could not check" in msg["hookSpecificOutput"]["additionalContext"]
    assert "updatedToolOutput" not in msg["hookSpecificOutput"]


def test_redaction_never_leaks_in_any_context():
    contexts = ['{}', '"{}"', "'{}'", "key={}", "Bearer {}", "{}\\n", "<td>{}</td>", '{{"k": "{}"}}', "url?x={}&y=1"]
    for kind, text, value in SAMPLES:
        if kind in ("private-key", "secret-assignment", "aws-secret-access-key", "db-url-password", "url-password",
                    "slack-webhook", "azure-storage-key"):
            continue        # these need their surrounding key or URL; covered by the parametrized test
        for c in contexts:
            red, _ = S.redact_text(c.format(value))
            assert value not in red, (kind, c)
    # JSON-escaped, as in a transcript line
    for kind, text, value in SAMPLES:
        enc = json.dumps({"content": text})
        red, _ = S.redact_text(enc)
        assert value not in red and value.replace("\n", "\\n") not in red, kind


def test_audit_refuses_a_link(tmp_path):
    proj = tmp_path / "p"
    (proj).mkdir()
    target = tmp_path / "elsewhere"
    target.mkdir()
    try:
        os.symlink(target, proj / ".security", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("no symlink permission")
    assert S.audit({"cwd": str(proj), "tool_name": "Bash"}, "withheld", []) is False
    assert not any(target.iterdir())


def write_transcript(folder, lines):
    folder.mkdir(parents=True, exist_ok=True)
    f = folder / "session-1.jsonl"
    f.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    return f


def test_sweep_reports_masked_with_revocation_steps(tmp_path):
    aws = j("AK", "IA", rnd(16, UPNUM))
    gh = j("gh", "p_", rnd(36))
    write_transcript(tmp_path / "projects" / "C--x", [
        {"type": "user", "message": {"content": "hello"}},
        {"type": "tool_result", "content": f"AWS_ACCESS_KEY_ID={aws}\nother"},
        {"type": "tool_result", "content": f"GH={gh}"},
        {"type": "tool_result", "content": f"again {gh}"},
    ])
    (tmp_path / "app.log").write_text("ok\n", encoding="utf-8")
    p = subprocess.run([sys.executable, "-I", str(SHIELD), "sweep", str(tmp_path)], capture_output=True, timeout=60)
    out = p.stdout.decode("utf-8", "replace")
    assert p.returncode == 1, out
    assert aws not in out and gh not in out and aws[4:] not in out and gh[4:] not in out
    assert "aws-access-key-id" in out and "github-token" in out
    assert "session-1.jsonl:2" in out and "session-1.jsonl:3" in out
    assert out.count("github-token ") == 1              # the repeat on line 4 is folded into the first
    assert "IAM" in out and "Personal access tokens" in out
    pj = subprocess.run([sys.executable, "-I", str(SHIELD), "sweep", "--json", str(tmp_path)], capture_output=True, timeout=60)
    data = json.loads(pj.stdout)
    assert {f["type"] for f in data["findings"]} == {"aws-access-key-id", "github-token"}
    assert aws not in pj.stdout.decode() and gh not in pj.stdout.decode()


def test_sweep_clean_and_example_only_pass(tmp_path):
    write_transcript(tmp_path / "t", [{"content": j("doc key AK", "IAIOSFODNN7", "EXAMPLE")}, {"content": "nothing"}])
    p = subprocess.run([sys.executable, "-I", str(SHIELD), "sweep", str(tmp_path)], capture_output=True, timeout=60)
    assert p.returncode == 0, p.stdout
    p = subprocess.run([sys.executable, "-I", str(SHIELD), "sweep", "--include-examples", str(tmp_path)],
                       capture_output=True, timeout=60)
    assert p.returncode == 0 and b"[LOW]" in p.stdout


def test_sweep_default_targets_use_the_configured_folder_only(tmp_path, monkeypatch):
    cfg = tmp_path / "cfg"
    (cfg / "projects").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    proj = tmp_path / "proj"
    (proj / "logs").mkdir(parents=True)
    (proj / "server.log").write_text("x\n")
    t = S.default_targets(str(proj))
    assert t[0] == str(cfg / "projects") and str(proj / "logs") in t and str(proj / "server.log") in t
    assert not any(str(Path.home() / ".claude") in x for x in t)


def test_sweep_skips_links_and_handles_long_lines(tmp_path):
    gh = j("gh", "p_", rnd(36))
    f = tmp_path / "big.log"
    f.write_text("a" * (S.LINE_CHUNK + 100) + f" {gh}\nnext\n", encoding="utf-8")
    hits = S.sweep([str(tmp_path)])
    assert any(h["type"] == "github-token" and h["line"] == 1 for h in hits)
    assert all(gh not in json.dumps(h) for h in hits)


def test_shield_is_registered_identically_in_all_installers():
    import re
    g = (ROOT / "install-global.py").read_text(encoding="utf-8")
    m = re.search(r'SHIELD_MATCHER="([^"]+)"', g)
    assert m and "put_hook(hooks,\"PostToolUse\",SHIELD_MATCHER" in g
    assert "G.SHIELD_MATCHER" in (ROOT / "install-managed.py").read_text(encoding="utf-8")
    ex = json.loads((ROOT / "enterprise-managed-settings.example.json").read_text(encoding="utf-8"))
    post = [h["matcher"] for h in ex["hooks"]["PostToolUse"] if any("secret_shield" in x["command"] for x in h["hooks"])]
    assert post == [m.group(1)]
    for tool in ("Bash", "Read", "Grep", "WebFetch", "PowerShell"):
        assert tool in m.group(1).split("|")
    assert "mcp__.*" in m.group(1)

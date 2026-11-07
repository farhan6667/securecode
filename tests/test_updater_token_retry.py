"""7.1 updater: a public repo needs no token, so a 401, 403 (not a rate limit) or 404 that came with a token is retried once
without it. A gh login for another account, an expired token or an SSO rule used to stop the check with HTTP 404 on a public
repository. A rate limit still backs off, and a private repository still fails visibly."""
import io
import json
import sys
import time
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_update_mechanism import CFG, http_error, load, make_app  # noqa: E402


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def release(tag="v6.2.0", assets=()):
    return Resp(json.dumps({"tag_name": tag, "assets": list(assets)}).encode())


def build(tmp_path, monkeypatch, name, api_impl):
    app = make_app(tmp_path)
    upd = load(app / "scripts" / "updater.py", name)
    calls = []

    def fake_api(url, tok, accept="x"):
        calls.append(tok)
        return api_impl(tok)
    monkeypatch.setattr(upd, "api", fake_api)
    return upd, calls


@pytest.mark.parametrize("code", [401, 403, 404])
def test_a_token_that_gets_a_refusal_is_retried_without_it(tmp_path, monkeypatch, code):
    def impl(tok):
        if tok:
            raise http_error(code, {})
        return release()
    upd, calls = build(tmp_path, monkeypatch, f"upd_retry_{code}", impl)
    assert upd.check_and_update(CFG, "ghp_not_a_real_token_for_the_test") == "up-to-date"
    assert calls == ["ghp_not_a_real_token_for_the_test", None]


def test_a_rate_limit_is_not_retried_without_the_token(tmp_path, monkeypatch):
    reset = int(time.time()) + 600

    def impl(tok):
        raise http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)})
    upd, calls = build(tmp_path, monkeypatch, "upd_retry_rl", impl)
    with pytest.raises(upd.RateLimited):
        upd.check_and_update(CFG, "tok")
    assert calls == ["tok"]


def test_a_private_repo_fails_visibly_after_exactly_one_retry(tmp_path, monkeypatch):
    def impl(tok):
        raise http_error(404, {})
    upd, calls = build(tmp_path, monkeypatch, "upd_retry_private", impl)
    with pytest.raises(urllib.error.HTTPError) as e:
        upd.check_and_update(CFG, "tok")
    assert e.value.code == 404 and calls == ["tok", None]


def test_no_token_means_no_retry(tmp_path, monkeypatch):
    def impl(tok):
        raise http_error(404, {})
    upd, calls = build(tmp_path, monkeypatch, "upd_retry_none", impl)
    with pytest.raises(urllib.error.HTTPError):
        upd.check_and_update(CFG, None)
    assert calls == [None]


def test_other_errors_are_not_retried(tmp_path, monkeypatch):
    for code in (400, 500, 502):
        def impl(tok, code=code):
            raise http_error(code, {})
        upd, calls = build(tmp_path / f"c{code}", monkeypatch, f"upd_retry_other_{code}", impl)
        with pytest.raises(urllib.error.HTTPError):
            upd.check_and_update(CFG, "tok")
        assert calls == ["tok"], code


def test_an_asset_download_that_the_token_cannot_reach_is_retried_without_it(tmp_path, monkeypatch):
    assets = [{"name": CFG["asset"], "url": "https://api.github.com/repos/x/y/releases/assets/1", "size": 3},
              {"name": CFG["asset"] + ".sig", "url": "https://api.github.com/repos/x/y/releases/assets/2", "size": 3}]
    app = make_app(tmp_path)
    upd = load(app / "scripts" / "updater.py", "upd_retry_dl")
    toks = []

    def fake_download(url, tok, dest):
        toks.append(tok)
        if tok:
            raise http_error(404, {})
        Path(dest).write_bytes(b"abc")
    monkeypatch.setattr(upd, "api", lambda url, tok, accept="x": release("v9.9.9", assets))
    monkeypatch.setattr(upd, "download", fake_download)
    monkeypatch.setattr(upd, "verify_signature", lambda *a, **k: False)    # stop after the downloads
    assert upd.check_and_update(CFG, "tok", workdir=tmp_path / "w") == "SIGNATURE-INVALID"
    # the first asset: token tried, then none; the second asset is then fetched without a token straight away
    assert toks == ["tok", None, None], toks


def test_the_token_is_never_sent_to_a_host_that_is_not_github(tmp_path):
    upd = load(make_app(tmp_path) / "scripts" / "updater.py", "upd_retry_host")
    with pytest.raises(RuntimeError):
        upd.api("https://evil.example/repos/x/y/releases/latest", "tok")
    with pytest.raises(RuntimeError):
        upd.download("http://api.github.com/x", "tok", tmp_path / "f")

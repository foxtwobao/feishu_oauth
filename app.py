import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from flask import Flask, redirect, request

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("feishu_oauth")

app = Flask(__name__)

FEISHU_AUTH_URL = "https://passport.feishu.cn/suite/passport/oauth/authorize"
FEISHU_TOKEN_URL = "https://passport.feishu.cn/suite/passport/oauth/token"
FEISHU_USERINFO_URL = "https://passport.feishu.cn/suite/passport/oauth/userinfo"


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name, default)
    if value is None or value.strip() == "":
        return None
    return value.strip()

CONFIG_PATH = _env("CONFIG_PATH", "./config.yaml") or "./config.yaml"


def _load_simple_yaml(path: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    try:
        raw = Path(path).read_text().splitlines()
    except Exception:
        return data
    for line in raw:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        data[key] = value
    return data


_config = _load_simple_yaml(CONFIG_PATH)


def _cfg(key: str) -> Optional[str]:
    value = _config.get(key)
    if value is None or value.strip() == "":
        return None
    return value.strip()


APP_ID = _env("FEISHU_APP_ID") or _cfg("feishu_app_id")
APP_SECRET = _env("FEISHU_APP_SECRET") or _cfg("feishu_app_secret")
REDIRECT_URI = _env("FEISHU_REDIRECT_URI") or _cfg("feishu_redirect_uri")
WEBHOOK_URL = _env("WEBHOOK_URL") or _cfg("webhook_url")
STATE_SECRET = _env("STATE_SECRET") or _cfg("state_secret") or secrets.token_urlsafe(32)
STATE_TTL_SECONDS = int(_env("STATE_TTL_SECONDS") or _cfg("state_ttl_seconds") or "600")
STORAGE_PATH = Path(_env("STORAGE_PATH") or _cfg("storage_path") or "./data/oauth_tokens.json")


def _require_config() -> Optional[str]:
    missing = []
    if not APP_ID:
        missing.append("FEISHU_APP_ID")
    if not APP_SECRET:
        missing.append("FEISHU_APP_SECRET")
    if not REDIRECT_URI:
        missing.append("FEISHU_REDIRECT_URI")
    if missing:
        return "Missing required env: " + ", ".join(missing)
    return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sign_state(payload: str) -> str:
    mac = hmac.new(STATE_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return _b64url(mac)


def _build_state() -> str:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    payload = f"{timestamp}:{nonce}"
    signature = _sign_state(payload)
    return f"{payload}:{signature}"


def _verify_state(state: str) -> bool:
    try:
        timestamp, nonce, signature = state.split(":", 2)
        payload = f"{timestamp}:{nonce}"
        expected = _sign_state(payload)
        if not hmac.compare_digest(signature, expected):
            return False
        if abs(time.time() - int(timestamp)) > STATE_TTL_SECONDS:
            return False
        return True
    except Exception:
        return False


def _load_storage() -> list[Dict[str, Any]]:
    if not STORAGE_PATH.exists():
        return []
    try:
        data = json.loads(STORAGE_PATH.read_text())
        if isinstance(data, list):
            return data
    except Exception as exc:
        logger.warning("Failed to read storage file: %s", exc)
    return []


def _save_record(record: Dict[str, Any]) -> None:
    STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = _load_storage()
    data.append(record)
    STORAGE_PATH.write_text(json.dumps(data, indent=2))


def _exchange_code(code: str) -> Dict[str, Any]:
    payload = {
        "grant_type": "authorization_code",
        "client_id": APP_ID,
        "client_secret": APP_SECRET,
        "code": code,
    }
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(FEISHU_TOKEN_URL, json=payload)
        resp.raise_for_status()
        body = resp.json()

    if body.get("code") not in (0, None):
        raise RuntimeError(body.get("msg") or f"Token exchange failed: {body}")

    data = body.get("data") or body
    return data


def _fetch_userinfo(access_token: str) -> Optional[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(FEISHU_USERINFO_URL, headers=headers)
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("Userinfo request failed: %s", exc)
        return None

    if body.get("code") not in (0, None):
        logger.warning("Userinfo returned error: %s", body)
        return None

    return body.get("data") or body


def _post_webhook(record: Dict[str, Any]) -> None:
    if not WEBHOOK_URL:
        return
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(WEBHOOK_URL, json=record)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Webhook delivery failed: %s", exc)


@app.route("/healthz")
def healthz() -> tuple[str, int]:
    return "ok", 200


@app.route("/")
def index() -> tuple[str, int]:
    config_error = _require_config()
    if config_error:
        return config_error, 500
    return "Feishu OAuth service is running", 200


@app.route("/oauth/login")
def oauth_login():
    config_error = _require_config()
    if config_error:
        return config_error, 500

    state = _build_state()
    url = (
        f"{FEISHU_AUTH_URL}?client_id={APP_ID}"
        f"&redirect_uri={REDIRECT_URI}&response_type=code&state={state}"
    )
    return redirect(url)


@app.route("/oauth/callback")
def oauth_callback():
    config_error = _require_config()
    if config_error:
        return config_error, 500

    if request.args.get("error"):
        message = request.args.get("error_description") or request.args.get("error")
        return f"Authorization failed: {message}", 400

    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "Missing authorization code", 400
    if not state or not _verify_state(state):
        return "Invalid or expired state", 400

    try:
        token_data = _exchange_code(code)
    except Exception as exc:
        logger.exception("Token exchange failed")
        return f"Token exchange failed: {exc}", 500

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = int(token_data.get("expires_in", 7200))
    if not access_token or not refresh_token:
        return "Token data missing in response", 500

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    userinfo = _fetch_userinfo(access_token)

    record = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "expires_at": expires_at.isoformat(),
        "user": userinfo,
        "raw_token_response": token_data,
    }

    try:
        _save_record(record)
    except Exception as exc:
        logger.exception("Failed to persist token record")
        return f"Failed to persist token: {exc}", 500

    _post_webhook(record)

    display_name = None
    if isinstance(userinfo, dict):
        display_name = userinfo.get("name") or userinfo.get("en_name")

    display = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "expires_at": expires_at.isoformat(),
        "user": userinfo,
    }
    payload = json.dumps(display, indent=2)
    name_line = f"<p>Welcome, {display_name}.</p>" if display_name else ""
    html = f"""<!DOCTYPE html>
<html>
<head><title>Authorization Complete</title></head>
<body>
  <h1>Authorization completed successfully.</h1>
  {name_line}
  <p>Tokens and expiry (copy as needed):</p>
  <div>
    <button type="button" onclick="copyText('access')">Copy access_token</button>
    <button type="button" onclick="copyText('refresh')">Copy refresh_token</button>
    <button type="button" onclick="copyText('all')">Copy all</button>
    <span id="copy-status" style="margin-left:8px;"></span>
  </div>
  <pre id="payload">{payload}</pre>
  <textarea id="access" style="position:absolute;left:-9999px;">{access_token}</textarea>
  <textarea id="refresh" style="position:absolute;left:-9999px;">{refresh_token}</textarea>
  <textarea id="all" style="position:absolute;left:-9999px;">{payload}</textarea>
  <script>
    function copyText(id) {{
      var el = document.getElementById(id);
      if (!el) return;
      el.select();
      el.setSelectionRange(0, 99999);
      try {{
        document.execCommand('copy');
        document.getElementById('copy-status').textContent = 'Copied';
      }} catch (e) {{
        document.getElementById('copy-status').textContent = 'Copy failed';
      }}
      setTimeout(function() {{
        document.getElementById('copy-status').textContent = '';
      }}, 1200);
    }}
  </script>
</body>
</html>
"""
    return html, 200


if __name__ == "__main__":
    config_error = _require_config()
    if config_error:
        logger.warning(config_error)
        logger.warning("Service will still start, but /oauth/login will fail until config is set.")
    app.run(host="0.0.0.0", port=int(_env("PORT") or _cfg("port") or 8000))

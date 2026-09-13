import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import sys
import time
import string
import base64
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlsplit
from zoneinfo import ZoneInfo

import aiofiles
import httpx
import uvicorn
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

# ── تزریق مستقیم پروکسی دویچه تلکام به لایه شبکه پایتون ───────────────────────
PROXY_HOST = "://ipoasis.com"
PROXY_PORT = 8668
PROXY_USER = "user-K7UO7Ach_6607-region-de-city-TROISDORF-sess-838010-sessTime-118"
PROXY_PASS = "wB20uBAH"

_auth_bytes = f"{PROXY_USER}:{PROXY_PASS}".encode("utf-8")
_auth_b64 = base64.b64encode(_auth_bytes).decode("utf-8")

_original_open_connection = asyncio.open_connection

async def _patched_open_connection(host, port, *args, **kwargs):
    """اتصال به مقصد از طریق متد CONNECT پروکسی"""
    reader, writer = await _original_open_connection(PROXY_HOST, PROXY_PORT, *args, **kwargs)
    
    connect_req = (
        f"CONNECT {host}:{port} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Proxy-Authorization: Basic {_auth_b64}\r\n"
        f"Proxy-Connection: Keep-Alive\r\n\r\n"
    )
    writer.write(connect_req.encode("utf-8"))
    await writer.drain()
    
    resp_line = await reader.readline()
    if b"200" not in resp_line:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(f"Proxy rejected: {resp_line.decode().strip()}")
        
    while True:
        line = await reader.readline()
        if line == b"\r\n" or not line:
            break
            
    return reader, writer

asyncio.open_connection = _patched_open_connection
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.modules.setdefault("main", sys.modules[__name__])

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
APP_NAME = "Technamooz Panel"
APP_VERSION = "2.0.0"
logger = logging.getLogger("Technamooz")

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title=f"{APP_NAME} v{APP_VERSION}", docs_url=None, redoc_url=None)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "technamooz_state.json"
SECRET_FILE = DATA_DIR / "technamooz_secret.key"
SAVE_LOCK = asyncio.Lock()

def _load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        secret_path = SECRET_FILE
        if secret_path.exists():
            existing = secret_path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_secret = secrets.token_urlsafe(32)
        SECRET_FILE.write_text(new_secret, encoding="utf-8")
        return new_secret
    except Exception as e:
        logger.warning(f"Could not persist SECRET_KEY: {e}")
        return secrets.token_urlsafe(32)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": _load_or_create_secret(),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() in {"1", "true", "yes"}

# رفع کامل ارور اصلی کدهای پنل
ALLOWED_PUBLIC_HOSTS = {x.strip().split(":", 1)[0].lower() for x in os.environ.get("ALLOWED_PUBLIC_HOSTS", "").split(",") if x.strip()}

_cors_origins = [x.strip() for x in os.environ.get("CORS_ORIGINS", "").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Requested-With"],
)

async def load_state():
    global LINKS, AUTH, SUBS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        state_path = DATA_FILE
        if state_path.exists():
            async with aiofiles.open(state_path, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            loaded_links = data.get("links", {})
            loaded_subs = data.get("subs", {})
            BOT_SETTINGS.update(data.get("telegram", {}))
            for item in loaded_links.values():
                if item.get("protocol") == "xhttp-stream-one":
                    item["protocol"] = "xhttp-stream-up"
            LINKS.update(loaded_links)
            SUBS.update(loaded_subs)
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
            if data.get("username"):
                AUTH["username"] = str(data["username"]).strip()
            logger.info(f"State loaded: {len(LINKS)} links, {len(SUBS)} subs")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "password_hash": AUTH["password_hash"],
                "username": AUTH["username"],
                "telegram": dict(BOT_SETTINGS),
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()

PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up")
DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}
DEFAULT_PORT = 443
MIN_PORT, MAX_PORT = 1, 65535

DEFAULT_SPEED_LIMIT = 0

def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

def hash_password(pw: str) -> str:
    iterations = 310_000
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt, expected = stored.split("$", 3)
            digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), int(iterations))
            return hmac.compare_digest(digest.hex(), expected)
        except (ValueError, TypeError):
            return False
    legacy = hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()
    return hmac.compare_digest(legacy, stored)

AUTH = {"username": os.environ.get("ADMIN_USERNAME", "Amirparsa"), "password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "Technamooz"))}
LOGIN_CAPTCHAS: dict[str, tuple[str, float]] = {}
BOT_SETTINGS = {"enabled": bool(os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()), "token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(), "admin_ids": os.environ.get("TELEGRAM_ADMIN_IDS", "").strip()}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()
LOGIN_FAILURES: dict[str, list[float]] = defaultdict(list)
LOGIN_LOCK = asyncio.Lock()

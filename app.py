import os
import json
import binascii
import asyncio
import logging
from threading import RLock
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, make_response
import requests
import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson

from apscheduler.schedulers.background import BackgroundScheduler

import like_pb2
import like_count_pb2
import uid_generator_pb2

# ============================================================
# HARDCODED CONFIG
# ============================================================
JWT_API_URL = "https://jwtapi-navy.vercel.app/token"   # no key, only uid+password

# Auto-refresh schedule: every day at 04:00 Beijing time
REFRESH_TZ = "Asia/Shanghai"   # Beijing time (UTC+8, no DST)
REFRESH_HOUR = 4
REFRESH_MINUTE = 0

# First generation 30 seconds after startup
STARTUP_REFRESH_DELAY_SECONDS = 30

OWNER_HANDLE = "TG: @apon2029"
REFRESH_SECRET = ""   # optional: /refresh-tokens?secret=... ; empty = open

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_DIR = BASE_DIR
ACCOUNTS_PATH = os.path.join(BASE_DIR, "accounts.json")
CONFIG_RO_PATH = os.path.join(BASE_DIR, "keys.json")
CONFIG_RW_PATH = os.path.join("/tmp", "keys.json")

# ============================================================
# Logging
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("like-api")

app = Flask(__name__)
os.makedirs(TOKEN_DIR, exist_ok=True)

config_lock = RLock()
_refresh_state_lock = RLock()
_refresh_state = {"last_refresh_iso": None, "last_result": None, "running": False}

# ============================================================
# keys.json config I/O — UNCHANGED
# ============================================================
def _active_config_path_for_read() -> str:
    return CONFIG_RW_PATH if os.path.exists(CONFIG_RW_PATH) else CONFIG_RO_PATH

def _read_config() -> dict:
    path = _active_config_path_for_read()
    if not os.path.exists(path):
        raise FileNotFoundError("keys.json not found.")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if "ALLOWED_KEYS" not in cfg or "ADMIN_KEYS" not in cfg or "RESET_TZ" not in cfg:
        raise ValueError("keys.json must include ALLOWED_KEYS, ADMIN_KEYS, RESET_TZ")
    if not isinstance(cfg["ALLOWED_KEYS"], dict) or not isinstance(cfg["ADMIN_KEYS"], list):
        raise ValueError("ALLOWED_KEYS must be object; ADMIN_KEYS must be array")
    return cfg

def get_allowed_keys() -> dict:
    with config_lock:
        return _read_config()["ALLOWED_KEYS"]

def get_admin_keys() -> set:
    with config_lock:
        return set(_read_config()["ADMIN_KEYS"])

def is_admin_key(k: str) -> bool:
    return k in get_admin_keys()

def _get_limit_for(api_key: str) -> int:
    allowed = get_allowed_keys()
    if api_key not in allowed:
        raise KeyError("key not allowed")
    return int(allowed[api_key])

# ============================================================
# timezone / quota — UNCHANGED
# ============================================================
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

def _today_str() -> str:
    with config_lock:
        tzname = _read_config()["RESET_TZ"]
    if ZoneInfo:
        return datetime.now(ZoneInfo(tzname)).strftime("%Y-%m-%d")
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

usage_store: dict = {}
usage_lock = RLock()

def get_used_count(api_key: str) -> int:
    day = _today_str()
    with usage_lock:
        return usage_store.get(api_key, {}).get(day, 0)

def _set_used_count(api_key: str, value: int) -> None:
    day = _today_str()
    with usage_lock:
        per_key = usage_store.setdefault(api_key, {})
        per_key[day] = max(0, int(value))

def consume_one(api_key: str) -> int:
    day = _today_str()
    with usage_lock:
        per_key = usage_store.setdefault(api_key, {})
        per_key[day] = per_key.get(day, 0) + 1
        return per_key[day]

# ============================================================
# token files — region aware
# ============================================================
_REGION_ALIASES = {
    "IND": "IND",
    "BR": "BR", "US": "BR", "SAC": "BR", "NA": "BR",
    "BD": "BD",
}

def _token_file_for(server_name: str) -> str:
    s = (server_name or "").upper()
    region = _REGION_ALIASES.get(s, "BD")
    return os.path.join(TOKEN_DIR, f"token_{region.lower()}.json")

def load_tokens(server_name: str) -> list:
    path = _token_file_for(server_name)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Token file {os.path.basename(path)} not found. "
            f"Refresh has not completed yet — wait for the startup job or GET /refresh-tokens."
        )
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or not data:
        raise ValueError(f"{os.path.basename(path)} is empty or malformed.")
    return data

# ============================================================
# game helpers — UNCHANGED
# ============================================================
def encrypt_message(plaintext):
    k = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(k, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode("utf-8")

def create_protobuf_message(user_id, region):
    m = like_pb2.like()
    m.uid = int(user_id)
    m.region = region
    return m.SerializeToString()

async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=edata, headers=headers) as resp:
            return resp.status

async def send_multiple_requests(uid, server_name, url):
    msg = create_protobuf_message(uid, server_name)
    enc_uid = encrypt_message(msg)
    tokens = load_tokens(server_name)
    tasks = [send_request(enc_uid, tokens[i % len(tokens)]["token"], url) for i in range(2000)]
    return await asyncio.gather(*tasks)

def create_protobuf(uid):
    m = uid_generator_pb2.uid_generator()
    m.krishna_ = int(uid)
    m.teamXdarks = 1
    return m.SerializeToString()

def enc(uid):
    return encrypt_message(create_protobuf(uid))

def make_request(encrypted, server_name, token):
    s = server_name.upper()
    if s == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif s in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }
    resp = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
    binary = bytes.fromhex(resp.content.hex())
    try:
        obj = like_count_pb2.Info()
        obj.ParseFromString(binary)
        return obj
    except Exception:
        return None

def _no_store_response(payload, status=200):
    resp = make_response(jsonify(payload), status)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp

def _parse_account_info(pb_obj):
    try:
        if pb_obj is None:
            return None
        js = json.loads(MessageToJson(pb_obj))
        ai = js.get("AccountInfo", {})
        uid = int(ai.get("UID", 0))
        likes = int(ai.get("Likes", 0))
        name = str(ai.get("PlayerNickname", ""))
        if uid <= 0:
            return None
        return {"uid": uid, "likes": likes, "name": name}
    except Exception:
        return None

# ============================================================
# JWT refresh — uid + password only
# ============================================================
def _load_accounts() -> list:
    if not os.path.exists(ACCOUNTS_PATH):
        raise FileNotFoundError(f"accounts.json not found at {ACCOUNTS_PATH}")
    with open(ACCOUNTS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("accounts.json must be a JSON array.")
    out = []
    for item in data:
        if isinstance(item, dict) and item.get("uid") and item.get("password"):
            out.append({"uid": str(item["uid"]), "password": str(item["password"])})
    if not out:
        raise ValueError("accounts.json contains no valid {uid,password} entries.")
    return out

def _fetch_jwt(account: dict, timeout: int = 30):
    params = {"uid": account["uid"], "password": account["password"]}
    try:
        resp = requests.get(JWT_API_URL, params=params, timeout=timeout)
        if not (200 <= resp.status_code < 300):
            log.warning("JWT API %s for uid=%s: %s", resp.status_code, account["uid"], resp.text[:120])
            return None, None
        data = resp.json()
        token = data.get("token")
        region = (data.get("region") or "IND").upper()
        if not token:
            log.warning("JWT API returned no token for uid=%s", account["uid"])
            return None, None
        return token, region
    except Exception as e:
        log.warning("JWT API error for uid=%s: %s", account["uid"], e)
        return None, None

def _delete_all_token_files() -> list:
    deleted = []
    for name in os.listdir(TOKEN_DIR):
        if name.startswith("token_") and name.endswith(".json"):
            try:
                os.remove(os.path.join(TOKEN_DIR, name))
                deleted.append(name)
            except OSError as e:
                log.warning("Could not delete %s: %s", name, e)
    return deleted

def refresh_tokens() -> dict:
    with _refresh_state_lock:
        if _refresh_state["running"]:
            return {"ok": False, "error": "refresh already running"}
        _refresh_state["running"] = True

    started = datetime.now(timezone.utc)
    log.info("refresh: starting at %s UTC", started.isoformat())

    try:
        accounts = _load_accounts()
    except Exception as e:
        log.error("refresh: cannot load accounts.json: %s", e)
        with _refresh_state_lock:
            _refresh_state["running"] = False
            _refresh_state["last_result"] = {"ok": False, "error": str(e)}
        return {"ok": False, "error": f"accounts.json: {e}"}

    deleted = _delete_all_token_files()
    log.info("refresh: deleted %d old token file(s): %s", len(deleted), deleted)

    by_region: dict = {}
    failures: list = []
    for acct in accounts:
        token, region = _fetch_jwt(acct)
        if token:
            by_region.setdefault(region, []).append({"token": token})
        else:
            failures.append({"uid": acct["uid"], "reason": "api_failure"})

    written = {}
    for region, tokens in by_region.items():
        if not tokens:
            continue
        path = os.path.join(TOKEN_DIR, f"token_{region.lower()}.json")
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(tokens, f)
            os.replace(tmp, path)
            written[region.lower()] = len(tokens)
            log.info("refresh: wrote %s with %d token(s)", os.path.basename(path), len(tokens))
        except OSError as e:
            log.error("refresh: failed to write %s: %s", path, e)
            if os.path.exists(tmp):
                try: os.remove(tmp)
                except OSError: pass

    finished = datetime.now(timezone.utc)
    result = {
        "ok": True,
        "started": started.isoformat(),
        "finished": finished.isoformat(),
        "deleted_files": deleted,
        "accounts_total": len(accounts),
        "tokens_written": written,
        "failures": failures,
    }

    with _refresh_state_lock:
        _refresh_state["last_refresh_iso"] = finished.isoformat()
        _refresh_state["last_result"] = {
            "ok": True, "written": written,
            "failures": len(failures), "accounts": len(accounts),
        }
        _refresh_state["running"] = False

    log.info("refresh: complete. accounts=%d, wrote=%s, failures=%d",
             len(accounts), written, len(failures))
    return result

# ============================================================
# /like — auth layer UNCHANGED
# ============================================================
@app.get("/like")
def handle_like():
    try:
        uid = request.args.get("uid")
        server_name = request.args.get("server_name", "").upper()
        api_key = request.args.get("key", "").strip()

        admins = get_admin_keys()
        allowed = get_allowed_keys()
        is_admin = api_key in admins

        if not api_key or (api_key not in allowed and not is_admin):
            return jsonify({"error": "Invalid or missing API key 🔑"}), 403
        if not uid or not server_name:
            return jsonify({"error": "UID and server_name are required"}), 400

        if not is_admin:
            limit_for_key = _get_limit_for(api_key)
            used_now = get_used_count(api_key)
            if used_now >= limit_for_key:
                return jsonify({"error": "Daily request limit reached for this key.",
                                "status": 429, "remains": f"(0/{limit_for_key})"}), 429

        try:
            tokens = load_tokens(server_name)
        except (FileNotFoundError, ValueError) as e:
            return jsonify({"error": "tokens_unavailable", "detail": str(e)}), 503

        token = tokens[0]["token"]
        encrypted = enc(uid)

        before_obj = make_request(encrypted, server_name, token)
        before = _parse_account_info(before_obj)
        if before is None:
            remains_str = "(∞/∞)" if is_admin else f"({max(0, _get_limit_for(api_key) - get_used_count(api_key))}/{_get_limit_for(api_key)})"
            return jsonify({
                "LikesGivenByAPI": 0, "LikesafterCommand": 0, "LikesbeforeCommand": 0,
                "PlayerNickname": "Unknown",
                "UID": int(uid) if str(uid).isdigit() else uid,
                "remains": remains_str, "Owner": OWNER_HANDLE, "status": 0
            })

        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggpolarbear.com/LikeProfile"
        asyncio.run(send_multiple_requests(uid, server_name, url))

        after_obj = make_request(encrypted, server_name, token)
        after = _parse_account_info(after_obj) or {"likes": before["likes"], "uid": before["uid"], "name": before["name"]}
        like_given = max(0, int(after["likes"]) - int(before["likes"]))
        status_value = 1 if like_given > 0 else 2

        if not is_admin:
            limit_for_key = _get_limit_for(api_key)
            new_used = consume_one(api_key)
            if new_used > limit_for_key:
                _set_used_count(api_key, limit_for_key)
                return jsonify({"error": "Daily request limit reached for this key.",
                                "status": 429, "remains": f"(0/{limit_for_key})"}), 429
            remaining = max(0, limit_for_key - new_used)
            remains_str = f"({remaining}/{limit_for_key})"
        else:
            remains_str = "(∞/∞)"

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": int(after["likes"]),
            "LikesbeforeCommand": int(before["likes"]),
            "PlayerNickname": str(after["name"]),
            "UID": int(after["uid"]),
            "remains": remains_str,
            "Owner": OWNER_HANDLE,
            "status": status_value
        })
    except Exception as e:
        return jsonify({"error": "config_or_runtime_error", "detail": str(e)}), 500

# ============================================================
# /kdkenejeekekkekekek — remain lookup, UNCHANGED
# ============================================================
@app.get("/kdkenejeekekkekekek")
def get_remain():
    try:
        qkey = request.args.get("key", "").strip()
        admins = get_admin_keys()
        allowed = get_allowed_keys()

        if qkey:
            if qkey in admins:
                return _no_store_response({
                    "key": qkey, "limit": "infinite", "used": 0,
                    "remaining": "infinite", "remains": "(∞/∞)", "admin": True
                })
            if qkey not in allowed:
                return _no_store_response({"error": "Invalid key for remain lookup"}, 403)
            limit = _get_limit_for(qkey)
            used = get_used_count(qkey)
            remaining = max(0, limit - used)
            return _no_store_response({
                "key": qkey, "limit": limit, "used": used,
                "remaining": remaining, "remains": f"({remaining}/{limit})"
            })

        out = []
        keys_union = set(allowed.keys()) | admins
        for k in sorted(keys_union):
            if k in admins:
                out.append({"key": k, "admin": True, "limit": "infinite",
                            "used": 0, "remaining": "infinite", "remains": "(∞/∞)"})
            else:
                limit = _get_limit_for(k)
                used = get_used_count(k)
                remaining = max(0, limit - used)
                out.append({"key": k, "admin": False, "limit": limit,
                            "used": used, "remaining": remaining,
                            "remains": f"({remaining}/{limit})"})
        return _no_store_response({"day": _today_str(), "keys": out})
    except Exception as e:
        return _no_store_response({"error": "config_error", "detail": str(e)}, 500)

# ============================================================
# manual refresh + health
# ============================================================
def _check_secret():
    if not REFRESH_SECRET:
        return True
    return request.args.get("secret") == REFRESH_SECRET

@app.get("/refresh-tokens")
def refresh_tokens_endpoint():
    if not _check_secret():
        return jsonify({"error": "forbidden"}), 403
    result = refresh_tokens()
    return jsonify(result), (200 if result.get("ok") else 500)

@app.get("/health")
def health():
    with _refresh_state_lock:
        state = dict(_refresh_state)
    token_counts = {}
    try:
        for name in os.listdir(TOKEN_DIR):
            if name.startswith("token_") and name.endswith(".json"):
                try:
                    with open(os.path.join(TOKEN_DIR, name), "r", encoding="utf-8") as f:
                        token_counts[name] = len(json.load(f))
                except Exception:
                    token_counts[name] = -1
    except OSError:
        pass
    return jsonify({
        "ok": True,
        "token_dir": TOKEN_DIR,
        "token_files": token_counts,
        "refresh": state,
        "schedule": {
            "startup_delay_seconds": STARTUP_REFRESH_DELAY_SECONDS,
            "daily_at": f"{REFRESH_HOUR:02d}:{REFRESH_MINUTE:02d} {REFRESH_TZ}",
        },
    })

# ============================================================
# scheduler — startup once + daily 04:00 Asia/Shanghai
# ============================================================
_scheduler = None

def _start_scheduler():
    global _scheduler
    if _scheduler is not None:
        return

    _scheduler = BackgroundScheduler(timezone=REFRESH_TZ)

    # 1) First generation: 30s after startup
    _scheduler.add_job(
        refresh_tokens,
        trigger="date",
        run_date=datetime.now(timezone.utc) + timedelta(seconds=STARTUP_REFRESH_DELAY_SECONDS),
        id="refresh_on_startup",
        replace_existing=True,
    )

    # 2) Daily regeneration: 04:00 Asia/Shanghai
    _scheduler.add_job(
        refresh_tokens,
        trigger="cron",
        hour=REFRESH_HOUR,
        minute=REFRESH_MINUTE,
        id="refresh_daily",
        replace_existing=True,
    )

    _scheduler.start()
    log.info(
        "scheduler started: startup refresh in %ds, then daily at %02d:%02d %s",
        STARTUP_REFRESH_DELAY_SECONDS, REFRESH_HOUR, REFRESH_MINUTE, REFRESH_TZ,
    )

if os.getenv("DISABLE_SCHEDULER") != "1":
    _start_scheduler()

# ============================================================
# entry point — `python app.py`
# ============================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    log.info("starting Flask on 0.0.0.0:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
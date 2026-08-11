from pathlib import Path

src = r'''# ============================================================
# GORILLA GUARD ADVANCED
# ============================================================
# Tiered server-side application integrity system
# ============================================================

from flask import Flask, jsonify, request, render_template
from functools import wraps
from pathlib import Path
import os
import time
import hmac
import hashlib
import secrets
import logging
import re
from datetime import datetime, timezone
import requests

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gorilla_guard")

SECURITY_LEVELS = {
    1: {"name": "Advanced", "severity": "advanced"},
    2: {"name": "Elite", "severity": "elite"},
    3: {"name": "VIP", "severity": "vip"},
    4: {"name": "Maximum", "severity": "maximum"},
}

try:
    DEFAULT_SECURITY_LEVEL = int(os.environ.get("GORILLA_SECURITY_LEVEL", "3"))
except ValueError:
    DEFAULT_SECURITY_LEVEL = 3

if DEFAULT_SECURITY_LEVEL not in SECURITY_LEVELS:
    DEFAULT_SECURITY_LEVEL = 3

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

CONFIG = {
    "package_id": os.environ.get("VALID_PACKAGE", "").strip(),
    "title_id": os.environ.get("PLAYFAB_TITLE_ID", "").strip(),
    "meta_app_id": os.environ.get("META_APP_ID", "").strip(),
    "meta_api_key": os.environ.get("META_API_KEY", "").strip(),
    "playfab_secret": os.environ.get("PLAYFAB_SECRET_KEY", "").strip(),
}

def load_trusted_certificates():
    raw = os.environ.get("TRUSTED_CERT_SHA256", "")
    result = set()
    for value in raw.split(","):
        normalized = normalize_certificate(value)
        if normalized:
            result.add(normalized)
    return result

def normalize_certificate(certificate):
    if not isinstance(certificate, str):
        return ""
    return (
        certificate.replace(":", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "")
        .strip()
        .lower()
    )

def valid_sha256(certificate):
    value = normalize_certificate(certificate)
    return len(value) == 64 and bool(re.fullmatch(r"[0-9a-f]{64}", value))

TRUSTED_CERTIFICATES = load_trusted_certificates()

DISCORD_WEBHOOKS = {
    "apk_modified": os.environ.get("DISCORD_WEBHOOK_APK_MODIFIED"),
    "signature": os.environ.get("DISCORD_WEBHOOK_SIGNATURE"),
    "keystore": os.environ.get("DISCORD_WEBHOOK_KEYSTORE"),
    "attestation": os.environ.get("DISCORD_WEBHOOK_ATTESTATION"),
    "device": os.environ.get("DISCORD_WEBHOOK_DEVICE"),
    "replay": os.environ.get("DISCORD_WEBHOOK_REPLAY"),
    "tamper": os.environ.get("DISCORD_WEBHOOK_TAMPER"),
    "critical": os.environ.get("DISCORD_WEBHOOK_CRITICAL"),
    "success": os.environ.get("DISCORD_WEBHOOK_SUCCESS"),
    "system": os.environ.get("DISCORD_WEBHOOK_SYSTEM"),
}

DISCORD_COLORS = {
    "info": 3447003,
    "warning": 16776960,
    "high": 16744192,
    "critical": 15158332,
    "success": 5763719,
}

NONCES = {}
SESSIONS = {}
NONCE_LIFETIME = int(os.environ.get("NONCE_LIFETIME", "120"))
SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME", "900"))

def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()

def safe_player_id(player_id):
    if not player_id:
        return "unknown"
    return str(player_id)[:128]

def send_discord(category, title, description, severity="info", fields=None):
    webhook = DISCORD_WEBHOOKS.get(category)
    if not webhook:
        return False

    embed = {
        "title": title,
        "description": description,
        "color": DISCORD_COLORS.get(severity, DISCORD_COLORS["info"]),
        "timestamp": utc_timestamp(),
        "footer": {"text": "Gorilla Guard Advanced"},
    }

    if fields:
        embed["fields"] = fields

    try:
        response = requests.post(
            webhook,
            json={"username": "Gorilla Guard", "embeds": [embed]},
            timeout=5,
        )
        return 200 <= response.status_code < 300
    except requests.RequestException as exc:
        logger.warning("Discord notification failed: %s", exc)
        return False

def security_event(category, title, description, severity="warning",
                   player_id=None, reason=None):
    fields = []
    if player_id is not None:
        fields.append({
            "name": "Player",
            "value": f"`{safe_player_id(player_id)}`",
            "inline": True,
        })
    if reason:
        fields.append({
            "name": "Reason",
            "value": str(reason)[:1024],
            "inline": False,
        })
    return send_discord(category, title, description, severity, fields)

def security_configuration_ready():
    if not CONFIG["package_id"] or not TRUSTED_CERTIFICATES:
        return False
    return all(valid_sha256(cert) for cert in TRUSTED_CERTIFICATES)

def certificate_is_trusted(certificate):
    normalized = normalize_certificate(certificate)
    if not valid_sha256(normalized):
        return False
    return any(hmac.compare_digest(normalized, trusted)
               for trusted in TRUSTED_CERTIFICATES)

def verify_package(package_id):
    if not package_id or not CONFIG["package_id"]:
        return False
    return hmac.compare_digest(str(package_id), str(CONFIG["package_id"]))

def create_nonce(player_id):
    player_id = safe_player_id(player_id)
    nonce = secrets.token_urlsafe(32)
    NONCES[player_id] = {"nonce": nonce, "created": time.time()}
    return nonce

def consume_nonce(player_id, supplied_nonce):
    player_id = safe_player_id(player_id)
    record = NONCES.get(player_id)
    if not record:
        return False
    if time.time() - record["created"] > NONCE_LIFETIME:
        NONCES.pop(player_id, None)
        return False

    valid = hmac.compare_digest(
        str(supplied_nonce or ""),
        str(record["nonce"]),
    )
    if valid:
        NONCES.pop(player_id, None)
    return valid

def create_session(player_id, threat_score):
    session_id = secrets.token_urlsafe(48)
    now = time.time()
    SESSIONS[session_id] = {
        "player_id": safe_player_id(player_id),
        "created": now,
        "expires": now + SESSION_LIFETIME,
        "threat_score": threat_score,
    }
    return session_id

def validate_session(session_id, player_id):
    if not session_id:
        return False
    session = SESSIONS.get(session_id)
    if not session:
        return False
    if time.time() > session["expires"]:
        SESSIONS.pop(session_id, None)
        return False
    return hmac.compare_digest(str(session["player_id"]), str(player_id))

def threat_level(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"

def calculate_threat_score(findings):
    weights = {
        "package": 50,
        "signature": 80,
        "attestation": 60,
        "device": 40,
        "replay": 75,
        "tamper": 70,
        "build": 35,
        "session": 45,
    }
    return min(sum(weights.get(finding, 20) for finding in findings), 100)

def inspect_application_state(app_state):
    findings = []
    if not isinstance(app_state, dict):
        return ["build", "tamper"]

    package_id = app_state.get("package_id")
    certificate = app_state.get("package_cert_sha256_digest")
    build_id = app_state.get("build_id")
    version = app_state.get("version")

    if not verify_package(package_id):
        findings.append("package")

    if not certificate or not valid_sha256(certificate):
        findings.append("signature")
    elif not certificate_is_trusted(certificate):
        findings.append("signature")

    if build_id is not None and not isinstance(build_id, str):
        findings.append("build")
    if version is not None and not isinstance(version, str):
        findings.append("build")

    return findings

def inspect_device_state(device_state):
    if not isinstance(device_state, dict):
        return ["device"]

    findings = []
    integrity = device_state.get("device_integrity_state")
    unique_id = device_state.get("unique_id")

    if not unique_id:
        findings.append("device")

    if integrity and integrity not in {"Advanced", "Basic", "Standard"}:
        findings.append("device")

    return findings

def detect_tampering(claims):
    if not isinstance(claims, dict):
        return ["tamper"]

    findings = []
    app_state = claims.get("app_state", {})
    device_state = claims.get("device_state", {})

    if not isinstance(app_state, dict) or not isinstance(device_state, dict):
        return ["tamper"]

    if not app_state.get("package_id"):
        findings.append("tamper")

    integrity = device_state.get("device_integrity_state")
    unique_id = device_state.get("unique_id")
    if integrity and not unique_id:
        findings.append("tamper")

    return findings

def inspect_attestation(attestation):
    if not isinstance(attestation, dict):
        return ["attestation"]

    records = attestation.get("data", [])
    if not isinstance(records, list) or not records:
        return ["attestation"]

    record = records[0]
    if not isinstance(record, dict) or record.get("message") != "success":
        return ["attestation"]

    return []

def security_decision(level, findings):
    findings = list(dict.fromkeys(findings))
    score = calculate_threat_score(findings)

    if level >= 1 and any(x in findings for x in ("package", "signature")):
        return False, score
    if level >= 2 and any(x in findings for x in ("attestation", "replay", "session")):
        return False, score
    if level >= 3 and ("tamper" in findings or score >= 70):
        return False, score
    if level >= 4 and ("device" in findings or score > 0):
        return False, score

    return True, score

def send_detection_alerts(player_id, package_id, findings, score):
    for finding in findings:
        if finding == "package":
            security_event(
                "signature", "📦 PACKAGE ID MISMATCH",
                "The submitted package does not match the configured production package.",
                "critical", player_id, f"Received package: {package_id or 'missing'}"
            )
        elif finding == "signature":
            security_event(
                "apk_modified", "🚨 UNTRUSTED APK SIGNATURE",
                "The application signing certificate is not in the trusted certificate set.",
                "critical", player_id, "Possible modified or re-signed APK."
            )
            security_event(
                "keystore", "🔐 SIGNING-KEY VERIFICATION FAILED",
                "The application's verifiable signing identity was not recognized as trusted.",
                "high", player_id, "Certificate verification failed."
            )
        elif finding == "attestation":
            security_event(
                "attestation", "🛡️ ATTESTATION VERIFICATION FAILED",
                "Platform integrity information could not be accepted.",
                "high", player_id, "Attestation validation failed."
            )
        elif finding == "device":
            security_event(
                "device", "📱 DEVICE INTEGRITY WARNING",
                "Device integrity information did not satisfy the selected policy.",
                "high", player_id, "Device integrity check failed."
            )
        elif finding == "replay":
            security_event(
                "replay", "🔄 REPLAY ATTACK DETECTED",
                "A nonce was missing, expired, or had already been consumed.",
                "critical", player_id, "Authentication replay protection triggered."
            )
        elif finding == "tamper":
            security_event(
                "tamper", "⚠️ INTEGRITY STATE INCONSISTENCY",
                "Multiple supplied security signals were inconsistent.",
                "critical", player_id, "Possible tampering or malformed security data."
            )
        elif finding == "build":
            security_event(
                "tamper", "🏗️ BUILD INTEGRITY WARNING",
                "Application build metadata was inconsistent with the expected structure.",
                "warning", player_id, "Build integrity check failed."
            )
        elif finding == "session":
            security_event(
                "replay", "🔒 SESSION VALIDATION FAILED",
                "The supplied authentication session could not be validated.",
                "high", player_id, "Session invalid or expired."
            )

    if score >= 90:
        security_event(
            "critical", "🚨 CRITICAL THREAT SCORE",
            "Gorilla Guard calculated a critical security threat score.",
            "critical", player_id, f"Threat score: {score}/100"
        )

def require_level(minimum_level):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if DEFAULT_SECURITY_LEVEL < minimum_level:
                return jsonify({
                    "success": False,
                    "error": "Security level unavailable.",
                }), 403
            return function(*args, **kwargs)
        return wrapper
    return decorator

# ------------------------------------------------------------
# HOME
# ------------------------------------------------------------

@app.get("/")
def home():
    # FIX: this endpoint now renders the UI instead of returning
    # the old JSON health response. If templates/index.html does
    # not exist, return a useful JSON status instead of a 500.
    template = TEMPLATES_DIR / "index.html"
    if template.exists():
        return render_template(
            "index.html",
            security_level=DEFAULT_SECURITY_LEVEL,
            security_level_name=SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]["name"],
        )

    return jsonify({
        "service": "Gorilla Guard Advanced",
        "status": "online",
        "security_level": DEFAULT_SECURITY_LEVEL,
        "security_level_name": SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]["name"],
        "message": "Backend online. Create templates/index.html for the web dashboard.",
    })

@app.get("/api/security/levels")
def security_levels():
    return jsonify({
        "current": DEFAULT_SECURITY_LEVEL,
        "levels": [
            {"level": number, "name": data["name"]}
            for number, data in SECURITY_LEVELS.items()
        ],
    })

@app.post("/api/security/nonce")
@require_level(2)
def issue_nonce():
    body = request.get_json(silent=True) or {}
    player_id = safe_player_id(body.get("UserId"))

    if player_id == "unknown":
        return jsonify({"success": False, "error": "UserId is required."}), 400

    nonce = create_nonce(player_id)
    return jsonify({
        "success": True,
        "nonce": nonce,
        "expires_in": NONCE_LIFETIME,
    })

@app.post("/api/security/verify")
def verify():
    body = request.get_json(silent=True) or {}

    player_id = safe_player_id(body.get("UserId"))
    claims = body.get("claims", {})
    attestation = body.get("attestation")
    supplied_nonce = body.get("Nonce")
    session_id = body.get("SessionId")

    findings = []

    if not security_configuration_ready():
        security_event(
            "critical",
            "⚙️ SECURITY CONFIGURATION ERROR",
            "Production package and trusted SHA-256 signing certificate are required.",
            "critical",
            player_id,
            "Server security configuration incomplete.",
        )
        return jsonify({
            "success": False,
            "error": "Security configuration incomplete.",
        }), 503

    if not isinstance(claims, dict):
        findings.append("tamper")
        claims = {}

    app_state = claims.get("app_state", {})
    device_state = claims.get("device_state", {})

    findings.extend(inspect_application_state(app_state))

    if DEFAULT_SECURITY_LEVEL >= 2:
        findings.extend(inspect_device_state(device_state))
        findings.extend(inspect_attestation(attestation))

        if not consume_nonce(player_id, supplied_nonce):
            findings.append("replay")

        if session_id and not validate_session(session_id, player_id):
            findings.append("session")

    if DEFAULT_SECURITY_LEVEL >= 3:
        findings.extend(detect_tampering(claims))

    findings = list(dict.fromkeys(findings))
    score = calculate_threat_score(findings)

    package_id = app_state.get("package_id") if isinstance(app_state, dict) else None

    if findings:
        send_detection_alerts(player_id, package_id, findings, score)

    allowed, score = security_decision(DEFAULT_SECURITY_LEVEL, findings)

    if not allowed:
        return jsonify({
            "success": False,
            "authenticated": False,
            "security_level": DEFAULT_SECURITY_LEVEL,
            "security_level_name": SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]["name"],
            "threat_score": score,
            "threat_level": threat_level(score),
            "detections": findings,
            "message": "Security verification failed.",
        }), 403

    session = create_session(player_id, score)

    send_discord(
        "success",
        "🟢 GORILLA GUARD VERIFICATION PASSED",
        "The application passed the selected Gorilla Guard security policy.",
        "success",
        fields=[
            {"name": "Player", "value": f"`{player_id}`", "inline": True},
            {"name": "Security Level", "value": f"{DEFAULT_SECURITY_LEVEL} — {SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]['name']}", "inline": True},
            {"name": "Threat Score", "value": f"{score}/100", "inline": True},
            {"name": "Package", "value": f"`{package_id or 'unknown'}`", "inline": False},
            {"name": "Result", "value": "✅ AUTHENTICATED", "inline": False},
        ],
    )

    return jsonify({
        "success": True,
        "authenticated": True,
        "security_level": DEFAULT_SECURITY_LEVEL,
        "security_level_name": SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]["name"],
        "threat_score": score,
        "threat_level": threat_level(score),
        "session_id": session,
        "message": "Security verification passed.",
    })

@app.post("/api/security/session/check")
@require_level(2)
def session_check():
    body = request.get_json(silent=True) or {}
    player_id = safe_player_id(body.get("UserId"))
    session_id = body.get("SessionId")

    if not validate_session(session_id, player_id):
        security_event(
            "replay",
            "🔒 SESSION VALIDATION FAILED",
            "A session request was rejected because the session was invalid or expired.",
            "high",
            player_id,
            "Invalid session.",
        )
        return jsonify({"success": False, "authenticated": False}), 403

    return jsonify({"success": True, "authenticated": True})

@app.post("/api/security/discord-test/<category>")
def discord_test(category):
    if category not in DISCORD_WEBHOOKS:
        return jsonify({"success": False, "error": "Invalid Discord category."}), 400

    sent = send_discord(
        category,
        "🦍 GORILLA GUARD TEST ALERT",
        "This is a test notification from Gorilla Guard Advanced.",
        "info",
        fields=[
            {"name": "Category", "value": category, "inline": True},
            {"name": "Security Level", "value": f"{DEFAULT_SECURITY_LEVEL} — {SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]['name']}", "inline": True},
        ],
    )

    return jsonify({"success": sent, "category": category})

@app.get("/api/security/status")
def security_status():
    return jsonify({
        "service": "Gorilla Guard Advanced",
        "online": True,
        "security_level": DEFAULT_SECURITY_LEVEL,
        "security_level_name": SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]["name"],
        "configuration_ready": security_configuration_ready(),
        "package_configured": bool(CONFIG["package_id"]),
        "trusted_certificates": len(TRUSTED_CERTIFICATES),
        "modules": {
            "apk_integrity": True,
            "signature_verification": True,
            "keystore_identity": True,
            "attestation": DEFAULT_SECURITY_LEVEL >= 2,
            "replay_protection": DEFAULT_SECURITY_LEVEL >= 2,
            "session_security": DEFAULT_SECURITY_LEVEL >= 2,
            "device_integrity": DEFAULT_SECURITY_LEVEL >= 2,
            "tamper_detection": DEFAULT_SECURITY_LEVEL >= 3,
            "threat_scoring": True,
            "critical_escalation": DEFAULT_SECURITY_LEVEL >= 3,
            "strict_mode": DEFAULT_SECURITY_LEVEL >= 4,
        },
        "discord": {
            category: bool(webhook)
            for category, webhook in DISCORD_WEBHOOKS.items()
        },
    })

@app.get("/api/health")
def health():
    return jsonify({
        "status": "online",
        "service": "gorilla-guard",
        "security_level": DEFAULT_SECURITY_LEVEL,
        "security_level_name": SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]["name"],
    })

def cleanup_security_state():
    now = time.time()

    for player_id, record in list(NONCES.items()):
        if now - record["created"] > NONCE_LIFETIME:
            NONCES.pop(player_id, None)

    for session_id, session in list(SESSIONS.items()):
        if now > session["expires"]:
            SESSIONS.pop(session_id, None)

if __name__ == "__main__":
    logger.info("Starting Gorilla Guard Advanced.")
    logger.info(
        "Security level: %s (%s)",
        DEFAULT_SECURITY_LEVEL,
        SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]["name"],
    )

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
'''

path = Path("/mnt/data/index.py")
path.write_text(src, encoding="utf-8")
print(f"Fixed index.py written to {path}")

# ============================================================
# GORILLA GUARD ADVANCED
# ============================================================
#
# Tiered server-side application integrity system
#
# LEVEL 1  = ADVANCED
# LEVEL 2  = ELITE
# LEVEL 3  = VIP
# LEVEL 4  = MAXIMUM
#
# Features:
#   - APK/package verification
#   - Signing certificate SHA-256 verification
#   - Certificate rotation support
#   - Attestation validation hook
#   - Nonce/replay protection
#   - Session protection
#   - Threat scoring
#   - Tamper/inconsistency detection
#   - Device integrity evaluation
#   - Detailed Discord security alerts
#   - Separate webhook slots
#   - Fail-closed security configuration
#
# IMPORTANT:
# The server cannot directly inspect a private APK keystore.
# It verifies signing information and trusted attestation
# data supplied by the application/platform.
#
# ============================================================

from flask import Flask, jsonify, request
from functools import wraps

import os
import time
import hmac
import hashlib
import secrets
import logging
import re
from datetime import datetime, timezone

import requests


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 512 * 1024


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO
)

logger = logging.getLogger(
    "gorilla_guard"
)


# ============================================================
# SECURITY LEVELS
# ============================================================

SECURITY_LEVELS = {

    1: {
        "name": "Advanced",
        "severity": "advanced",
    },

    2: {
        "name": "Elite",
        "severity": "elite",
    },

    3: {
        "name": "VIP",
        "severity": "vip",
    },

    4: {
        "name": "Maximum",
        "severity": "maximum",
    },

}


DEFAULT_SECURITY_LEVEL = int(
    os.environ.get(
        "GORILLA_SECURITY_LEVEL",
        "3"
    )
)


if DEFAULT_SECURITY_LEVEL not in SECURITY_LEVELS:

    DEFAULT_SECURITY_LEVEL = 3


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

CONFIG = {

    "package_id":
        os.environ.get(
            "VALID_PACKAGE",
            ""
        ).strip(),

    "title_id":
        os.environ.get(
            "PLAYFAB_TITLE_ID",
            ""
        ).strip(),

    "meta_app_id":
        os.environ.get(
            "META_APP_ID",
            ""
        ).strip(),

    "meta_api_key":
        os.environ.get(
            "META_API_KEY",
            ""
        ).strip(),

    "playfab_secret":
        os.environ.get(
            "PLAYFAB_SECRET_KEY",
            ""
        ).strip(),

}


# ============================================================
# TRUSTED CERTIFICATES
# ============================================================
#
# Multiple certificates can be supplied for legitimate
# signing-key rotation.
#
# Example:
#
# TRUSTED_CERT_SHA256=
# abc123...,def456...
#
# ============================================================

def load_trusted_certificates():

    raw = os.environ.get(
        "TRUSTED_CERT_SHA256",
        ""
    )

    certificates = set()

    for value in raw.split(","):

        normalized = (
            value
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "")
            .strip()
            .lower()
        )

        if normalized:

            certificates.add(
                normalized
            )

    return certificates


TRUSTED_CERTIFICATES = (
    load_trusted_certificates()
)


# ============================================================
# DISCORD WEBHOOKS
# ============================================================

DISCORD_WEBHOOKS = {

    "apk_modified":
        os.environ.get(
            "DISCORD_WEBHOOK_APK_MODIFIED"
        ),

    "signature":
        os.environ.get(
            "DISCORD_WEBHOOK_SIGNATURE"
        ),

    "keystore":
        os.environ.get(
            "DISCORD_WEBHOOK_KEYSTORE"
        ),

    "attestation":
        os.environ.get(
            "DISCORD_WEBHOOK_ATTESTATION"
        ),

    "device":
        os.environ.get(
            "DISCORD_WEBHOOK_DEVICE"
        ),

    "replay":
        os.environ.get(
            "DISCORD_WEBHOOK_REPLAY"
        ),

    "tamper":
        os.environ.get(
            "DISCORD_WEBHOOK_TAMPER"
        ),

    "critical":
        os.environ.get(
            "DISCORD_WEBHOOK_CRITICAL"
        ),

    "success":
        os.environ.get(
            "DISCORD_WEBHOOK_SUCCESS"
        ),

    "system":
        os.environ.get(
            "DISCORD_WEBHOOK_SYSTEM"
        ),

}


# ============================================================
# DISCORD COLORS
# ============================================================

DISCORD_COLORS = {

    "info": 3447003,

    "warning": 16776960,

    "high": 16744192,

    "critical": 15158332,

    "success": 5763719,

}


# ============================================================
# RUNTIME SECURITY STATE
# ============================================================

NONCES = {}

SESSIONS = {}

THREAT_EVENTS = {}


NONCE_LIFETIME = int(
    os.environ.get(
        "NONCE_LIFETIME",
        "120"
    )
)


SESSION_LIFETIME = int(
    os.environ.get(
        "SESSION_LIFETIME",
        "900"
    )
)


# ============================================================
# TIME
# ============================================================

def utc_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# SAFE PLAYER IDENTIFIER
# ============================================================

def safe_player_id(
    player_id
):

    if not player_id:

        return "unknown"


    value = str(
        player_id
    )


    if len(value) > 128:

        value = value[:128]


    return value


# ============================================================
# DISCORD
# ============================================================

def send_discord(
    category,
    title,
    description,
    severity="info",
    fields=None
):

    webhook = DISCORD_WEBHOOKS.get(
        category
    )


    if not webhook:

        return False


    embed = {

        "title":
            title,

        "description":
            description,

        "color":
            DISCORD_COLORS.get(
                severity,
                DISCORD_COLORS["info"]
            ),

        "timestamp":
            utc_timestamp(),

        "footer": {

            "text":
                "Gorilla Guard Advanced"

        },

    }


    if fields:

        embed["fields"] = fields


    payload = {

        "username":
            "Gorilla Guard",

        "embeds": [
            embed
        ],

    }


    try:

        response = requests.post(

            webhook,

            json=payload,

            timeout=5

        )


        return (
            200
            <= response.status_code
            < 300
        )


    except requests.RequestException as exc:

        logger.warning(
            "Discord notification failed: %s",
            exc
        )

        return False


# ============================================================
# SECURITY EVENT
# ============================================================

def security_event(
    category,
    title,
    description,
    severity="warning",
    player_id=None,
    reason=None
):

    fields = []


    if player_id is not None:

        fields.append({

            "name":
                "Player",

            "value":
                f"`{safe_player_id(player_id)}`",

            "inline":
                True,

        })


    if reason:

        fields.append({

            "name":
                "Reason",

            "value":
                str(reason)[:1024],

            "inline":
                False,

        })


    send_discord(

        category,

        title,

        description,

        severity,

        fields

    )


# ============================================================
# CONFIGURATION VALIDATION
# ============================================================

def security_configuration_ready():

    if not CONFIG["package_id"]:

        return False


    if not TRUSTED_CERTIFICATES:

        return False


    for certificate in TRUSTED_CERTIFICATES:

        if not valid_sha256(
            certificate
        ):

            return False


    return True


# ============================================================
# SHA-256
# ============================================================

def normalize_certificate(
    certificate
):

    if not isinstance(
        certificate,
        str
    ):

        return ""


    return (
        certificate
        .replace(":", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "")
        .strip()
        .lower()
    )


def valid_sha256(
    certificate
):

    value = normalize_certificate(
        certificate
    )


    if len(value) != 64:

        return False


    return bool(
        re.fullmatch(
            r"[0-9a-f]{64}",
            value
        )
    )


# ============================================================
# CONSTANT-TIME CERTIFICATE CHECK
# ============================================================

def certificate_is_trusted(
    certificate
):

    normalized = normalize_certificate(
        certificate
    )


    if not valid_sha256(
        normalized
    ):

        return False


    for trusted in TRUSTED_CERTIFICATES:

        if hmac.compare_digest(
            normalized,
            trusted
        ):

            return True


    return False


# ============================================================
# PACKAGE CHECK
# ============================================================

def verify_package(
    package_id
):

    if not package_id:

        return False


    if not CONFIG["package_id"]:

        return False


    return hmac.compare_digest(

        str(package_id),

        str(CONFIG["package_id"])

    )


# ============================================================
# NONCE SYSTEM
# ============================================================

def create_nonce(
    player_id
):

    player_id = safe_player_id(
        player_id
    )


    nonce = secrets.token_urlsafe(
        32
    )


    NONCES[player_id] = {

        "nonce":
            nonce,

        "created":
            time.time(),

    }


    return nonce


def consume_nonce(
    player_id,
    supplied_nonce
):

    player_id = safe_player_id(
        player_id
    )


    record = NONCES.get(
        player_id
    )


    if not record:

        return False


    if (
        time.time()
        - record["created"]
        > NONCE_LIFETIME
    ):

        NONCES.pop(
            player_id,
            None
        )

        return False


    expected = record[
        "nonce"
    ]


    valid = hmac.compare_digest(

        str(supplied_nonce or ""),

        str(expected)

    )


    if valid:

        NONCES.pop(
            player_id,
            None
        )


    return valid


# ============================================================
# SESSION SYSTEM
# ============================================================

def create_session(
    player_id,
    threat_score
):

    session_id = secrets.token_urlsafe(
        48
    )


    SESSIONS[session_id] = {

        "player_id":
            safe_player_id(
                player_id
            ),

        "created":
            time.time(),

        "expires":
            time.time()
            + SESSION_LIFETIME,

        "threat_score":
            threat_score,

    }


    return session_id


def validate_session(
    session_id,
    player_id
):

    if not session_id:

        return False


    session = SESSIONS.get(
        session_id
    )


    if not session:

        return False


    if (
        time.time()
        > session["expires"]
    ):

        SESSIONS.pop(
            session_id,
            None
        )

        return False


    return hmac.compare_digest(

        str(
            session["player_id"]
        ),

        str(
            player_id
        )

    )


# ============================================================
# THREAT SCORING
# ============================================================

def threat_level(
    score
):

    if score >= 90:

        return "CRITICAL"


    if score >= 70:

        return "HIGH"


    if score >= 40:

        return "MEDIUM"


    return "LOW"


def calculate_threat_score(
    findings
):

    weights = {

        "package":
            50,

        "signature":
            80,

        "attestation":
            60,

        "device":
            40,

        "replay":
            75,

        "tamper":
            70,

        "build":
            35,

        "session":
            45,

    }


    score = 0


    for finding in findings:

        score += weights.get(
            finding,
            20
        )


    return min(
        score,
        100
    )


# ============================================================
# BUILD / APPLICATION STATE
# ============================================================

def inspect_application_state(
    app_state
):

    findings = []


    if not isinstance(
        app_state,
        dict
    ):

        findings.append(
            "build"
        )

        return findings


    package_id = app_state.get(
        "package_id"
    )


    certificate = app_state.get(
        "package_cert_sha256_digest"
    )


    build_id = app_state.get(
        "build_id"
    )


    version = app_state.get(
        "version"
    )


    # Package

    if not verify_package(
        package_id
    ):

        findings.append(
            "package"
        )


    # Certificate

    if not certificate:

        findings.append(
            "signature"
        )

    elif not valid_sha256(
        certificate
    ):

        findings.append(
            "signature"
        )

    elif not certificate_is_trusted(
        certificate
    ):

        findings.append(
            "signature"
        )


    # Build metadata

    if build_id is not None:

        if not isinstance(
            build_id,
            str
        ):

            findings.append(
                "build"
            )


    if version is not None:

        if not isinstance(
            version,
            str
        ):

            findings.append(
                "build"
            )


    return findings


# ============================================================
# DEVICE STATE
# ============================================================

def inspect_device_state(
    device_state
):

    findings = []


    if not isinstance(
        device_state,
        dict
    ):

        findings.append(
            "device"
        )

        return findings


    integrity = device_state.get(
        "device_integrity_state"
    )


    unique_id = device_state.get(
        "unique_id"
    )


    if not unique_id:

        findings.append(
            "device"
        )


    if integrity:

        accepted = {

            "Advanced",
            "Basic",
            "Standard",

        }


        if integrity not in accepted:

            findings.append(
                "device"
            )


    return findings


# ============================================================
# TAMPER / INCONSISTENCY CHECKS
# ============================================================

def detect_tampering(
    claims
):

    findings = []


    if not isinstance(
        claims,
        dict
    ):

        findings.append(
            "tamper"
        )

        return findings


    app_state = claims.get(
        "app_state",
        {}
    )


    device_state = claims.get(
        "device_state",
        {}
    )


    # Application and device state must both
    # be structured objects.

    if not isinstance(
        app_state,
        dict
    ):

        findings.append(
            "tamper"
        )


    if not isinstance(
        device_state,
        dict
    ):

        findings.append(
            "tamper"
        )


    # A package identifier should not be empty
    # when an attestation result claims to be valid.

    if isinstance(
        app_state,
        dict
    ):

        if not app_state.get(
            "package_id"
        ):

            findings.append(
                "tamper"
            )


    # Device identity should accompany device
    # integrity information.

    if isinstance(
        device_state,
        dict
    ):

        integrity = device_state.get(
            "device_integrity_state"
        )

        unique_id = device_state.get(
            "unique_id"
        )


        if integrity and not unique_id:

            findings.append(
                "tamper"
            )


    return findings


# ============================================================
# ATTESTATION RESULT
# ============================================================

def inspect_attestation(
    attestation
):

    findings = []


    if not isinstance(
        attestation,
        dict
    ):

        findings.append(
            "attestation"
        )

        return findings


    records = attestation.get(
        "data",
        []
    )


    if not isinstance(
        records,
        list
    ):

        findings.append(
            "attestation"
        )

        return findings


    if not records:

        findings.append(
            "attestation"
        )

        return findings


    record = records[0]


    if not isinstance(
        record,
        dict
    ):

        findings.append(
            "attestation"
        )

        return findings


    if record.get(
        "message"
    ) != "success":

        findings.append(
            "attestation"
        )


    return findings


# ============================================================
# SECURITY DECISION
# ============================================================

def security_decision(
    level,
    findings
):

    # Remove duplicates.

    findings = list(
        dict.fromkeys(
            findings
        )
    )


    score = calculate_threat_score(
        findings
    )


    # --------------------------------------------------------
    # ADVANCED
    # --------------------------------------------------------

    if level >= 1:

        if (
            "package"
            in findings
        ):

            return False, score


        if (
            "signature"
            in findings
        ):

            return False, score


    # --------------------------------------------------------
    # ELITE
    # --------------------------------------------------------

    if level >= 2:

        if (
            "attestation"
            in findings
        ):

            return False, score


        if (
            "replay"
            in findings
        ):

            return False, score


        if (
            "session"
            in findings
        ):

            return False, score


    # --------------------------------------------------------
    # VIP
    # --------------------------------------------------------

    if level >= 3:

        if (
            "tamper"
            in findings
        ):

            return False, score


        if score >= 70:

            return False, score


    # --------------------------------------------------------
    # MAXIMUM
    # --------------------------------------------------------

    if level >= 4:

        if (
            "device"
            in findings
        ):

            return False, score


        if score > 0:

            return False, score


    return True, score


# ============================================================
# DETAILED SECURITY ALERTS
# ============================================================

def send_detection_alerts(
    player_id,
    package_id,
    findings,
    score
):

    level = threat_level(
        score
    )


    for finding in findings:

        if finding == "package":

            security_event(

                "signature",

                "📦 PACKAGE ID MISMATCH",

                (
                    "The submitted application "
                    "package does not match the "
                    "configured production package."
                ),

                "critical",

                player_id,

                f"Received package: "
                f"{package_id or 'missing'}"

            )


        elif finding == "signature":

            security_event(

                "apk_modified",

                "🚨 UNTRUSTED APK SIGNATURE",

                (
                    "The application signing "
                    "certificate could not be "
                    "matched against the trusted "
                    "certificate set."
                ),

                "critical",

                player_id,

                "Possible modified or re-signed APK."

            )


            security_event(

                "keystore",

                "🔐 SIGNING-KEY VERIFICATION FAILED",

                (
                    "The application's verifiable "
                    "signing identity was not "
                    "recognized as trusted."
                ),

                "high",

                player_id,

                "Certificate verification failed."

            )


        elif finding == "attestation":

            security_event(

                "attestation",

                "🛡️ ATTESTATION VERIFICATION FAILED",

                (
                    "Platform integrity information "
                    "could not be accepted."
                ),

                "high",

                player_id,

                "Attestation validation failed."

            )


        elif finding == "device":

            security_event(

                "device",

                "📱 DEVICE INTEGRITY WARNING",

                (
                    "The device integrity information "
                    "did not satisfy the selected "
                    "security policy."
                ),

                "high",

                player_id,

                "Device integrity check failed."

            )


        elif finding == "replay":

            security_event(

                "replay",

                "🔄 REPLAY ATTACK DETECTED",

                (
                    "A nonce was missing, expired, "
                    "or had already been consumed."
                ),

                "critical",

                player_id,

                "Authentication replay protection triggered."

            )


        elif finding == "tamper":

            security_event(

                "tamper",

                "⚠️ INTEGRITY STATE INCONSISTENCY",

                (
                    "Multiple supplied security "
                    "signals were inconsistent."
                ),

                "critical",

                player_id,

                "Possible tampering or malformed security data."

            )


        elif finding == "build":

            security_event(

                "tamper",

                "🏗️ BUILD INTEGRITY WARNING",

                (
                    "Application build metadata "
                    "was inconsistent with the "
                    "expected structure."
                ),

                "warning",

                player_id,

                "Build integrity check failed."

            )


        elif finding == "session":

            security_event(

                "replay",

                "🔒 SESSION VALIDATION FAILED",

                (
                    "The supplied authentication "
                    "session could not be validated."
                ),

                "high",

                player_id,

                "Session invalid or expired."

            )


    if score >= 90:

        security_event(

            "critical",

            "🚨 CRITICAL THREAT SCORE",

            (
                "Gorilla Guard calculated a critical "
                "security threat score."
            ),

            "critical",

            player_id,

            f"Threat score: {score}/100"

        )


# ============================================================
# AUTH DECORATOR
# ============================================================

def require_level(
    minimum_level
):

    def decorator(
        function
    ):

        @wraps(function)
        def wrapper(
            *args,
            **kwargs
        ):

            if DEFAULT_SECURITY_LEVEL < minimum_level:

                return jsonify({

                    "success":
                        False,

                    "error":
                        "Security level unavailable."

                }), 403


            return function(
                *args,
                **kwargs
            )


        return wrapper


    return decorator


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def home():
    return render_template(
        "index.html",
        modules=PRODUCTS,
        targets=TARGETS
    )


# ============================================================
# SECURITY LEVELS
# ============================================================

@app.get(
    "/api/security/levels"
)
def security_levels():

    return jsonify({

        "current":
            DEFAULT_SECURITY_LEVEL,

        "levels": [

            {
                "level":
                    number,

                "name":
                    data["name"],

            }

            for number, data
            in SECURITY_LEVELS.items()

        ],

    })


# ============================================================
# NONCE ENDPOINT
# ============================================================

@app.post(
    "/api/security/nonce"
)
@require_level(2)
def issue_nonce():

    body = request.get_json(
        silent=True
    ) or {}


    player_id = safe_player_id(
        body.get(
            "UserId"
        )
    )


    if player_id == "unknown":

        return jsonify({

            "success":
                False,

            "error":
                "UserId is required."

        }), 400


    nonce = create_nonce(
        player_id
    )


    return jsonify({

        "success":
            True,

        "nonce":
            nonce,

        "expires_in":
            NONCE_LIFETIME,

    })


# ============================================================
# MAIN VERIFICATION
# ============================================================

@app.post(
    "/api/security/verify"
)
def verify():

    body = request.get_json(
        silent=True
    ) or {}


    player_id = safe_player_id(
        body.get(
            "UserId"
        )
    )


    claims = body.get(
        "claims",
        {}
    )


    attestation = body.get(
        "attestation"
    )


    supplied_nonce = body.get(
        "Nonce"
    )


    session_id = body.get(
        "SessionId"
    )


    findings = []


    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    if not security_configuration_ready():

        security_event(

            "critical",

            "⚙️ SECURITY CONFIGURATION ERROR",

            (
                "Gorilla Guard is not configured "
                "with a production package and "
                "trusted signing certificate."
            ),

            "critical",

            player_id,

            "Server security configuration incomplete."

        )


        return jsonify({

            "success":
                False,

            "error":
                "Security configuration incomplete."

        }), 503


    # --------------------------------------------------------
    # Claims
    # --------------------------------------------------------

    if not isinstance(
        claims,
        dict
    ):

        findings.append(
            "tamper"
        )

        claims = {}


    app_state = claims.get(
        "app_state",
        {}
    )


    device_state = claims.get(
        "device_state",
        {}
    )


    # --------------------------------------------------------
    # Application checks
    # --------------------------------------------------------

    findings.extend(
        inspect_application_state(
            app_state
        )
    )


    # --------------------------------------------------------
    # Device checks
    # --------------------------------------------------------

    if DEFAULT_SECURITY_LEVEL >= 2:

        findings.extend(
            inspect_device_state(
                device_state
            )
        )


    # --------------------------------------------------------
    # Tamper checks
    # --------------------------------------------------------

    if DEFAULT_SECURITY_LEVEL >= 3:

        findings.extend(
            detect_tampering(
                claims
            )
        )


    # --------------------------------------------------------
    # Attestation
    # --------------------------------------------------------

    if DEFAULT_SECURITY_LEVEL >= 2:

        findings.extend(
            inspect_attestation(
                attestation
            )
        )


    # --------------------------------------------------------
    # Replay protection
    # --------------------------------------------------------

    if DEFAULT_SECURITY_LEVEL >= 2:

        if not consume_nonce(
            player_id,
            supplied_nonce
        ):

            findings.append(
                "replay"
            )


    # --------------------------------------------------------
    # Session
    # --------------------------------------------------------

    if DEFAULT_SECURITY_LEVEL >= 2:

        if session_id:

            if not validate_session(
                session_id,
                player_id
            ):

                findings.append(
                    "session"
                )


    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    findings = list(
        dict.fromkeys(
            findings
        )
    )


    # --------------------------------------------------------
    # Threat score
    # --------------------------------------------------------

    score = calculate_threat_score(
        findings
    )


    # --------------------------------------------------------
    # Alerts
    # --------------------------------------------------------

    if findings:

        package_id = None


        if isinstance(
            app_state,
            dict
        ):

            package_id = app_state.get(
                "package_id"
            )


        send_detection_alerts(

            player_id,

            package_id,

            findings,

            score

        )


    # --------------------------------------------------------
    # Security decision
    # --------------------------------------------------------

    allowed, score = security_decision(

        DEFAULT_SECURITY_LEVEL,

        findings

    )


    # --------------------------------------------------------
    # Rejected
    # --------------------------------------------------------

    if not allowed:

        return jsonify({

            "success":
                False,

            "authenticated":
                False,

            "security_level":
                DEFAULT_SECURITY_LEVEL,

            "security_level_name":
                SECURITY_LEVELS[
                    DEFAULT_SECURITY_LEVEL
                ]["name"],

            "threat_score":
                score,

            "threat_level":
                threat_level(score),

            "detections":
                findings,

            "message":
                "Security verification failed.",

        }), 403


    # --------------------------------------------------------
    # Session creation
    # --------------------------------------------------------

    session = create_session(

        player_id,

        score

    )


    # --------------------------------------------------------
    # SUCCESS ALERT
    # --------------------------------------------------------

    package_id = None


    if isinstance(
        app_state,
        dict
    ):

        package_id = app_state.get(
            "package_id"
        )


    send_discord(

        "success",

        "🟢 GORILLA GUARD VERIFICATION PASSED",

        (
            "The application successfully "
            "passed the selected Gorilla Guard "
            "security policy."
        ),

        "success",

        fields=[

            {
                "name":
                    "Player",

                "value":
                    f"`{player_id}`",

                "inline":
                    True,

            },

            {
                "name":
                    "Security Level",

                "value":
                    (
                        f"{DEFAULT_SECURITY_LEVEL} — "
                        f"{SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]['name']}"
                    ),

                "inline":
                    True,

            },

            {
                "name":
                    "Threat Score",

                "value":
                    f"{score}/100",

                "inline":
                    True,

            },

            {
                "name":
                    "Package",

                "value":
                    f"`{package_id or 'unknown'}`",

                "inline":
                    False,

            },

            {
                "name":
                    "Result",

                "value":
                    "✅ AUTHENTICATED",

                "inline":
                    False,

            },

        ]

    )


    return jsonify({

        "success":
            True,

        "authenticated":
            True,

        "security_level":
            DEFAULT_SECURITY_LEVEL,

        "security_level_name":
            SECURITY_LEVELS[
                DEFAULT_SECURITY_LEVEL
            ]["name"],

        "threat_score":
            score,

        "threat_level":
            threat_level(score),

        "session_id":
            session,

        "message":
            "Security verification passed.",

    })


# ============================================================
# SESSION CHECK
# ============================================================

@app.post(
    "/api/security/session/check"
)
@require_level(2)
def session_check():

    body = request.get_json(
        silent=True
    ) or {}


    player_id = safe_player_id(
        body.get(
            "UserId"
        )
    )


    session_id = body.get(
        "SessionId"
    )


    valid = validate_session(

        session_id,

        player_id

    )


    if not valid:

        security_event(

            "replay",

            "🔒 SESSION VALIDATION FAILED",

            (
                "A session request was rejected "
                "because the session was invalid "
                "or expired."
            ),

            "high",

            player_id,

            "Invalid session."

        )


        return jsonify({

            "success":
                False,

            "authenticated":
                False,

        }), 403


    return jsonify({

        "success":
            True,

        "authenticated":
            True,

    })


# ============================================================
# DISCORD TEST
# ============================================================

@app.post(
    "/api/security/discord-test/<category>"
)
def discord_test(
    category
):

    if category not in DISCORD_WEBHOOKS:

        return jsonify({

            "success":
                False,

            "error":
                "Invalid Discord category."

        }), 400


    sent = send_discord(

        category,

        "🦍 GORILLA GUARD TEST ALERT",

        (
            "This is a test notification from "
            "the Gorilla Guard Advanced security "
            "system."
        ),

        "info",

        fields=[

            {
                "name":
                    "Category",

                "value":
                    category,

                "inline":
                    True,

            },

            {
                "name":
                    "Security Level",

                "value":
                    (
                        f"{DEFAULT_SECURITY_LEVEL} — "
                        f"{SECURITY_LEVELS[DEFAULT_SECURITY_LEVEL]['name']}"
                    ),

                "inline":
                    True,

            },

        ]

    )


    return jsonify({

        "success":
            sent,

        "category":
            category,

    })


# ============================================================
# SECURITY STATUS
# ============================================================

@app.get(
    "/api/security/status"
)
def security_status():

    return jsonify({

        "service":
            "Gorilla Guard Advanced",

        "online":
            True,

        "security_level":
            DEFAULT_SECURITY_LEVEL,

        "security_level_name":
            SECURITY_LEVELS[
                DEFAULT_SECURITY_LEVEL
            ]["name"],

        "configuration_ready":
            security_configuration_ready(),

        "package_configured":
            bool(
                CONFIG["package_id"]
            ),

        "trusted_certificates":
            len(
                TRUSTED_CERTIFICATES
            ),

        "modules": {

            "apk_integrity":
                True,

            "signature_verification":
                True,

            "keystore_identity":
                True,

            "attestation":
                DEFAULT_SECURITY_LEVEL >= 2,

            "replay_protection":
                DEFAULT_SECURITY_LEVEL >= 2,

            "session_security":
                DEFAULT_SECURITY_LEVEL >= 2,

            "device_integrity":
                DEFAULT_SECURITY_LEVEL >= 2,

            "tamper_detection":
                DEFAULT_SECURITY_LEVEL >= 3,

            "threat_scoring":
                DEFAULT_SECURITY_LEVEL >= 3,

            "critical_escalation":
                DEFAULT_SECURITY_LEVEL >= 3,

            "strict_mode":
                DEFAULT_SECURITY_LEVEL >= 4,

        },

        "discord": {

            category:
                bool(webhook)

            for category, webhook
            in DISCORD_WEBHOOKS.items()

        },

    })


# ============================================================
# HEALTH
# ============================================================

@app.get(
    "/api/health"
)
def health():

    return jsonify({

        "status":
            "online",

        "service":
            "gorilla-guard",

        "security_level":
            DEFAULT_SECURITY_LEVEL,

        "security_level_name":
            SECURITY_LEVELS[
                DEFAULT_SECURITY_LEVEL
            ]["name"],

    })


# ============================================================
# CLEANUP
# ============================================================

def cleanup_security_state():

    now = time.time()


    expired_nonces = [

        player_id

        for player_id, record
        in NONCES.items()

        if (
            now
            - record["created"]
            > NONCE_LIFETIME
        )

    ]


    for player_id in expired_nonces:

        NONCES.pop(
            player_id,
            None
        )


    expired_sessions = [

        session_id

        for session_id, session
        in SESSIONS.items()

        if now > session["expires"]

    ]


    for session_id in expired_sessions:

        SESSIONS.pop(
            session_id,
            None
        )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    logger.info(
        "Starting Gorilla Guard Advanced."
    )

    logger.info(
        "Security level: %s (%s)",
        DEFAULT_SECURITY_LEVEL,
        SECURITY_LEVELS[
            DEFAULT_SECURITY_LEVEL
        ]["name"]
    )

    app.run(

        host="0.0.0.0",

        port=int(
            os.environ.get(
                "PORT",
                "5000"
            )
        ),

        debug=False,

    )

from flask import Flask, render_template, jsonify, request
from pathlib import Path
import os
import base64
import json
import secrets
import time
import hashlib
import requests


# ============================================================
# APP
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

app.config["MAX_CONTENT_LENGTH"] = 512 * 1024


# ============================================================
# GAME CONFIGURATION
# ============================================================
# Put the REAL values in your hosting platform's environment
# variables. Do not put secret keys directly in this file.
# ============================================================

GAME_CONFIG = {
    "titleid": os.environ.get(
        "PLAYFAB_TITLE_ID",
        "YOUR_TITLE_ID"
    ),

    "meta_app_id": os.environ.get(
        "META_APP_ID",
        "YOUR_META_APP_ID"
    ),

    "package_id": os.environ.get(
        "VALID_PACKAGE",
        "YOUR_PACKAGE_ID"
    ),

    "playfab_secret_key": os.environ.get(
        "PLAYFAB_SECRET_KEY"
    ),

    "meta_api_key": os.environ.get(
        "META_API_KEY"
    ),
}


# ============================================================
# DISCORD WEBHOOK SLOTS
# ============================================================

DISCORD_WEBHOOKS = {

    # MOTHERSHIP
    "mothership_pass": os.environ.get(
        "DISCORD_WEBHOOK_MOTHERSHIP_PASS"
    ),

    "mothership_fail": os.environ.get(
        "DISCORD_WEBHOOK_MOTHERSHIP_FAIL"
    ),

    # ANTI-CHEAT
    "anticheat": os.environ.get(
        "DISCORD_WEBHOOK_ANTICHEAT"
    ),

    # REPORTS
    "reports": os.environ.get(
        "DISCORD_WEBHOOK_REPORTS"
    ),

    # SECURITY
    "security": os.environ.get(
        "DISCORD_WEBHOOK_SECURITY"
    ),

    # AUTHENTICATION
    "auth": os.environ.get(
        "DISCORD_WEBHOOK_AUTH"
    ),

    # SYSTEM
    "system": os.environ.get(
        "DISCORD_WEBHOOK_SYSTEM"
    ),
}


# ============================================================
# DISCORD ALERT FUNCTION
# ============================================================

def send_discord_alert(category, message):

    webhook = DISCORD_WEBHOOKS.get(category)

    if not webhook:
        return False

    try:

        response = requests.post(
            webhook,
            json={
                "content": message
            },
            timeout=5,
        )

        return 200 <= response.status_code < 300

    except requests.RequestException:

        return False


# ============================================================
# MOTHERSHIP FAILURE HELPER
# ============================================================

def mothership_failure(
    version,
    user_id,
    reason
):

    send_discord_alert(
        "mothership_fail",
        (
            f"❌ **Mothership {version} FAILED**\n"
            f"Player: `{user_id}`\n"
            f"Reason: {reason}"
        ),
    )

    send_discord_alert(
        "security",
        (
            f"🚨 Mothership {version} security event\n"
            f"Player: `{user_id}`\n"
            f"Reason: {reason}"
        ),
    )

    return jsonify({
        "success": False,
        "BanMessage":
            f"MOTHERSHIP {version} "
            f"AUTHENTICATION FAILED. "
            f"REASON: {reason}",
        "BanExpirationTime": "Unknown",
    }), 403


# ============================================================
# MOTHERSHIP SUCCESS HELPER
# ============================================================

def mothership_success(
    version,
    user_id
):

    send_discord_alert(
        "mothership_pass",
        (
            f"✅ **Mothership {version} PASSED**\n"
            f"Player: `{user_id}`\n"
            f"Integrity authentication passed."
        ),
    )

    send_discord_alert(
        "system",
        (
            f"🦍 Gorilla Guard Mothership {version} "
            f"authentication passed for `{user_id}`."
        ),
    )

    return jsonify({
        "success": True,
        "product":
            f"Gorilla Guard Mothership {version}",
        "message":
            "Integrity authentication passed.",
    })


# ============================================================
# META ATTESTATION
# ============================================================

def verify_attestation(token):

    if not token:
        return None

    meta_api_key = GAME_CONFIG.get(
        "meta_api_key"
    )

    if not meta_api_key:
        return None

    try:

        response = requests.get(
            "https://graph.oculus.com/"
            "platform_integrity/verify",

            params={
                "token": token,
                "access_token": meta_api_key,
            },

            timeout=5,
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException:

        return None


# ============================================================
# CLAIM DECODER
# ============================================================

def decode_claims(claims):

    if not claims:
        return None

    try:

        padding = "=" * (
            -len(claims) % 4
        )

        decoded = base64.urlsafe_b64decode(
            claims + padding
        )

        return json.loads(
            decoded.decode("utf-8")
        )

    except (
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ):

        return None


# ============================================================
# MOTHERSHIP V1
# ============================================================

@app.post(
    "/v1/player/client/auth/complete/QUEST"
)
def mothership_v1():

    body = request.get_json(
        silent=True
    ) or {}

    user_id = str(
        body.get(
            "UserId",
            ""
        )
    ).strip()

    token = str(
        body.get(
            "AttestationToken",
            ""
        )
    ).strip()


    if not user_id:

        return mothership_failure(
            "V1",
            "unknown",
            "Missing UserId."
        )


    if not token:

        return mothership_failure(
            "V1",
            user_id,
            "Missing AttestationToken."
        )


    data = verify_attestation(token)


    if not data:

        return mothership_failure(
            "V1",
            user_id,
            "Attestation verification failed."
        )


    records = data.get(
        "data",
        []
    )


    if not records:

        return mothership_failure(
            "V1",
            user_id,
            "Attestation response contained no data."
        )


    validation = records[0]


    if validation.get(
        "message"
    ) != "success":

        return mothership_failure(
            "V1",
            user_id,
            "Attestation validation failed."
        )


    claims = decode_claims(
        validation.get(
            "claims"
        )
    )


    if not claims:

        return mothership_failure(
            "V1",
            user_id,
            "Invalid attestation claims."
        )


    app_state = claims.get(
        "app_state",
        {}
    )

    device_state = claims.get(
        "device_state",
        {}
    )


    package_id = app_state.get(
        "package_id"
    )

    package_digest = app_state.get(
        "package_cert_sha256_digest"
    )

    integrity_state = device_state.get(
        "device_integrity_state"
    )

    unique_id = device_state.get(
        "unique_id"
    )


    if not package_id:

        return mothership_failure(
            "V1",
            user_id,
            "Package ID missing."
        )


    if package_id != GAME_CONFIG["package_id"]:

        send_discord_alert(
            "anticheat",
            (
                f"🛡️ **Package mismatch detected**\n"
                f"Mothership: V1\n"
                f"Player: `{user_id}`"
            ),
        )

        return mothership_failure(
            "V1",
            user_id,
            "Package ID mismatch."
        )


    if not package_digest:

        return mothership_failure(
            "V1",
            user_id,
            "Package certificate digest missing."
        )


    if not unique_id:

        return mothership_failure(
            "V1",
            user_id,
            "Device identity missing."
        )


    if integrity_state != "Advanced":

        send_discord_alert(
            "anticheat",
            (
                f"🛡️ **Untrusted device detected**\n"
                f"Mothership: V1\n"
                f"Player: `{user_id}`"
            ),
        )

        return mothership_failure(
            "V1",
            user_id,
            "Device integrity was not trusted."
        )


    return mothership_success(
        "V1",
        user_id
    )


# ============================================================
# MOTHERSHIP V2 SECURITY STATE
# ============================================================

pending_nonces = {}

NONCE_LIFETIME = 120


# ============================================================
# CREATE NONCE
# ============================================================

def create_nonce(user_id):

    nonce = secrets.token_urlsafe(
        32
    )

    pending_nonces[user_id] = {
        "nonce": nonce,
        "created": time.time(),
    }

    return nonce


# ============================================================
# GET NONCE
# ============================================================

def get_nonce(user_id):

    record = pending_nonces.get(
        user_id
    )

    if not record:
        return None

    if (
        time.time()
        - record["created"]
        > NONCE_LIFETIME
    ):

        pending_nonces.pop(
            user_id,
            None
        )

        return None

    return record["nonce"]


# ============================================================
# CONSUME NONCE
# ============================================================

def consume_nonce(user_id):

    pending_nonces.pop(
        user_id,
        None
    )


# ============================================================
# MOTHERSHIP V2 NONCE ENDPOINT
# ============================================================

@app.post(
    "/v2/player/client/auth/nonce"
)
def mothership_v2_nonce():

    body = request.get_json(
        silent=True
    ) or {}

    user_id = str(
        body.get(
            "UserId",
            ""
        )
    ).strip()


    if not user_id:

        return jsonify({
            "success": False,
            "error": "Missing UserId."
        }), 400


    nonce = create_nonce(
        user_id
    )


    send_discord_alert(
        "system",
        (
            f"🔐 Mothership V2 issued "
            f"an authentication nonce for "
            f"`{user_id}`."
        ),
    )


    return jsonify({
        "success": True,
        "nonce": nonce,
        "expires_in": NONCE_LIFETIME,
    })


# ============================================================
# MOTHERSHIP V2 AUTHENTICATION
# ============================================================

@app.post(
    "/v2/player/client/auth/complete/QUEST"
)
def mothership_v2():

    body = request.get_json(
        silent=True
    ) or {}


    user_id = str(
        body.get(
            "UserId",
            ""
        )
    ).strip()

    token = str(
        body.get(
            "AttestationToken",
            ""
        )
    ).strip()

    client_nonce = str(
        body.get(
            "Nonce",
            ""
        )
    ).strip()


    if not user_id:

        return mothership_failure(
            "V2",
            "unknown",
            "Missing UserId."
        )


    if not token:

        return mothership_failure(
            "V2",
            user_id,
            "Missing AttestationToken."
        )


    expected_nonce = get_nonce(
        user_id
    )


    if not expected_nonce:

        send_discord_alert(
            "anticheat",
            (
                f"🛡️ **Invalid/expired nonce**\n"
                f"Mothership: V2\n"
                f"Player: `{user_id}`"
            ),
        )

        return mothership_failure(
            "V2",
            user_id,
            "Nonce expired or does not exist."
        )


    if not secrets.compare_digest(
        client_nonce,
        expected_nonce
    ):

        send_discord_alert(
            "anticheat",
            (
                f"🛡️ **Nonce mismatch detected**\n"
                f"Mothership: V2\n"
                f"Player: `{user_id}`"
            ),
        )

        return mothership_failure(
            "V2",
            user_id,
            "Nonce mismatch."
        )


    data = verify_attestation(
        token
    )


    if not data:

        return mothership_failure(
            "V2",
            user_id,
            "Attestation verification failed."
        )


    records = data.get(
        "data",
        []
    )


    if not records:

        return mothership_failure(
            "V2",
            user_id,
            "Attestation response was empty."
        )


    validation = records[0]


    if validation.get(
        "message"
    ) != "success":

        return mothership_failure(
            "V2",
            user_id,
            "Attestation validation failed."
        )


    claims = decode_claims(
        validation.get(
            "claims"
        )
    )


    if not claims:

        return mothership_failure(
            "V2",
            user_id,
            "Invalid attestation claims."
        )


    app_state = claims.get(
        "app_state",
        {}
    )

    device_state = claims.get(
        "device_state",
        {}
    )


    package_id = app_state.get(
        "package_id"
    )

    package_digest = app_state.get(
        "package_cert_sha256_digest"
    )

    integrity_state = device_state.get(
        "device_integrity_state"
    )

    unique_id = device_state.get(
        "unique_id"
    )


    if not package_id:

        return mothership_failure(
            "V2",
            user_id,
            "Package ID missing."
        )


    if package_id != GAME_CONFIG["package_id"]:

        send_discord_alert(
            "anticheat",
            (
                f"🛡️ **Package mismatch detected**\n"
                f"Mothership: V2\n"
                f"Player: `{user_id}`"
            ),
        )

        return mothership_failure(
            "V2",
            user_id,
            "Package ID mismatch."
        )


    if not package_digest:

        return mothership_failure(
            "V2",
            user_id,
            "Package certificate digest missing."
        )


    if not unique_id:

        return mothership_failure(
            "V2",
            user_id,
            "Device identity missing."
        )


    if integrity_state != "Advanced":

        send_discord_alert(
            "anticheat",
            (
                f"🛡️ **Untrusted device detected**\n"
                f"Mothership: V2\n"
                f"Player: `{user_id}`"
            ),
        )

        return mothership_failure(
            "V2",
            user_id,
            "Device integrity was not trusted."
        )


    consume_nonce(
        user_id
    )


    device_reference = hashlib.sha256(
        unique_id.encode("utf-8")
    ).hexdigest()[:24]


    send_discord_alert(
        "mothership_pass",
        (
            f"✅ **Mothership V2 PASSED**\n"
            f"Player: `{user_id}`\n"
            f"Device reference: `{device_reference}`"
        ),
    )


    send_discord_alert(
        "system",
        (
            f"🦍 Mothership V2 authentication "
            f"passed for `{user_id}`."
        ),
    )


    return jsonify({
        "success": True,
        "product":
            "Gorilla Guard Mothership V2",
        "device_reference":
            device_reference,
        "message":
            "Enhanced integrity authentication passed.",
    })


# ============================================================
# MOTHERSHIP CATALOG
# ============================================================

MOTHERSHIP = [

    {
        "id": "mothership-v1",
        "name": "Mothership V1",
        "version": "V1",
        "status": "available",
        "status_text": "AVAILABLE",
        "status_size": "normal",
        "icon": "🚀",
        "category": "Mothership",
        "risk": "Critical",
        "description":
            "Server-side integrity authentication.",
        "tags": [
            "mothership",
            "attestation",
            "integrity",
            "authentication",
        ],
        "required_configuration": [
            "titleid",
            "Meta app id",
            "package_id",
            "playfab_secret_key",
            "meta_api_key",
        ],
    },

    {
        "id": "mothership-v2",
        "name": "Mothership V2",
        "version": "V2",
        "status": "available",
        "status_text": "AVAILABLE",
        "status_size": "normal",
        "icon": "🚀",
        "category": "Mothership",
        "risk": "Critical",
        "description":
            "Enhanced authentication with "
            "nonce-based replay resistance.",
        "tags": [
            "mothership",
            "attestation",
            "nonce",
            "replay",
            "integrity",
        ],
        "required_configuration": [
            "titleid",
            "Meta app id",
            "package_id",
            "playfab_secret_key",
            "meta_api_key",
        ],
    },

    {
        "id": "mothership-v3",
        "name": "Mothership V3",
        "version": "V3",
        "status": "coming_soon",
        "status_text": "COMING SOON",
        "status_size": "huge",
        "icon": "🔒",
        "category": "Mothership",
        "risk": "Critical",
        "description":
            "Advanced Mothership protection.",
        "tags": [
            "mothership",
            "coming-soon",
        ],
    },

    {
        "id": "mothership-v4",
        "name": "Mothership V4",
        "version": "V4",
        "status": "coming_soon",
        "status_text": "COMING SOON",
        "status_size": "huge",
        "icon": "🔒",
        "category": "Mothership",
        "risk": "Critical",
        "description":
            "Next-generation Mothership protection.",
        "tags": [
            "mothership",
            "coming-soon",
        ],
    },

    {
        "id": "mothership-v5",
        "name": "Mothership V5",
        "version": "V5",
        "status": "coming_soon",
        "status_text": "COMING SOON",
        "status_size": "huge",
        "icon": "🔒",
        "category": "Mothership",
        "risk": "Critical",
        "description":
            "Future advanced Mothership protection.",
        "tags": [
            "mothership",
            "coming-soon",
        ],
    },
]


# ============================================================
# OTHER ANTI-CHEAT MODULES
# ============================================================

MODULES = [

    {
        "id": "movement",
        "icon": "🦍",
        "name": "Movement Integrity",
        "category": "Movement",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Server-side validation for impossible "
            "speed, position deltas, and velocity.",
        "tags": [
            "movement",
            "velocity",
            "server",
        ],
        "code": """
# Movement Integrity

MAX_SPEED = 7.0
MAX_DELTA = 2.5


def validate_movement(
    previous_position,
    current_position,
    delta_time
):

    if delta_time <= 0:
        return False

    distance = distance_between(
        previous_position,
        current_position
    )

    speed = distance / delta_time

    return (
        speed <= MAX_SPEED
        and distance <= MAX_DELTA
    )
""",
    },

    {
        "id": "teleport",
        "icon": "⚡",
        "name": "Teleport Detection",
        "category": "Movement",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Flags impossible position changes.",
        "tags": [
            "teleport",
            "position",
        ],
        "code": """
# Teleport Detection

MAX_ALLOWED_DISTANCE = 5.0


def detect_teleport(
    previous_position,
    current_position
):

    distance = distance_between(
        previous_position,
        current_position
    )

    return distance > MAX_ALLOWED_DISTANCE
""",
    },

    {
        "id": "session",
        "icon": "🪪",
        "name": "Session Integrity",
        "category": "Authentication",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Short-lived server sessions with "
            "replay protection.",
        "tags": [
            "session",
            "replay",
        ],
        "code": """
# Session Integrity

SESSION_LIFETIME_SECONDS = 900


def validate_session(session):

    if not session:
        return False

    if session.is_expired():
        return False

    if session.replay_detected():
        return False

    return True
""",
    },

    {
        "id": "rpc",
        "icon": "📡",
        "name": "RPC Spam Guard",
        "category": "Network",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Rate-limits gameplay requests.",
        "tags": [
            "rpc",
            "spam",
            "network",
        ],
        "code": """
# RPC Spam Guard

MAX_REQUESTS_PER_WINDOW = 30
WINDOW_SECONDS = 10


def allow_request(
    player_id,
    limiter
):

    return limiter.allow(
        player_id,
        MAX_REQUESTS_PER_WINDOW,
        WINDOW_SECONDS
    )
""",
    },

    {
        "id": "packet",
        "icon": "📦",
        "name": "Packet Validation",
        "category": "Network",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Validates expected event structures.",
        "tags": [
            "packet",
            "network",
            "state",
        ],
        "code": """
# Packet Validation

REQUIRED_FIELDS = {
    "player_id",
    "event",
    "timestamp"
}


def validate_packet(packet):

    if not isinstance(
        packet,
        dict
    ):
        return False

    return REQUIRED_FIELDS.issubset(
        packet.keys()
    )
""",
    },

    {
        "id": "inventory",
        "icon": "🎒",
        "name": "Inventory Authority",
        "category": "Economy",
        "risk": "Critical",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Keeps inventory changes authoritative.",
        "tags": [
            "inventory",
            "shop",
            "server",
        ],
        "code": """
# Inventory Authority


def grant_item(
    player,
    item_id
):

    if not item_exists(
        item_id
    ):
        return False

    add_item_to_server_inventory(
        player.id,
        item_id
    )

    return True
""",
    },

    {
        "id": "currency",
        "icon": "💎",
        "name": "Currency Authority",
        "category": "Economy",
        "risk": "Critical",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Validates economy operations server-side.",
        "tags": [
            "currency",
            "economy",
        ],
        "code": """
# Currency Authority


def add_currency(
    player_id,
    amount
):

    if amount <= 0:
        return False

    return server_currency_transaction(
        player_id,
        amount
    )
""",
    },

    {
        "id": "reports",
        "icon": "🚨",
        "name": "Report Abuse Guard",
        "category": "Moderation",
        "risk": "Medium",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Flags suspicious report bursts.",
        "tags": [
            "reports",
            "moderation",
        ],
        "code": """
# Report Abuse Guard

REPORT_LIMIT = 10


def check_report_rate(
    player_id,
    report_store
):

    reports = report_store.count_recent(
        player_id
    )

    return reports <= REPORT_LIMIT
""",
    },

    {
        "id": "logging",
        "icon": "📋",
        "name": "Detection Logging",
        "category": "Monitoring",
        "risk": "Medium",
        "status": "available",
        "status_text": "AVAILABLE",
        "description":
            "Stores detection evidence and timestamps.",
        "tags": [
            "logs",
            "evidence",
        ],
        "code": """
# Detection Logging


def log_detection(
    player_id,
    detection_type,
    evidence
):

    record = {
        "player_id": player_id,
        "detection": detection_type,
        "evidence": evidence,
        "timestamp": current_timestamp()
    }

    save_detection_record(
        record
    )

    return record
""",
    },
]


# ============================================================
# COMBINED PRODUCTS
# ============================================================

PRODUCTS = (
    MODULES
    + MOTHERSHIP
)


# ============================================================
# TARGETS
# ============================================================

TARGETS = [

    {
        "id": "vercel-flask",
        "name": "Vercel + Flask",
        "icon": "▲",
        "description":
            "Python Flask backend deployed through Vercel.",
    },

    {
        "id": "playfab",
        "name": "PlayFab",
        "icon": "🎮",
        "description":
            "PlayFab server-side integration target.",
    },
]


# ============================================================
# HOME PAGE
# ============================================================

@app.get("/")
def home():

    return render_template(
        "index.html",
        modules=PRODUCTS,
        targets=TARGETS,
    )


# ============================================================
# CODE PAGE
# ============================================================

@app.get("/code/<product_id>")
def code_page(product_id):

    product = next(
        (
            item
            for item in PRODUCTS
            if item["id"] == product_id
        ),
        None,
    )

    if product is None:

        return (
            "Product not found",
            404
        )


    coming_soon = (
        product.get("status")
        == "coming_soon"
    )


    return render_template(
        "code.html",
        module=product,
        targets=TARGETS,
        coming_soon=coming_soon,
    )


# ============================================================
# MODULE API
# ============================================================

@app.get("/api/modules")
def get_modules():

    output = []

    for product in PRODUCTS:

        public_product = {
            key: value
            for key, value in product.items()
            if key != "code"
        }

        output.append(
            public_product
        )

    return jsonify(output)


# ============================================================
# SINGLE MODULE API
# ============================================================

@app.get("/api/modules/<product_id>")
def get_module(product_id):

    product = next(
        (
            item
            for item in PRODUCTS
            if item["id"] == product_id
        ),
        None,
    )

    if product is None:

        return jsonify({
            "error":
                "Product not found"
        }), 404


    return jsonify(
        product
    )


# ============================================================
# DISCORD STATUS
# ============================================================

@app.get("/api/discord/status")
def discord_status():

    return jsonify({

        category: bool(webhook)

        for category, webhook
        in DISCORD_WEBHOOKS.items()

    })


# ============================================================
# DISCORD TEST
# ============================================================

@app.post("/api/discord/test/<category>")
def test_discord(category):

    if category not in DISCORD_WEBHOOKS:

        return jsonify({
            "success": False,
            "error":
                "Invalid Discord category."
        }), 400


    success = send_discord_alert(
        category,
        "🦍 Gorilla Guard test notification."
    )


    if not success:

        return jsonify({
            "success": False,
            "error":
                "That webhook is not configured "
                "or Discord rejected the request."
        }), 400


    return jsonify({
        "success": True,
        "category": category,
    })


# ============================================================
# TARGET API
# ============================================================

@app.get("/api/targets")
def get_targets():

    return jsonify(
        TARGETS
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():

    return jsonify({

        "status":
            "online",

        "service":
            "gorilla-guard",

        "mothership": {

            "v1":
                "available",

            "v2":
                "available",

            "v3":
                "coming_soon",

            "v4":
                "coming_soon",

            "v5":
                "coming_soon",
        },

        "discord": {

            category:
                bool(webhook)

            for category, webhook
            in DISCORD_WEBHOOKS.items()

        },

    })


# ============================================================
# HELLO WORLD
# ============================================================

@app.get("/hello-world")
def hello_world():

    return (
        "Gorilla Guard Flask backend online."
    )


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True,
    )

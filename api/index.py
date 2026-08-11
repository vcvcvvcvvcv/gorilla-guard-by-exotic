from flask import Flask, render_template, jsonify, request
from pathlib import Path
import os
import json
import base64
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
#
# These are placeholders only.
#
# Configure the real values as server-side environment
# variables. Do NOT put real secret keys in this file.
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
# DISCORD WEBHOOK CONFIGURATION
# ============================================================
#
# FIVE SEPARATE DESTINATIONS
#
# 1. Anti-cheat detections
# 2. Player reports
# 3. Security events
# 4. Authentication failures
# 5. System/server events
#
# The real webhook URLs are environment variables.
# ============================================================

DISCORD_WEBHOOKS = {

    "anticheat": os.environ.get(
        "DISCORD_WEBHOOK_ANTICHEAT"
    ),

    "reports": os.environ.get(
        "DISCORD_WEBHOOK_REPORTS"
    ),

    "security": os.environ.get(
        "DISCORD_WEBHOOK_SECURITY"
    ),

    "auth": os.environ.get(
        "DISCORD_WEBHOOK_AUTH"
    ),

    "system": os.environ.get(
        "DISCORD_WEBHOOK_SYSTEM"
    ),
}


# ============================================================
# DISCORD ALERT HELPER
# ============================================================

def send_discord_alert(
    category,
    message
):
    """
    Sends an alert to the webhook assigned
    to the specified category.
    """

    webhook = DISCORD_WEBHOOKS.get(
        category
    )

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
# SECURITY EVENT LOGGER
# ============================================================

def security_event(
    category,
    message
):

    send_discord_alert(
        category,
        message
    )


# ============================================================
# MOTHERSHIP V1
# ============================================================

MOTHERSHIP_V1 = {

    "id": "mothership-v1",

    "name": "Mothership V1",

    "version": "V1",

    "status": "available",

    "status_text": "AVAILABLE",

    "status_size": "normal",

    "icon": "🚀",

    "category": "Mothership",

    "risk": "Critical",

    "description": (
        "Foundational server-side integrity "
        "authentication with attestation, "
        "package verification, and device "
        "integrity validation."
    ),

    "tags": [
        "mothership",
        "attestation",
        "integrity",
        "authentication",
    ],

    "required_configuration": [
        "titleid",
        "meta_app_id",
        "package_id",
        "playfab_secret_key",
        "meta_api_key",
    ],

    "code": r'''
import os
import base64
import json
import requests

from flask import Flask, jsonify, request


app = Flask(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

PLAYFAB_TITLE_ID = os.environ.get(
    "PLAYFAB_TITLE_ID",
    "YOUR_TITLE_ID"
)

META_APP_ID = os.environ.get(
    "META_APP_ID",
    "YOUR_META_APP_ID"
)

PLAYFAB_SECRET_KEY = os.environ.get(
    "PLAYFAB_SECRET_KEY"
)

META_API_KEY = os.environ.get(
    "META_API_KEY"
)

VALID_PACKAGE = os.environ.get(
    "VALID_PACKAGE",
    "YOUR_PACKAGE_ID"
)


# ============================================================
# FAILURE RESPONSE
# ============================================================

def authentication_failed(reason):

    return jsonify({

        "success": False,

        "BanMessage":
            "MOTHERSHIP V1 AUTHENTICATION FAILED. "
            f"REASON: {reason}",

        "BanExpirationTime":
            "Unknown",

    }), 403


# ============================================================
# META ATTESTATION
# ============================================================

def verify_attestation(token):

    if not token:
        return None

    if not META_API_KEY:
        return None

    try:

        response = requests.get(

            "https://graph.oculus.com/"
            "platform_integrity/verify",

            params={

                "token":
                    token,

                "access_token":
                    META_API_KEY,

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
# AUTHENTICATION
# ============================================================

@app.post(
    "/v1/player/client/auth/complete/QUEST"
)
def mothership_auth():

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

        security_event(
            "auth",
            "Mothership V1 rejected authentication: "
            "missing UserId."
        )

        return authentication_failed(
            "Missing UserId."
        )


    if not token:

        security_event(
            "auth",
            f"Mothership V1 rejected authentication "
            f"for player {user_id}: missing token."
        )

        return authentication_failed(
            "Missing AttestationToken."
        )


    data = verify_attestation(
        token
    )


    if not data:

        security_event(
            "security",
            f"Mothership V1 attestation verification "
            f"failed for player {user_id}."
        )

        return authentication_failed(
            "Attestation verification failed."
        )


    records = data.get(
        "data",
        []
    )


    if not records:

        security_event(
            "security",
            f"Mothership V1 received an empty "
            f"attestation response for {user_id}."
        )

        return authentication_failed(
            "Attestation response contained no data."
        )


    validation = records[0]


    if validation.get(
        "message"
    ) != "success":

        security_event(
            "security",
            f"Mothership V1 rejected invalid "
            f"attestation for {user_id}."
        )

        return authentication_failed(
            "Attestation validation failed."
        )


    claims = decode_claims(
        validation.get(
            "claims"
        )
    )


    if not claims:

        return authentication_failed(
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

        return authentication_failed(
            "Package ID missing."
        )


    if package_id != VALID_PACKAGE:

        security_event(
            "anticheat",
            f"Mothership V1 detected a package "
            f"mismatch for player {user_id}."
        )

        return authentication_failed(
            "Package ID does not match the "
            "configured application."
        )


    if not package_digest:

        return authentication_failed(
            "Package certificate digest missing."
        )


    if not unique_id:

        return authentication_failed(
            "Device identity missing."
        )


    if integrity_state != "Advanced":

        security_event(
            "anticheat",
            f"Mothership V1 rejected an untrusted "
            f"device for player {user_id}."
        )

        return authentication_failed(
            "Device integrity was not trusted."
        )


    security_event(
        "system",
        f"Mothership V1 authentication passed "
        f"for player {user_id}."
    )


    return jsonify({

        "success":
            True,

        "product":
            "Gorilla Guard Mothership V1",

        "message":
            "Integrity authentication passed.",

    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                7080
            )
        )
    )
''',
}


# ============================================================
# MOTHERSHIP V2
# ============================================================

MOTHERSHIP_V2 = {

    "id": "mothership-v2",

    "name": "Mothership V2",

    "version": "V2",

    "status": "available",

    "status_text": "AVAILABLE",

    "status_size": "normal",

    "icon": "🚀",

    "category": "Mothership",

    "risk": "Critical",

    "description": (
        "Enhanced Mothership authentication with "
        "nonce-based replay resistance, stricter "
        "attestation validation, package verification, "
        "and security-event handling."
    ),

    "tags": [
        "mothership",
        "attestation",
        "nonce",
        "replay",
        "integrity",
    ],

    "required_configuration": [
        "titleid",
        "meta_app_id",
        "package_id",
        "playfab_secret_key",
        "meta_api_key",
    ],

    "code": r'''
import os
import base64
import json
import secrets
import time
import hashlib
import requests

from flask import Flask, jsonify, request


app = Flask(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

PLAYFAB_TITLE_ID = os.environ.get(
    "PLAYFAB_TITLE_ID",
    "YOUR_TITLE_ID"
)

META_APP_ID = os.environ.get(
    "META_APP_ID",
    "YOUR_META_APP_ID"
)

PLAYFAB_SECRET_KEY = os.environ.get(
    "PLAYFAB_SECRET_KEY"
)

META_API_KEY = os.environ.get(
    "META_API_KEY"
)

VALID_PACKAGE = os.environ.get(
    "VALID_PACKAGE",
    "YOUR_PACKAGE_ID"
)


# ============================================================
# SECURITY STATE
# ============================================================

pending_nonces = {}

NONCE_LIFETIME = 120


# ============================================================
# FAILURE
# ============================================================

def authentication_failed(reason):

    return jsonify({

        "success":
            False,

        "BanMessage":
            "MOTHERSHIP V2 AUTHENTICATION FAILED. "
            f"REASON: {reason}",

        "BanExpirationTime":
            "Unknown",

    }), 403


# ============================================================
# NONCES
# ============================================================

def create_nonce(user_id):

    nonce = secrets.token_urlsafe(
        32
    )

    pending_nonces[user_id] = {

        "nonce":
            nonce,

        "created":
            time.time(),

    }

    return nonce


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


def consume_nonce(user_id):

    pending_nonces.pop(
        user_id,
        None
    )


# ============================================================
# ATTESTATION
# ============================================================

def verify_attestation(token):

    if not token:
        return None

    if not META_API_KEY:
        return None

    try:

        response = requests.get(

            "https://graph.oculus.com/"
            "platform_integrity/verify",

            params={

                "token":
                    token,

                "access_token":
                    META_API_KEY,

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
# NONCE ENDPOINT
# ============================================================

@app.post(
    "/v2/player/client/auth/nonce"
)
def request_nonce():

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
            "error":
                "Missing UserId."
        }), 400


    nonce = create_nonce(
        user_id
    )


    security_event(
        "system",
        f"Mothership V2 issued an authentication "
        f"nonce for player {user_id}."
    )


    return jsonify({

        "nonce":
            nonce,

        "expires_in":
            NONCE_LIFETIME,

    })


# ============================================================
# AUTHENTICATION
# ============================================================

@app.post(
    "/v2/player/client/auth/complete/QUEST"
)
def mothership_auth():

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

        return authentication_failed(
            "Missing UserId."
        )


    if not token:

        return authentication_failed(
            "Missing AttestationToken."
        )


    expected_nonce = get_nonce(
        user_id
    )


    if not expected_nonce:

        security_event(
            "security",
            f"Mothership V2 rejected an expired "
            f"or missing nonce for {user_id}."
        )

        return authentication_failed(
            "Nonce expired or does not exist."
        )


    if not secrets.compare_digest(
        client_nonce,
        expected_nonce
    ):

        security_event(
            "anticheat",
            f"Mothership V2 detected a nonce "
            f"mismatch for {user_id}."
        )

        return authentication_failed(
            "Nonce mismatch."
        )


    data = verify_attestation(
        token
    )


    if not data:

        return authentication_failed(
            "Attestation verification failed."
        )


    records = data.get(
        "data",
        []
    )


    if not records:

        return authentication_failed(
            "Attestation response was empty."
        )


    validation = records[0]


    if validation.get(
        "message"
    ) != "success":

        security_event(
            "security",
            f"Mothership V2 rejected invalid "
            f"attestation for {user_id}."
        )

        return authentication_failed(
            "Attestation validation failed."
        )


    claims = decode_claims(
        validation.get(
            "claims"
        )
    )


    if not claims:

        return authentication_failed(
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

        return authentication_failed(
            "Package ID missing."
        )


    if package_id != VALID_PACKAGE:

        security_event(
            "anticheat",
            f"Mothership V2 detected a package "
            f"mismatch for {user_id}."
        )

        return authentication_failed(
            "Package ID mismatch."
        )


    if not package_digest:

        return authentication_failed(
            "Package certificate digest missing."
        )


    if not unique_id:

        return authentication_failed(
            "Device identity missing."
        )


    if integrity_state != "Advanced":

        security_event(
            "anticheat",
            f"Mothership V2 rejected an untrusted "
            f"device for {user_id}."
        )

        return authentication_failed(
            "Device integrity was not trusted."
        )


    consume_nonce(
        user_id
    )


    device_reference = hashlib.sha256(
        unique_id.encode("utf-8")
    ).hexdigest()[:24]


    security_event(
        "system",
        f"Mothership V2 authentication passed "
        f"for player {user_id}."
    )


    return jsonify({

        "success":
            True,

        "product":
            "Gorilla Guard Mothership V2",

        "device_reference":
            device_reference,

        "message":
            "Enhanced integrity authentication passed.",

    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                7080
            )
        )
    )
''',
}


# ============================================================
# COMING SOON
# ============================================================

MOTHERSHIP_V3 = {
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
    "tags":
        ["mothership", "coming-soon"],
    "code": None,
}


MOTHERSHIP_V4 = {
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
    "tags":
        ["mothership", "coming-soon"],
    "code": None,
}


MOTHERSHIP_V5 = {
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
    "tags":
        ["mothership", "coming-soon"],
    "code": None,
}


# ============================================================
# MOTHERSHIP CATALOG
# ============================================================

MOTHERSHIP = [
    MOTHERSHIP_V1,
    MOTHERSHIP_V2,
    MOTHERSHIP_V3,
    MOTHERSHIP_V4,
    MOTHERSHIP_V5,
]


# ============================================================
# OTHER MODULES
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
        "status_size": "normal",
        "description":
            "Server-side movement validation.",
        "tags":
            ["movement", "velocity", "server"],
        "code":
            "# Movement Integrity\n\n"
            "MAX_SPEED = 7.0\n"
            "MAX_DELTA = 2.5\n",
    },

    {
        "id": "teleport",
        "icon": "⚡",
        "name": "Teleport Detection",
        "category": "Movement",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "status_size": "normal",
        "description":
            "Detects impossible position changes.",
        "tags":
            ["teleport", "position"],
        "code":
            "# Teleport Detection\n\n"
            "MAX_ALLOWED_DISTANCE = 5.0\n",
    },

    {
        "id": "session",
        "icon": "🪪",
        "name": "Session Integrity",
        "category": "Authentication",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "status_size": "normal",
        "description":
            "Protects server sessions.",
        "tags":
            ["session", "replay"],
        "code":
            "# Session Integrity\n\n"
            "SESSION_LIFETIME_SECONDS = 900\n",
    },

    {
        "id": "rpc",
        "icon": "📡",
        "name": "RPC Spam Guard",
        "category": "Network",
        "risk": "High",
        "status": "available",
        "status_text": "AVAILABLE",
        "status_size": "normal",
        "description":
            "Rate-limits gameplay requests.",
        "tags":
            ["rpc", "spam", "network"],
        "code":
            "# RPC Spam Guard\n\n"
            "MAX_REQUESTS_PER_WINDOW = 30\n",
    },
]


# ============================================================
# COMBINED CATALOG
# ============================================================

PRODUCTS = MODULES + MOTHERSHIP


# ============================================================
# TARGETS
# ============================================================

TARGETS = [

    {
        "id": "vercel-flask",
        "name": "Vercel + Flask",
        "icon": "▲",
        "description":
            "Python Flask backend.",
    },

    {
        "id": "playfab",
        "name": "PlayFab",
        "icon": "🎮",
        "description":
            "PlayFab server integration.",
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

    return jsonify(
        output
    )


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
# DISCORD CONFIGURATION STATUS
# ============================================================

@app.get("/api/discord/status")
def discord_status():

    return jsonify({

        "anticheat":
            bool(
                DISCORD_WEBHOOKS["anticheat"]
            ),

        "reports":
            bool(
                DISCORD_WEBHOOKS["reports"]
            ),

        "security":
            bool(
                DISCORD_WEBHOOKS["security"]
            ),

        "auth":
            bool(
                DISCORD_WEBHOOKS["auth"]
            ),

        "system":
            bool(
                DISCORD_WEBHOOKS["system"]
            ),
    })


# ============================================================
# DISCORD TEST
# ============================================================

@app.post("/api/discord/test/<category>")
def test_discord(category):

    allowed_categories = {
        "anticheat",
        "reports",
        "security",
        "auth",
        "system",
    }

    if category not in allowed_categories:

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
                "Webhook is not configured or "
                "the Discord request failed."
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

            "anticheat":
                bool(
                    DISCORD_WEBHOOKS["anticheat"]
                ),

            "reports":
                bool(
                    DISCORD_WEBHOOKS["reports"]
                ),

            "security":
                bool(
                    DISCORD_WEBHOOKS["security"]
                ),

            "auth":
                bool(
                    DISCORD_WEBHOOKS["auth"]
                ),

            "system":
                bool(
                    DISCORD_WEBHOOKS["system"]
                ),
        },
    })


# ============================================================
# HELLO WORLD
# ============================================================

@app.get("/hello-world")
def hello_world():

    return (
        "Gorilla Guard backend online."
    )


# ============================================================
# RUN
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

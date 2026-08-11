from flask import Flask, render_template, jsonify, request
from pathlib import Path
import hashlib
import os
import re
import time
import uuid
import json
import threading
import urllib.request
import urllib.error


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
# MOTHERSHIP PRODUCTS
# ============================================================
#
# V1 and V2 are available.
# V3/V4/V5 are intentionally marked Coming Soon.
#
# IMPORTANT:
# Never place real Meta/Oculus credentials in source code.
# Use environment variables in your actual deployment.
# ============================================================

MOTHERSHIP = [

    {
        "id": "mothership-v1",
        "name": "Mothership V1",
        "version": "V1",
        "status": "available",
        "icon": "🚀",
        "risk": "Critical",
        "category": "Mothership",
        "description": (
            "Foundational server-side integrity authentication "
            "with attestation validation, package verification, "
            "and device integrity checks."
        ),
        "tags": [
            "mothership",
            "attestation",
            "integrity",
            "authentication",
        ],

        "code": r'''
import os
import json
import base64
import requests

from flask import Flask, jsonify, request


# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)

OCULUS_APP_ID = os.environ.get(
    "OCULUS_APP_ID"
)

OCULUS_APP_SECRET = os.environ.get(
    "OCULUS_APP_SECRET"
)

VALID_PACKAGE = os.environ.get(
    "VALID_PACKAGE",
    "com.company.product"
)


# ============================================================
# HELPERS
# ============================================================

def authentication_failed(reason):
    return jsonify({
        "BanMessage":
            "MOTHERSHIP V1 AUTHENTICATION FAILED. "
            f"REASON: {reason}",

        "BanExpirationTime":
            "Unknown",
    }), 403


def verify_attestation(token):
    if not token:
        return None

    if not OCULUS_APP_ID or not OCULUS_APP_SECRET:
        return None

    url = (
        "https://graph.oculus.com/"
        "platform_integrity/verify"
    )

    try:

        response = requests.get(
            url,
            params={
                "token": token,
                "access_token":
                    OCULUS_APP_SECRET,
            },
            timeout=5,
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException:
        return None


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
# MOTHERSHIP V1 AUTH
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
            "",
        )
    ).strip()

    attestation_token = str(
        body.get(
            "AttestationToken",
            "",
        )
    ).strip()

    if not user_id:
        return authentication_failed(
            "Missing user ID."
        )

    if not attestation_token:
        return authentication_failed(
            "Attestation token was empty."
        )

    data = verify_attestation(
        attestation_token
    )

    if not data:
        return authentication_failed(
            "Attestation service could not "
            "be reached or returned invalid data."
        )

    records = data.get(
        "data",
        []
    )

    if not records:
        return authentication_failed(
            "Attestation response contained "
            "no validation records."
        )

    response_data = records[0]

    if response_data.get(
        "message"
    ) != "success":

        return authentication_failed(
            "Attestation validation failed."
        )

    claims = decode_claims(
        response_data.get(
            "claims"
        )
    )

    if not claims:
        return authentication_failed(
            "Attestation claims could not "
            "be decoded."
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

    integrity_state = device_state.get(
        "device_integrity_state"
    )

    unique_id = device_state.get(
        "unique_id"
    )

    if not unique_id:
        return authentication_failed(
            "Device identity was missing."
        )

    if not package_id:
        return authentication_failed(
            "Package identity was missing."
        )

    if package_id != VALID_PACKAGE:
        return authentication_failed(
            "Package identity was not recognized."
        )

    if integrity_state != "Advanced":
        return authentication_failed(
            "Device integrity state was "
            "not trusted."
        )

    return jsonify({
        "success": True,
        "product": "Gorilla Guard Mothership V1",
        "message":
            "Integrity authentication passed.",
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                7080,
            )
        ),
    )
''',
    },


    {
        "id": "mothership-v2",
        "name": "Mothership V2",
        "version": "V2",
        "status": "available",
        "icon": "🚀",
        "risk": "Critical",
        "category": "Mothership",
        "description": (
            "Enhanced Mothership authentication with "
            "nonce-based replay resistance, stricter "
            "attestation validation, package verification, "
            "and structured security events."
        ),
        "tags": [
            "mothership",
            "attestation",
            "nonce",
            "replay",
            "integrity",
        ],

        "code": r'''
import os
import json
import base64
import hashlib
import secrets
import time
import requests

from flask import Flask, jsonify, request


# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)

OCULUS_APP_SECRET = os.environ.get(
    "OCULUS_APP_SECRET"
)

VALID_PACKAGE = os.environ.get(
    "VALID_PACKAGE",
    "com.company.product"
)

NONCE_LIFETIME = 120


# ============================================================
# SERVER STATE
# ============================================================

pending_nonces = {}


# ============================================================
# HELPERS
# ============================================================

def make_failure(reason):
    return jsonify({
        "BanMessage":
            "MOTHERSHIP V2 AUTHENTICATION FAILED. "
            f"REASON: {reason}",

        "BanExpirationTime":
            "Unknown",
    }), 403


def generate_nonce(user_id):

    nonce = secrets.token_urlsafe(
        32
    )

    pending_nonces[user_id] = {
        "nonce": nonce,
        "created": time.time(),
    }

    return nonce


def get_valid_nonce(user_id):

    record = pending_nonces.get(
        user_id
    )

    if not record:
        return None

    age = (
        time.time()
        - record["created"]
    )

    if age > NONCE_LIFETIME:

        pending_nonces.pop(
            user_id,
            None,
        )

        return None

    return record["nonce"]


def consume_nonce(user_id):

    pending_nonces.pop(
        user_id,
        None,
    )


def verify_attestation(token):

    if not token:
        return None

    if not OCULUS_APP_SECRET:
        return None

    try:

        response = requests.get(
            "https://graph.oculus.com/"
            "platform_integrity/verify",

            params={
                "token": token,
                "access_token":
                    OCULUS_APP_SECRET,
            },

            timeout=5,
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException:
        return None


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


def fingerprint(value):

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


# ============================================================
# NONCE ENDPOINT
# ============================================================

@app.post(
    "/v2/player/client/auth/nonce"
)
def create_auth_nonce():

    body = request.get_json(
        silent=True
    ) or {}

    user_id = str(
        body.get(
            "UserId",
            "",
        )
    ).strip()

    if not user_id:
        return jsonify({
            "error":
                "Missing user ID."
        }), 400

    nonce = generate_nonce(
        user_id
    )

    return jsonify({
        "nonce": nonce,
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
            "",
        )
    ).strip()

    token = str(
        body.get(
            "AttestationToken",
            "",
        )
    ).strip()

    client_nonce = str(
        body.get(
            "Nonce",
            "",
        )
    ).strip()

    if not user_id:
        return make_failure(
            "Missing user ID."
        )

    if not token:
        return make_failure(
            "Missing attestation token."
        )

    expected_nonce = get_valid_nonce(
        user_id
    )

    if not expected_nonce:
        return make_failure(
            "Authentication nonce expired "
            "or does not exist."
        )

    if not secrets.compare_digest(
        client_nonce,
        expected_nonce,
    ):
        return make_failure(
            "Authentication nonce mismatch."
        )

    data = verify_attestation(
        token
    )

    if not data:
        return make_failure(
            "Attestation validation failed."
        )

    records = data.get(
        "data",
        []
    )

    if not records:
        return make_failure(
            "Attestation response was empty."
        )

    result = records[0]

    if result.get(
        "message"
    ) != "success":

        return make_failure(
            "Attestation signature was invalid."
        )

    claims = decode_claims(
        result.get(
            "claims"
        )
    )

    if not claims:
        return make_failure(
            "Attestation claims were invalid."
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
        return make_failure(
            "Package identity missing."
        )

    if package_id != VALID_PACKAGE:
        return make_failure(
            "Package identity mismatch."
        )

    if not package_digest:
        return make_failure(
            "Package certificate digest missing."
        )

    if integrity_state != "Advanced":
        return make_failure(
            "Device integrity was not trusted."
        )

    if not unique_id:
        return make_failure(
            "Device identity missing."
        )

    consume_nonce(
        user_id
    )

    return jsonify({
        "success": True,

        "product":
            "Gorilla Guard Mothership V2",

        "device_reference":
            fingerprint(
                unique_id
            ),

        "message":
            "Enhanced integrity authentication passed.",
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                7080,
            )
        ),
    )
''',
    },


    # ========================================================
    # COMING SOON
    # ========================================================

    {
        "id": "mothership-v3",
        "name": "Mothership V3",
        "version": "V3",
        "status": "coming_soon",
        "icon": "🔒",
        "risk": "Critical",
        "category": "Mothership",
        "description":
            "Advanced Mothership protection.",
        "tags":
            ["mothership", "coming-soon"],
        "code": None,
    },

    {
        "id": "mothership-v4",
        "name": "Mothership V4",
        "version": "V4",
        "status": "coming_soon",
        "icon": "🔒",
        "risk": "Critical",
        "category": "Mothership",
        "description":
            "Next-generation Mothership protection.",
        "tags":
            ["mothership", "coming-soon"],
        "code": None,
    },

    {
        "id": "mothership-v5",
        "name": "Mothership V5",
        "version": "V5",
        "status": "coming_soon",
        "icon": "🔒",
        "risk": "Critical",
        "category": "Mothership",
        "description":
            "Future advanced Mothership protection.",
        "tags":
            ["mothership", "coming-soon"],
        "code": None,
    },
]


# ============================================================
# OTHER GORILLA GUARD MODULES
# ============================================================

MODULES = [
    {
        "id": "movement",
        "icon": "🦍",
        "name": "Movement Integrity",
        "category": "Movement",
        "risk": "High",
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
        "description":
            "Rate-limits gameplay requests.",
        "tags":
            ["rpc", "spam", "network"],
        "code":
            "# RPC Spam Guard\n\n"
            "MAX_REQUESTS_PER_WINDOW = 30\n",
    },

    {
        "id": "inventory",
        "icon": "🎒",
        "name": "Inventory Authority",
        "category": "Economy",
        "risk": "Critical",
        "description":
            "Keeps inventory authoritative.",
        "tags":
            ["inventory", "server"],
        "code":
            "# Inventory Authority\n",
    },

    {
        "id": "currency",
        "icon": "💎",
        "name": "Currency Authority",
        "category": "Economy",
        "risk": "Critical",
        "description":
            "Keeps currency authoritative.",
        "tags":
            ["currency", "economy"],
        "code":
            "# Currency Authority\n",
    },
]


# ============================================================
# COMBINED PRODUCT CATALOG
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
# HOME
# ============================================================

@app.get("/")
def home():

    return render_template(
        "index.html",
        modules=PRODUCTS,
        targets=TARGETS,
    )


# ============================================================
# SEE CODE
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
            404,
        )

    if product.get(
        "status"
    ) == "coming_soon":

        return render_template(
            "code.html",
            module=product,
            targets=TARGETS,
            coming_soon=True,
        )

    return render_template(
        "code.html",
        module=product,
        targets=TARGETS,
        coming_soon=False,
    )


# ============================================================
# PRODUCT API
# ============================================================

@app.get("/api/modules")
def get_modules():

    output = []

    for product in PRODUCTS:

        item = {
            key: value
            for key, value
            in product.items()
            if key != "code"
        }

        output.append(
            item
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
# TARGET API
# ============================================================

@app.get("/api/targets")
def get_targets():

    return jsonify(
        TARGETS
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():

    available = len([
        item
        for item in PRODUCTS
        if item.get("status")
        != "coming_soon"
    ])

    coming_soon = len([
        item
        for item in PRODUCTS
        if item.get("status")
        == "coming_soon"
    ])

    return jsonify({
        "status":
            "online",

        "service":
            "gorilla-guard",

        "available_products":
            available,

        "coming_soon":
            coming_soon,
    })


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
                5000,
            )
        ),
        debug=True,
    )

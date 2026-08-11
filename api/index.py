from flask import Flask, render_template, jsonify, request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)


# ============================================================
# GORILLA GUARD MODULES
# ============================================================

MODULES = [

    {
        "id": "movement",
        "icon": "🦍",
        "name": "Movement Integrity",
        "category": "Movement",
        "risk": "High",
        "description": (
            "Server-side validation for impossible speed, "
            "position deltas, and velocity."
        ),
        "tags": ["movement", "velocity", "server"],
        "code": """# Movement Integrity
# Defensive server-side example

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
"""
    },

    {
        "id": "teleport",
        "icon": "⚡",
        "name": "Teleport Detection",
        "category": "Movement",
        "risk": "High",
        "description": (
            "Flags position changes that exceed "
            "your configured movement model."
        ),
        "tags": ["teleport", "position"],
        "code": """# Teleport Detection

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
"""
    },

    {
        "id": "auth",
        "icon": "🔐",
        "name": "Secure Auto Authentication",
        "category": "Authentication",
        "risk": "Critical",
        "description": (
            "Establishes and validates a trusted "
            "player session when the game connects."
        ),
        "tags": ["auth", "session", "identity"],
        "code": """# Secure Auto Authentication

def establish_session(
    player_id,
    trusted_identity
):
    if not player_id:
        raise ValueError(
            "Missing player ID"
        )

    if not trusted_identity:
        raise PermissionError(
            "Identity could not be verified"
        )

    return create_server_session(
        player_id
    )
"""
    },

    {
        "id": "session",
        "icon": "🪪",
        "name": "Session Integrity",
        "category": "Authentication",
        "risk": "High",
        "description": (
            "Short-lived server sessions with "
            "expiration and replay protection."
        ),
        "tags": ["session", "replay"],
        "code": """# Session Integrity

SESSION_LIFETIME_SECONDS = 900


def validate_session(session):

    if not session:
        return False

    if session.is_expired():
        return False

    if session.replay_detected():
        return False

    return True
"""
    },

    {
        "id": "anti_modding",
        "icon": "🧩",
        "name": "Anti-Lib / Modding Signals",
        "category": "Anti-Modding",
        "risk": "Critical",
        "description": (
            "Collects integrity signals for unexpected "
            "or modified game components."
        ),
        "tags": ["library", "integrity", "modding"],
        "code": """# Anti-Lib / Modding Signals

EXPECTED_BUILD_HASH = "YOUR_BUILD_HASH"


def check_build_integrity(build_hash):
    return (
        build_hash == EXPECTED_BUILD_HASH
    )
"""
    },

    {
        "id": "rpc",
        "icon": "📡",
        "name": "RPC Spam Guard",
        "category": "Network",
        "risk": "High",
        "description": (
            "Rate-limits gameplay requests and flags "
            "abnormal event bursts."
        ),
        "tags": ["rpc", "spam", "network"],
        "code": """# RPC Spam Guard

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
"""
    },

    {
        "id": "packet",
        "icon": "📦",
        "name": "Packet Validation",
        "category": "Network",
        "risk": "High",
        "description": (
            "Validates expected event structure "
            "and server state transitions."
        ),
        "tags": ["packet", "network", "state"],
        "code": """# Packet Validation

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
"""
    },

    {
        "id": "inventory",
        "icon": "🎒",
        "name": "Inventory Authority",
        "category": "Economy",
        "risk": "Critical",
        "description": (
            "Keeps purchases and inventory changes "
            "authoritative on the backend."
        ),
        "tags": ["inventory", "shop", "server"],
        "code": """# Inventory Authority


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
"""
    },

    {
        "id": "currency",
        "icon": "💎",
        "name": "Currency Authority",
        "category": "Economy",
        "risk": "Critical",
        "description": (
            "Prevents client-only currency changes "
            "by validating economy operations server-side."
        ),
        "tags": ["currency", "economy"],
        "code": """# Currency Authority


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
"""
    },

    {
        "id": "reports",
        "icon": "🚨",
        "name": "Report Abuse Guard",
        "category": "Moderation",
        "risk": "Medium",
        "description": (
            "Flags suspicious report bursts "
            "for moderator review."
        ),
        "tags": ["reports", "moderation"],
        "code": """# Report Abuse Guard

REPORT_LIMIT = 10


def check_report_rate(
    player_id,
    report_store
):

    reports = report_store.count_recent(
        player_id
    )

    return reports <= REPORT_LIMIT
"""
    },

    {
        "id": "discord",
        "icon": "🔔",
        "name": "Discord Detection Alerts",
        "category": "Alerts",
        "risk": "High",
        "description": (
            "Sends detection notifications through "
            "a server-side Discord webhook."
        ),
        "tags": ["discord", "webhook", "alerts"],
        "code": """# Discord Detection Alerts
#
# Keep the webhook URL server-side.

import os
import requests


def send_detection_alert(message):

    webhook = os.environ.get(
        "DISCORD_WEBHOOK_URL"
    )

    if not webhook:
        return False

    response = requests.post(
        webhook,
        json={
            "content": message
        },
        timeout=5
    )

    return response.ok
"""
    },

    {
        "id": "logging",
        "icon": "📋",
        "name": "Detection Logging",
        "category": "Monitoring",
        "risk": "Medium",
        "description": (
            "Stores detection evidence, timestamps, "
            "and player/session references."
        ),
        "tags": ["logs", "evidence"],
        "code": """# Detection Logging


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
"""
    }

]


# ============================================================
# BACKEND TARGETS
# ============================================================

TARGETS = [

    {
        "id": "vercel-flask",
        "name": "Vercel + Flask",
        "icon": "▲",
        "description": (
            "Python Flask backend deployed through Vercel."
        )
    },

    {
        "id": "playfab",
        "name": "PlayFab",
        "icon": "🎮",
        "description": (
            "PlayFab server-side integration target."
        )
    }

]


# Temporary in-memory community list.
# For production, use a database.
COMMUNITY_SUBMISSIONS = []


# ============================================================
# HOME PAGE
# ============================================================

@app.get("/")
def home():

    return render_template(
        "index.html",
        modules=MODULES,
        targets=TARGETS
    )


# ============================================================
# SEE CODE PAGE
# ============================================================

@app.get("/code/<module_id>")
def code_page(module_id):

    module = next(
        (
            item
            for item in MODULES
            if item["id"] == module_id
        ),
        None
    )

    if module is None:
        return "Module not found", 404

    return render_template(
        "code.html",
        module=module,
        targets=TARGETS
    )


# ============================================================
# MODULE API
# ============================================================

@app.get("/api/modules")
def get_modules():

    return jsonify(
        MODULES
    )


@app.get("/api/modules/<module_id>")
def get_module(module_id):

    module = next(
        (
            item
            for item in MODULES
            if item["id"] == module_id
        ),
        None
    )

    if module is None:

        return jsonify({
            "error": "Module not found"
        }), 404

    return jsonify(
        module
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
# COMMUNITY SUBMISSIONS
# ============================================================

@app.post("/api/community/submit")
def submit_community_module():

    data = request.get_json(
        silent=True
    ) or {}

    name = str(
        data.get(
            "name",
            ""
        )
    ).strip()

    description = str(
        data.get(
            "description",
            ""
        )
    ).strip()

    code = str(
        data.get(
            "code",
            ""
        )
    ).strip()

    target = str(
        data.get(
            "target",
            ""
        )
    ).strip()

    if (
        not name
        or not description
        or not code
        or not target
    ):

        return jsonify({
            "error": (
                "name, description, code "
                "and target are required"
            )
        }), 400

    if target not in {
        "vercel-flask",
        "playfab"
    }:

        return jsonify({
            "error": "Invalid target"
        }), 400

    submission = {

        "id":
            len(
                COMMUNITY_SUBMISSIONS
            ) + 1,

        "name":
            name,

        "description":
            description,

        "code":
            code,

        "target":
            target,

        "status":
            "Automatic scan pending"
    }

    COMMUNITY_SUBMISSIONS.append(
        submission
    )

    return jsonify({
        "success": True,
        "submission": submission
    }), 201


@app.get("/api/community")
def get_community_modules():

    return jsonify(
        COMMUNITY_SUBMISSIONS
    )


# ============================================================
# HEALTH CHECK
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
        debug=True
    )

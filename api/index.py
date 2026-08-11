from flask import Flask, render_template, jsonify, request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

MODULES = [
    {
        "id": "movement",
        "icon": "🦍",
        "name": "Movement Integrity",
        "category": "Movement",
        "risk": "High",
        "description": "Server-side movement validation for impossible speed, position deltas, and velocity.",
        "tags": ["movement", "velocity", "server"],
    },
    {
        "id": "teleport",
        "icon": "⚡",
        "name": "Teleport Detection",
        "category": "Movement",
        "risk": "High",
        "description": "Flags position changes that exceed your configured movement model.",
        "tags": ["teleport", "position"],
    },
    {
        "id": "auth",
        "icon": "🔐",
        "name": "Secure Auto Authentication",
        "category": "Authentication",
        "risk": "Critical",
        "description": "Automatically establishes and validates a trusted player session when the game connects.",
        "tags": ["auth", "session", "identity"],
    },
    {
        "id": "session",
        "icon": "🪪",
        "name": "Session Integrity",
        "category": "Authentication",
        "risk": "High",
        "description": "Short-lived server sessions with expiration and replay protection.",
        "tags": ["session", "replay"],
    },
    {
        "id": "anti_lib",
        "icon": "🧩",
        "name": "Anti-Lib / Modding Signals",
        "category": "Anti-Modding",
        "risk": "Critical",
        "description": "Collects integrity signals for unexpected or modified game libraries.",
        "tags": ["library", "integrity", "modding"],
    },
    {
        "id": "rpc",
        "icon": "📡",
        "name": "RPC Spam Guard",
        "category": "Network",
        "risk": "High",
        "description": "Rate-limits gameplay requests and flags abnormal event bursts.",
        "tags": ["rpc", "spam", "network"],
    },
    {
        "id": "packet",
        "icon": "📦",
        "name": "Packet Validation",
        "category": "Network",
        "risk": "High",
        "description": "Validates expected packet/event structure and server state transitions.",
        "tags": ["packet", "network", "state"],
    },
    {
        "id": "inventory",
        "icon": "🎒",
        "name": "Inventory Authority",
        "category": "Economy",
        "risk": "Critical",
        "description": "Keeps purchases and inventory changes authoritative on the backend.",
        "tags": ["inventory", "shop", "server"],
    },
    {
        "id": "currency",
        "icon": "💎",
        "name": "Currency Authority",
        "category": "Economy",
        "risk": "Critical",
        "description": "Prevents client-only currency changes by validating economy operations server-side.",
        "tags": ["currency", "economy"],
    },
    {
        "id": "reports",
        "icon": "🚨",
        "name": "Report Abuse Guard",
        "category": "Moderation",
        "risk": "Medium",
        "description": "Flags suspicious report bursts for moderator review.",
        "tags": ["reports", "moderation"],
    },
    {
        "id": "discord",
        "icon": "🔔",
        "name": "Discord Detection Alerts",
        "category": "Alerts",
        "risk": "High",
        "description": "Sends detection notifications through server-side Discord webhooks.",
        "tags": ["discord", "webhook", "alerts"],
    },
    {
        "id": "logging",
        "icon": "📋",
        "name": "Detection Logging",
        "category": "Monitoring",
        "risk": "Medium",
        "description": "Stores detection evidence, timestamps, and player/session references.",
        "tags": ["logs", "evidence"],
    },
]

REVISIONS = [
    {
        "version": "v1.0",
        "name": "Foundation",
        "status": "Archived",
        "changes": ["Movement checks", "Basic rate limiting"],
    },
    {
        "version": "v2.0",
        "name": "Secure Core",
        "status": "Archived",
        "changes": [
            "Authentication",
            "Session validation",
            "Inventory authority",
        ],
    },
    {
        "version": "v3.0",
        "name": "Secure Core+",
        "status": "Current",
        "changes": [
            "Anti-modding signals",
            "Discord alerts",
            "Packet validation",
        ],
    },
]


@app.get("/")
def home():
    return render_template(
        "index.html",
        modules=MODULES,
        revisions=REVISIONS,
    )


@app.get("/api/modules")
def modules():
    return jsonify(MODULES)


@app.get("/api/modules/<module_id>")
def module(module_id):
    item = next(
        (x for x in MODULES if x["id"] == module_id),
        None,
    )

    if item is None:
        return jsonify({"error": "Module not found"}), 404

    return jsonify(item)


@app.get("/api/revisions")
def revisions():
    return jsonify(REVISIONS)


@app.post("/api/revisions")
def create_revision():
    data = request.get_json(silent=True) or {}

    version = str(data.get("version", "")).strip()
    name = str(data.get("name", "")).strip()
    changes = data.get("changes", [])

    if not version or not name or not isinstance(changes, list):
        return jsonify({
            "error": "version, name and changes are required"
        }), 400

    revision = {
        "version": version,
        "name": name,
        "status": "Draft",
        "changes": changes,
    }

    REVISIONS.insert(0, revision)

    return jsonify(revision), 201


@app.get("/hello-world")
def hello_world():
    return "GTAG Anti-Cheat Hub Flask backend online."


# IMPORTANT:
# Vercel detects this top-level variable.
# DO NOT rename it.
app = app

from flask import Flask, render_template, jsonify, request
from pathlib import Path
from copy import deepcopy
from collections import defaultdict
from threading import Lock
import hashlib
import json
import os
import re
import time
import uuid
import urllib.request
import urllib.error


# ============================================================
# PATHS / FLASK
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

app.config["MAX_CONTENT_LENGTH"] = 512 * 1024


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
            "Server-side movement validation for impossible "
            "speed, position deltas, acceleration, and velocity."
        ),
        "tags": ["movement", "velocity", "server", "integrity"],
        "code": r'''# Gorilla Guard — Movement Integrity
#
# Defensive reference implementation.
# Keep authoritative movement checks on your server.

MAX_SPEED = 7.0
MAX_ACCELERATION = 30.0
MAX_POSITION_DELTA = 2.5
MIN_DELTA_TIME = 0.001


def validate_movement(
    previous_position,
    current_position,
    previous_velocity,
    delta_time,
):
    if delta_time < MIN_DELTA_TIME:
        return {
            "valid": False,
            "reason": "invalid_delta_time",
        }

    distance = distance_between(
        previous_position,
        current_position,
    )

    speed = distance / delta_time

    if speed > MAX_SPEED:
        return {
            "valid": False,
            "reason": "impossible_speed",
            "speed": speed,
        }

    if distance > MAX_POSITION_DELTA:
        return {
            "valid": False,
            "reason": "impossible_position_delta",
            "distance": distance,
        }

    return {
        "valid": True,
        "speed": speed,
    }
''',
    },

    {
        "id": "teleport",
        "icon": "⚡",
        "name": "Teleport Detection",
        "category": "Movement",
        "risk": "High",
        "description": (
            "Flags position changes that exceed the configured "
            "movement model."
        ),
        "tags": ["teleport", "position", "movement"],
        "code": r'''# Gorilla Guard — Teleport Detection

MAX_ALLOWED_DISTANCE = 5.0


def detect_teleport(
    previous_position,
    current_position,
    allowed_distance=MAX_ALLOWED_DISTANCE,
):
    distance = distance_between(
        previous_position,
        current_position,
    )

    return {
        "detected": distance > allowed_distance,
        "distance": distance,
        "allowed_distance": allowed_distance,
    }
''',
    },

    {
        "id": "auth",
        "icon": "🔐",
        "name": "Secure Auto Authentication",
        "category": "Authentication",
        "risk": "Critical",
        "description": (
            "Establishes and validates trusted server-side "
            "player sessions."
        ),
        "tags": ["auth", "session", "identity", "server"],
        "code": r'''# Gorilla Guard — Secure Auto Authentication

SESSION_LIFETIME_SECONDS = 900


def establish_session(player_id, trusted_identity):
    if not player_id:
        raise ValueError("Missing player ID")

    if not trusted_identity:
        raise PermissionError(
            "Identity could not be verified"
        )

    return create_server_session(
        player_id=player_id,
        lifetime=SESSION_LIFETIME_SECONDS,
    )


def validate_session(session):
    if not session:
        return False

    if session.is_expired():
        return False

    return session.identity_verified()
''',
    },

    {
        "id": "session",
        "icon": "🪪",
        "name": "Session Integrity",
        "category": "Authentication",
        "risk": "High",
        "description": (
            "Short-lived server sessions with expiration "
            "and replay protection."
        ),
        "tags": ["session", "replay", "integrity"],
        "code": r'''# Gorilla Guard — Session Integrity

SESSION_LIFETIME_SECONDS = 900


def validate_session(session):
    if not session:
        return False

    if session.is_expired():
        return False

    if session.replay_detected():
        return False

    if not session.server_issued:
        return False

    return True
''',
    },

    {
        "id": "anti_modding",
        "icon": "🧩",
        "name": "Anti-Lib / Modding Signals",
        "category": "Anti-Modding",
        "risk": "Critical",
        "description": (
            "Collects integrity signals for unexpected or "
            "modified game components."
        ),
        "tags": ["library", "integrity", "modding", "attestation"],
        "code": r'''# Gorilla Guard — Anti-Lib / Modding Signals
#
# Client integrity signals should be treated as evidence,
# not as the sole source of truth.

EXPECTED_BUILD_HASH = "YOUR_BUILD_HASH"


def check_build_integrity(build_hash):
    if not build_hash:
        return False

    return build_hash == EXPECTED_BUILD_HASH


def evaluate_integrity(
    build_hash,
    attestation_valid,
):
    return {
        "build_valid": check_build_integrity(
            build_hash
        ),
        "attestation_valid": bool(
            attestation_valid
        ),
    }
''',
    },

    {
        "id": "rpc",
        "icon": "📡",
        "name": "RPC Spam Guard",
        "category": "Network",
        "risk": "High",
        "description": (
            "Rate-limits gameplay requests and detects "
            "abnormal event bursts."
        ),
        "tags": ["rpc", "spam", "network", "rate-limit"],
        "code": r'''# Gorilla Guard — RPC Spam Guard

MAX_REQUESTS_PER_WINDOW = 30
WINDOW_SECONDS = 10


def allow_request(player_id, limiter):
    return limiter.allow(
        player_id,
        MAX_REQUESTS_PER_WINDOW,
        WINDOW_SECONDS,
    )


def validate_rpc(player_id, event_name, limiter):
    if not event_name:
        return False

    return allow_request(
        player_id,
        limiter,
    )
''',
    },

    {
        "id": "packet",
        "icon": "📦",
        "name": "Packet Validation",
        "category": "Network",
        "risk": "High",
        "description": (
            "Validates expected event structure and legal "
            "server-state transitions."
        ),
        "tags": ["packet", "network", "state", "schema"],
        "code": r'''# Gorilla Guard — Packet Validation

REQUIRED_FIELDS = {
    "player_id",
    "event",
    "timestamp",
}


def validate_packet(packet):
    if not isinstance(packet, dict):
        return False

    if not REQUIRED_FIELDS.issubset(
        packet.keys()
    ):
        return False

    return True


def validate_state_transition(
    previous_state,
    requested_state,
    allowed_transitions,
):
    allowed = allowed_transitions.get(
        previous_state,
        set(),
    )

    return requested_state in allowed
''',
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
        "tags": ["inventory", "shop", "server", "authority"],
        "code": r'''# Gorilla Guard — Inventory Authority


def grant_item(player, item_id):
    if not item_exists(item_id):
        return False

    if already_owned(
        player.id,
        item_id,
    ):
        return False

    add_item_to_server_inventory(
        player.id,
        item_id,
    )

    return True


def remove_item(player, item_id):
    if not server_inventory_contains(
        player.id,
        item_id,
    ):
        return False

    remove_from_server_inventory(
        player.id,
        item_id,
    )

    return True
''',
    },

    {
        "id": "currency",
        "icon": "💎",
        "name": "Currency Authority",
        "category": "Economy",
        "risk": "Critical",
        "description": (
            "Prevents client-only currency changes by "
            "validating economy operations server-side."
        ),
        "tags": ["currency", "economy", "server", "authority"],
        "code": r'''# Gorilla Guard — Currency Authority


def add_currency(player_id, amount):
    if amount <= 0:
        return False

    return server_currency_transaction(
        player_id=player_id,
        amount=amount,
        source="authorized_server_operation",
    )


def spend_currency(player_id, amount):
    if amount <= 0:
        return False

    balance = get_server_balance(
        player_id
    )

    if balance < amount:
        return False

    return server_currency_transaction(
        player_id=player_id,
        amount=-amount,
        source="authorized_server_operation",
    )
''',
    },

    {
        "id": "reports",
        "icon": "🚨",
        "name": "Report Abuse Guard",
        "category": "Moderation",
        "risk": "Medium",
        "description": (
            "Detects suspicious report bursts and duplicate "
            "report abuse for moderator review."
        ),
        "tags": ["reports", "moderation", "spam", "abuse"],
        "code": r'''# Gorilla Guard — Report Abuse Guard

REPORT_LIMIT = 10
REPORT_WINDOW_SECONDS = 60


def check_report_rate(
    reporter_id,
    report_store,
):
    reports = report_store.count_recent(
        reporter_id,
        REPORT_WINDOW_SECONDS,
    )

    if reports >= REPORT_LIMIT:
        return {
            "suspicious": True,
            "reason": "report_spam",
        }

    return {
        "suspicious": False,
    }


def check_duplicate_report(
    reporter_id,
    target_id,
    report_store,
):
    return report_store.exists_recent_duplicate(
        reporter_id,
        target_id,
    )
''',
    },

    {
        "id": "discord",
        "icon": "🔔",
        "name": "Discord Detection Alerts",
        "category": "Alerts",
        "risk": "High",
        "description": (
            "Sends server-side detection notifications "
            "through a Discord webhook."
        ),
        "tags": ["discord", "webhook", "alerts", "evidence"],
        "code": r'''# Gorilla Guard — Discord Detection Alerts
#
# Keep the webhook URL server-side.
# Never expose it to the game client.

import os
import requests


def send_detection_alert(
    detector,
    severity,
    player_reference,
    evidence,
):
    webhook = os.environ.get(
        "DISCORD_WEBHOOK_URL"
    )

    if not webhook:
        return False

    message = {
        "content": (
            f"🚨 Gorilla Guard Detection\\n"
            f"Detector: {detector}\\n"
            f"Severity: {severity}\\n"
            f"Player: {player_reference}\\n"
            f"Evidence: {evidence}"
        )
    }

    response = requests.post(
        webhook,
        json=message,
        timeout=5,
    )

    return response.ok
''',
    },

    {
        "id": "logging",
        "icon": "📋",
        "name": "Detection Logging",
        "category": "Monitoring",
        "risk": "Medium",
        "description": (
            "Stores detection evidence, timestamps, "
            "player references, and session references."
        ),
        "tags": ["logs", "evidence", "monitoring", "audit"],
        "code": r'''# Gorilla Guard — Detection Logging

def log_detection(
    player_reference,
    session_reference,
    detection_type,
    severity,
    evidence,
):
    record = {
        "player_reference":
            player_reference,

        "session_reference":
            session_reference,

        "detection":
            detection_type,

        "severity":
            severity,

        "evidence":
            evidence,

        "timestamp":
            current_timestamp(),
    }

    save_detection_record(
        record
    )

    return record
''',
    },

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
        ),
    },

    {
        "id": "playfab",
        "name": "PlayFab",
        "icon": "🎮",
        "description": (
            "PlayFab server-side integration target."
        ),
    },

    {
        "id": "mothership-v1",
        "name": "Mothership V1",
        "icon": "🚀",
        "description": (
            "Mothership V1 integration target."
        ),
    },

    {
        "id": "mothership-v2",
        "name": "Mothership V2",
        "icon": "🚀",
        "description": (
            "Mothership V2 integration target."
        ),
    },

    {
        "id": "mothership-v3",
        "name": "Mothership V3",
        "icon": "🚀",
        "description": (
            "Mothership V3 integration target."
        ),
    },

    {
        "id": "mothership-v4",
        "name": "Mothership V4",
        "icon": "🚀",
        "description": (
            "Mothership V4 integration target."
        ),
    },

    {
        "id": "mothership-v5",
        "name": "Mothership V5",
        "icon": "🚀",
        "description": (
            "Mothership V5 integration target."
        ),
    },

]


# ============================================================
# SECURITY STATE
# ============================================================
#
# These dictionaries are suitable for development/testing.
#
# IMPORTANT:
# Vercel serverless instances are not durable databases.
# For production, move these records to a real database.
# ============================================================

STATE_LOCK = Lock()

COMMUNITY_SUBMISSIONS = []
PINNED_MODULES = set()
REPORTS = []
DETECTION_EVENTS = []

PLAYER_SCORES = defaultdict(
    lambda: {
        "score": 0,
        "updated": time.time(),
    }
)

PREVIOUS_EVENT_HASH = ""


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

SCORE_THRESHOLDS = {
    "normal": 0,
    "suspicious": 30,
    "high": 60,
    "critical": 90,
}

SCORE_DECAY_SECONDS = 300

REPORT_LIMIT = 10
REPORT_WINDOW_SECONDS = 60


# ============================================================
# HELPERS
# ============================================================

def now():
    return int(time.time())


def safe_reference(value):
    """
    Creates a non-reversible short reference for logs.
    """
    return hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()[:24]


def get_severity(score):
    if score >= 90:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "suspicious"

    return "normal"


def sanitize_evidence(evidence):
    """
    Prevent obvious secrets from entering logs.
    """

    if not isinstance(evidence, dict):
        return {}

    blocked = {
        "password",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "webhook",
        "webhook_url",
        "secret",
        "api_key",
        "private_key",
    }

    cleaned = {}

    for key, value in evidence.items():

        if str(key).lower() in blocked:
            cleaned[key] = "[REDACTED]"
        else:
            cleaned[key] = value

    return cleaned


def decay_player_score(player_ref):
    record = PLAYER_SCORES.get(
        player_ref
    )

    if not record:
        return

    elapsed = time.time() - record["updated"]

    if elapsed < SCORE_DECAY_SECONDS:
        return

    steps = int(
        elapsed / SCORE_DECAY_SECONDS
    )

    record["score"] = max(
        0,
        record["score"] - (
            steps * 10
        ),
    )

    record["updated"] = time.time()


# ============================================================
# CENTRAL DETECTION ENGINE
# ============================================================

def record_detection(
    *,
    player_id,
    session_id,
    detector,
    points,
    evidence=None,
    requested_action="log",
):
    """
    Central security event pipeline.

    All anti-cheat detections should eventually flow
    through this function.
    """

    global PREVIOUS_EVENT_HASH

    if not detector:
        raise ValueError(
            "detector is required"
        )

    points = int(points)

    if points < 0:
        raise ValueError(
            "points cannot be negative"
        )

    player_ref = safe_reference(
        player_id
    )

    session_ref = safe_reference(
        session_id
    )

    evidence = sanitize_evidence(
        evidence or {}
    )

    with STATE_LOCK:

        decay_player_score(
            player_ref
        )

        record = PLAYER_SCORES[
            player_ref
        ]

        record["score"] += points
        record["updated"] = time.time()

        score = record["score"]

        severity = get_severity(
            score
        )

        action = choose_action(
            severity,
            requested_action,
        )

        event = {
            "event_id":
                uuid.uuid4().hex,

            "timestamp":
                now(),

            "player_reference":
                player_ref,

            "session_reference":
                session_ref,

            "detector":
                detector,

            "severity":
                severity,

            "score":
                score,

            "evidence":
                evidence,

            "action":
                action,
        }

        payload = {
            "previous_hash":
                PREVIOUS_EVENT_HASH,

            "event":
                event,
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

        event_hash = hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

        event["integrity_hash"] = event_hash

        PREVIOUS_EVENT_HASH = event_hash

        DETECTION_EVENTS.append(
            event
        )

    if severity in {
        "high",
        "critical",
    }:
        send_discord_detection(
            event
        )

    return event


def choose_action(
    severity,
    requested_action,
):
    allowed = {
        "log",
        "alert",
        "restrict",
        "kick",
        "ban",
    }

    if requested_action not in allowed:
        requested_action = "log"

    if severity == "normal":
        return "log"

    if severity == "suspicious":
        return (
            "alert"
            if requested_action
            != "log"
            else "log"
        )

    if severity == "high":
        if requested_action in {
            "restrict",
            "kick",
        }:
            return requested_action

        return "alert"

    if requested_action in {
        "restrict",
        "kick",
        "ban",
    }:
        return requested_action

    return "alert"


# ============================================================
# DISCORD ALERTS
# ============================================================

def send_discord_detection(event):
    """
    Sends detection information through a server-side
    Discord webhook.

    Set DISCORD_WEBHOOK_URL in the deployment environment.
    Never put the webhook in frontend JavaScript.
    """

    webhook = os.environ.get(
        "DISCORD_WEBHOOK_URL"
    )

    if not webhook:
        return False

    content = (
        "🚨 **Gorilla Guard Detection**\n"
        f"Detector: `{event['detector']}`\n"
        f"Severity: `{event['severity']}`\n"
        f"Score: `{event['score']}`\n"
        f"Player Ref: `{event['player_reference']}`\n"
        f"Session Ref: `{event['session_reference']}`\n"
        f"Action: `{event['action']}`\n"
        f"Event: `{event['event_id']}`"
    )

    body = json.dumps({
        "content": content
    }).encode("utf-8")

    try:

        req = urllib.request.Request(
            webhook,
            data=body,
            headers={
                "Content-Type":
                    "application/json",
                "User-Agent":
                    "GorillaGuard/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(
            req,
            timeout=5,
        ):
            return True

    except (
        urllib.error.URLError,
        TimeoutError,
    ):
        return False


# ============================================================
# COMMUNITY CODE SAFETY SCANNER
# ============================================================

DANGEROUS_PATTERNS = [

    (
        "shell_execution",
        re.compile(
            r"\b(os\.system|subprocess\."
            r"(Popen|run|call)|shell=True)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "dynamic_execution",
        re.compile(
            r"\b(eval|exec)\s*\(",
            re.IGNORECASE,
        ),
    ),

    (
        "encoded_payload",
        re.compile(
            r"\b(base64|b64decode|marshal|pickle)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "download_and_execute",
        re.compile(
            r"(requests\.(get|post)|urllib)"
            r".{0,250}"
            r"(exec|eval|subprocess|os\.system)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    (
        "filesystem_destruction",
        re.compile(
            r"\b(shutil\.rmtree|os\.remove|"
            r"os\.unlink)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "credential_access",
        re.compile(
            r"(password|token|secret|cookie)"
            r".{0,80}"
            r"(open|read|write)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

]


def scan_submission_code(code):
    """
    Static source inspection only.

    The submitted code is NEVER executed.

    This is a safety filter, not a perfect malware detector.
    """

    findings = []

    if len(code) > 200_000:
        findings.append({
            "type": "size_limit",
            "severity": "high",
        })

    for name, pattern in DANGEROUS_PATTERNS:

        if pattern.search(code):

            findings.append({
                "type": name,
                "severity": "high",
            })

    risk_score = 0

    for finding in findings:

        if finding["severity"] == "high":
            risk_score += 40

        elif finding["severity"] == "medium":
            risk_score += 20

        else:
            risk_score += 5

    if risk_score >= 80:
        status = "blocked"

    elif risk_score >= 40:
        status = "needs_review"

    else:
        status = "passed"

    return {
        "status": status,
        "risk_score": risk_score,
        "findings": findings,
        "scanned_at": now(),
        "scanner_version": "1.0",
    }


# ============================================================
# MODULE LOOKUP
# ============================================================

def find_module(module_id):

    for module in MODULES:

        if module["id"] == module_id:
            return module

    return None


def find_target(target_id):

    for target in TARGETS:

        if target["id"] == target_id:
            return target

    return None


# ============================================================
# HOME PAGE
# ============================================================

@app.get("/")
def home():

    return render_template(
        "index.html",
        modules=MODULES,
        targets=TARGETS,
        pinned=list(
            PINNED_MODULES
        ),
    )


# ============================================================
# SEE CODE PAGE
# ============================================================

@app.get("/code/<module_id>")
def code_page(module_id):

    module = find_module(
        module_id
    )

    if module is None:

        return (
            "Module not found",
            404,
        )

    target_id = request.args.get(
        "target"
    )

    selected_target = None

    if target_id:
        selected_target = find_target(
            target_id
        )

    module_for_template = deepcopy(
        module
    )

    if selected_target:
        module_for_template[
            "selected_target"
        ] = selected_target

    return render_template(
        "code.html",
        module=module_for_template,
        targets=TARGETS,
    )


# ============================================================
# MODULE API
# ============================================================

@app.get("/api/modules")
def get_modules():

    output = []

    for module in MODULES:

        item = {
            key: value
            for key, value
            in module.items()
            if key != "code"
        }

        item["pinned"] = (
            module["id"]
            in PINNED_MODULES
        )

        output.append(
            item
        )

    return jsonify(
        output
    )


@app.get("/api/modules/<module_id>")
def get_module(module_id):

    module = find_module(
        module_id
    )

    if module is None:

        return jsonify({
            "error":
                "Module not found"
        }), 404

    output = deepcopy(
        module
    )

    output["pinned"] = (
        module_id
        in PINNED_MODULES
    )

    return jsonify(
        output
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
# PIN / UNPIN MODULE
# ============================================================

@app.post("/api/modules/<module_id>/pin")
def pin_module(module_id):

    if find_module(module_id) is None:

        return jsonify({
            "error":
                "Module not found"
        }), 404

    with STATE_LOCK:

        PINNED_MODULES.add(
            module_id
        )

    return jsonify({
        "success": True,
        "module_id": module_id,
        "pinned": True,
    })


@app.delete("/api/modules/<module_id>/pin")
def unpin_module(module_id):

    if find_module(module_id) is None:

        return jsonify({
            "error":
                "Module not found"
        }), 404

    with STATE_LOCK:

        PINNED_MODULES.discard(
            module_id
        )

    return jsonify({
        "success": True,
        "module_id": module_id,
        "pinned": False,
    })


@app.get("/api/modules/pinned")
def get_pinned_modules():

    return jsonify([
        module
        for module in MODULES
        if module["id"]
        in PINNED_MODULES
    ])


# ============================================================
# COMMUNITY SUBMISSION
# ============================================================

@app.post("/api/community/submit")
def submit_community_module():

    data = request.get_json(
        silent=True
    ) or {}

    name = str(
        data.get(
            "name",
            "",
        )
    ).strip()

    description = str(
        data.get(
            "description",
            "",
        )
    ).strip()

    code = str(
        data.get(
            "code",
            "",
        )
    )

    target = str(
        data.get(
            "target",
            "",
        )
    ).strip()

    if not name:
        return jsonify({
            "error":
                "name is required"
        }), 400

    if not description:
        return jsonify({
            "error":
                "description is required"
        }), 400

    if not code:
        return jsonify({
            "error":
                "code is required"
        }), 400

    if not target:
        return jsonify({
            "error":
                "target is required"
        }), 400

    if find_target(target) is None:

        return jsonify({
            "error":
                "Invalid target"
        }), 400

    if len(name) > 120:

        return jsonify({
            "error":
                "name is too long"
        }), 400

    if len(description) > 2000:

        return jsonify({
            "error":
                "description is too long"
        }), 400

    if len(code) > 200_000:

        return jsonify({
            "error":
                "code is too large"
        }), 413

    scan = scan_submission_code(
        code
    )

    submission = {

        "id":
            uuid.uuid4().hex,

        "name":
            name,

        "description":
            description,

        "code":
            code,

        "target":
            target,

        "submitted_at":
            now(),

        "status":
            scan["status"],

        "scan":
            scan,

        "content_hash":
            hashlib.sha256(
                code.encode(
                    "utf-8"
                )
            ).hexdigest(),

    }

    with STATE_LOCK:

        COMMUNITY_SUBMISSIONS.append(
            submission
        )

    return jsonify({
        "success": True,
        "submission": {
            key: value
            for key, value
            in submission.items()
            if key != "code"
        },
    }), 201


@app.get("/api/community")
def get_community_modules():

    safe_output = []

    for submission in COMMUNITY_SUBMISSIONS:

        safe_output.append({
            key: value
            for key, value
            in submission.items()
            if key != "code"
        })

    return jsonify(
        safe_output
    )


@app.get("/api/community/<submission_id>")
def get_community_submission(
    submission_id
):

    for submission in COMMUNITY_SUBMISSIONS:

        if submission["id"] == submission_id:

            return jsonify(
                submission
            )

    return jsonify({
        "error":
            "Submission not found"
    }), 404


# ============================================================
# REPORTS
# ============================================================

@app.post("/api/reports")
def create_report():

    data = request.get_json(
        silent=True
    ) or {}

    reporter_id = str(
        data.get(
            "reporter_id",
            "",
        )
    ).strip()

    target_id = str(
        data.get(
            "target_id",
            "",
        )
    ).strip()

    reason = str(
        data.get(
            "reason",
            "",
        )
    ).strip()

    if not reporter_id:
        return jsonify({
            "error":
                "reporter_id is required"
        }), 400

    if not target_id:
        return jsonify({
            "error":
                "target_id is required"
        }), 400

    if not reason:
        return jsonify({
            "error":
                "reason is required"
        }), 400

    reporter_ref = safe_reference(
        reporter_id
    )

    cutoff = now() - REPORT_WINDOW_SECONDS

    recent_reports = [

        report
        for report in REPORTS

        if report["reporter_reference"]
        == reporter_ref

        and report["timestamp"]
        >= cutoff

    ]

    if len(recent_reports) >= REPORT_LIMIT:

        event = record_detection(
            player_id=reporter_id,
            session_id="report-system",
            detector="report_abuse",
            points=15,
            evidence={
                "reports_in_window":
                    len(recent_reports),
                "window_seconds":
                    REPORT_WINDOW_SECONDS,
            },
            requested_action="restrict",
        )

        return jsonify({
            "accepted":
                False,

            "reason":
                "report_rate_limit",

            "detection":
                event,
        }), 429

    report = {

        "id":
            uuid.uuid4().hex,

        "reporter_reference":
            reporter_ref,

        "target_reference":
            safe_reference(
                target_id
            ),

        "reason":
            reason[:1000],

        "timestamp":
            now(),

        "status":
            "queued",

    }

    with STATE_LOCK:

        REPORTS.append(
            report
        )

    return jsonify({
        "success":
            True,

        "report":
            report,
    }), 201


@app.get("/api/reports")
def get_reports():

    return jsonify(
        REPORTS
    )


# ============================================================
# SECURITY EVENT API
# ============================================================

@app.post("/api/security/event")
def security_event():

    data = request.get_json(
        silent=True
    ) or {}

    player_id = str(
        data.get(
            "player_id",
            "",
        )
    ).strip()

    session_id = str(
        data.get(
            "session_id",
            "",
        )
    ).strip()

    detector = str(
        data.get(
            "detector",
            "",
        )
    ).strip()

    points = data.get(
        "points",
        0,
    )

    evidence = data.get(
        "evidence",
        {},
    )

    requested_action = str(
        data.get(
            "action",
            "log",
        )
    ).strip()

    if not player_id:
        return jsonify({
            "error":
                "player_id is required"
        }), 400

    if not session_id:
        return jsonify({
            "error":
                "session_id is required"
        }), 400

    if not detector:
        return jsonify({
            "error":
                "detector is required"
        }), 400

    try:
        points = int(points)

    except (
        TypeError,
        ValueError,
    ):
        return jsonify({
            "error":
                "points must be an integer"
        }), 400

    if points < 0 or points > 100:

        return jsonify({
            "error":
                "points must be between 0 and 100"
        }), 400

    event = record_detection(
        player_id=player_id,
        session_id=session_id,
        detector=detector,
        points=points,
        evidence=evidence,
        requested_action=requested_action,
    )

    return jsonify({
        "success":
            True,

        "event":
            event,
    }), 201


@app.get("/api/security/events")
def security_events():

    limit = request.args.get(
        "limit",
        "100",
    )

    try:
        limit = int(limit)

    except ValueError:
        limit = 100

    limit = max(
        1,
        min(limit, 500),
    )

    return jsonify(
        DETECTION_EVENTS[-limit:]
    )


# ============================================================
# PLAYER SECURITY SCORE
# ============================================================

@app.get("/api/security/score/<player_id>")
def player_security_score(
    player_id
):

    reference = safe_reference(
        player_id
    )

    with STATE_LOCK:

        decay_player_score(
            reference
        )

        record = PLAYER_SCORES.get(
            reference
        )

        score = (
            int(record["score"])
            if record
            else 0
        )

    return jsonify({

        "player_reference":
            reference,

        "score":
            score,

        "severity":
            get_severity(score),

    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/hello-world")
def hello_world():

    return (
        "Gorilla Guard Flask backend online."
    )


@app.get("/api/health")
def health():

    return jsonify({

        "status":
            "online",

        "service":
            "gorilla-guard",

        "version":
            "2.0",

        "modules":
            len(MODULES),

        "targets":
            len(TARGETS),

        "scanner":
            "static",

    })


# ============================================================
# LOCAL DEVELOPMENT
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

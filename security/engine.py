"""
Gorilla Guard Security Engine

Centralized defensive detection, scoring, and evidence handling.

Important:
- Keep this code server-side.
- Do not put secrets, webhook URLs, passwords, or tokens here.
- Detection events should contain only the minimum information
  necessary for security and moderation.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, asdict
from threading import Lock
from typing import Any, Dict, Optional


# ============================================================
# CONFIGURATION
# ============================================================

SCORE_DECAY_SECONDS = 300

SEVERITY_THRESHOLDS = {
    "normal": 0,
    "suspicious": 30,
    "high": 60,
    "critical": 90,
}


# ============================================================
# DETECTION EVENT
# ============================================================

@dataclass
class DetectionEvent:

    event_id: str
    timestamp: int

    player_ref: str
    session_ref: str

    detector: str
    severity: str

    score: int

    evidence: Dict[str, Any]

    action: str = "log"


# ============================================================
# SECURITY ENGINE
# ============================================================

class SecurityEngine:

    def __init__(self):

        self._lock = Lock()

        self._scores: Dict[str, Dict[str, Any]] = {}

        self._events: list[DetectionEvent] = []

        self._previous_hash = ""


    # --------------------------------------------------------
    # EVENT ID
    # --------------------------------------------------------

    @staticmethod
    def _event_id() -> str:

        return uuid.uuid4().hex


    # --------------------------------------------------------
    # SAFE PLAYER REFERENCE
    # --------------------------------------------------------

    @staticmethod
    def player_reference(player_id: str) -> str:

        """
        Creates a non-reversible reference for logs.

        Do not store raw authentication credentials
        or sensitive client secrets.
        """

        return hashlib.sha256(
            player_id.encode("utf-8")
        ).hexdigest()[:24]


    # --------------------------------------------------------
    # SESSION REFERENCE
    # --------------------------------------------------------

    @staticmethod
    def session_reference(session_id: str) -> str:

        return hashlib.sha256(
            session_id.encode("utf-8")
        ).hexdigest()[:24]


    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    @staticmethod
    def severity_for_score(score: int) -> str:

        if score >= 90:
            return "critical"

        if score >= 60:
            return "high"

        if score >= 30:
            return "suspicious"

        return "normal"


    # --------------------------------------------------------
    # SCORE DECAY
    # --------------------------------------------------------

    def _apply_decay(self, player_ref: str):

        record = self._scores.get(player_ref)

        if not record:
            return

        now = time.time()

        elapsed = now - record["updated"]

        if elapsed < SCORE_DECAY_SECONDS:
            return

        decay_steps = int(
            elapsed / SCORE_DECAY_SECONDS
        )

        record["score"] = max(
            0,
            record["score"] - (
                decay_steps * 10
            )
        )

        record["updated"] = now


    # --------------------------------------------------------
    # ADD DETECTION
    # --------------------------------------------------------

    def report(

        self,

        *,
        player_id: str,
        session_id: str,

        detector: str,
        points: int,

        evidence: Optional[
            Dict[str, Any]
        ] = None,

        requested_action: str = "log",

    ) -> DetectionEvent:

        """
        Record one server-side security signal.

        The caller supplies a detection signal.
        The engine calculates the player's accumulated
        security score and severity.
        """

        if not detector:
            raise ValueError(
                "detector is required"
            )

        if points < 0:
            raise ValueError(
                "points cannot be negative"
            )

        evidence = evidence or {}

        player_ref = self.player_reference(
            player_id
        )

        session_ref = self.session_reference(
            session_id
        )

        with self._lock:

            self._apply_decay(
                player_ref
            )

            record = self._scores.setdefault(
                player_ref,
                {
                    "score": 0,
                    "updated": time.time()
                }
            )

            record["score"] += points
            record["updated"] = time.time()

            severity = self.severity_for_score(
                record["score"]
            )

            action = self._safe_action(
                severity,
                requested_action
            )

            event = DetectionEvent(

                event_id=self._event_id(),

                timestamp=int(
                    time.time()
                ),

                player_ref=player_ref,

                session_ref=session_ref,

                detector=detector,

                severity=severity,

                score=record["score"],

                evidence=self._sanitize_evidence(
                    evidence
                ),

                action=action,
            )

            self._events.append(
                event
            )

            self._previous_hash = (
                self._event_hash(event)
            )

            return event


    # --------------------------------------------------------
    # ACTION POLICY
    # --------------------------------------------------------

    @staticmethod
    def _safe_action(
        severity: str,
        requested_action: str
    ) -> str:

        """
        Prevents individual detectors from blindly
        forcing destructive actions.

        Server owners can later configure this policy.
        """

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
                in {"alert", "restrict",
                    "kick", "ban"}
                else "log"
            )

        if severity == "high":
            return (
                requested_action
                if requested_action
                in {"alert", "restrict", "kick"}
                else "alert"
            )

        # Critical
        return (
            requested_action
            if requested_action
            in {
                "alert",
                "restrict",
                "kick",
                "ban"
            }
            else "alert"
        )


    # --------------------------------------------------------
    # EVIDENCE SANITIZATION
    # --------------------------------------------------------

    @staticmethod
    def _sanitize_evidence(
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:

        """
        Remove obvious secrets before evidence reaches
        the logging system.
        """

        blocked_keys = {
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
        }

        cleaned = {}

        for key, value in evidence.items():

            normalized = str(
                key
            ).lower()

            if normalized in blocked_keys:
                cleaned[key] = "[REDACTED]"
                continue

            cleaned[key] = value

        return cleaned


    # --------------------------------------------------------
    # TAMPER-EVIDENT EVENT HASH
    # --------------------------------------------------------

    def _event_hash(
        self,
        event: DetectionEvent
    ) -> str:

        payload = {
            "previous_hash":
                self._previous_hash,

            "event":
                asdict(event),
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()


    # --------------------------------------------------------
    # RECENT EVENTS
    # --------------------------------------------------------

    def recent_events(
        self,
        limit: int = 100
    ) -> list[Dict[str, Any]]:

        if limit <= 0:
            return []

        limit = min(
            limit,
            1000
        )

        with self._lock:

            events = self._events[
                -limit:
            ]

            return [
                asdict(event)
                for event in events
            ]


    # --------------------------------------------------------
    # PLAYER SCORE
    # --------------------------------------------------------

    def player_score(
        self,
        player_id: str
    ) -> int:

        player_ref = self.player_reference(
            player_id
        )

        with self._lock:

            self._apply_decay(
                player_ref
            )

            record = self._scores.get(
                player_ref
            )

            if not record:
                return 0

            return int(
                record["score"]
            )


# ============================================================
# SINGLE SERVER-SIDE ENGINE
# ============================================================

security_engine = SecurityEngine()

"""
Token-based message authentication for ROS 2 topics.

The threat this addresses: ROS 2's default DDS configuration accepts any message
published to a topic. A node that knows the topic name can inject commands —
node spoofing — and a subscriber has no way to tell a spoofed command from a
genuine one. The dissertation demonstrated the vulnerability; this module is the
fix.

The scheme:

  - Trusted publishers and subscribers share a secret key.
  - Each command is wrapped with an HMAC-SHA256 tag computed over the command
    fields, a monotonic counter and a timestamp.
  - A subscriber accepts a command only if the tag verifies, the counter has
    advanced (blocking replay of a captured message) and the timestamp is
    recent (bounding how long a captured message stays useful).

HMAC rather than encryption because the goal here is authenticity and integrity
— proving a command came from a holder of the key and was not altered — not
secrecy. A velocity setpoint is not confidential; accepting a forged one is the
danger.

This module has no ROS dependency, so the identical logic runs in the ROS nodes
and in the standalone simulation, and can be unit-tested without a ROS install.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass


TAG_BYTES = 32          # full SHA-256
DEFAULT_MAX_AGE_S = 2.0  # a message older than this is rejected


def _canonical(payload: dict) -> bytes:
    """
    Deterministic bytes for a payload, so signer and verifier hash the same thing.

    sort_keys and fixed separators mean dict ordering and whitespace cannot
    change the result. Everything the subscriber will act on is inside here.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(key: bytes, command: dict, counter: int, timestamp: float | None = None) -> dict:
    """Wrap a command with a counter, timestamp and HMAC tag."""
    envelope = {
        "command": command,
        "counter": counter,
        "timestamp": time.time() if timestamp is None else timestamp,
    }
    tag = hmac.new(key, _canonical(envelope), hashlib.sha256).hexdigest()
    return {**envelope, "hmac": tag}


class VerificationError(Exception):
    """Raised when a message fails any authentication check. The reason is the message."""


@dataclass
class Verifier:
    """
    Stateful verifier for one command stream.

    It remembers the highest counter it has accepted, which is what makes replay
    detection work: a captured genuine message carries an old counter and is
    refused on resend.
    """

    key: bytes
    max_age_s: float = DEFAULT_MAX_AGE_S
    last_counter: int = -1

    def verify(self, message: dict, now: float | None = None) -> dict:
        """Return the command if the message is authentic, else raise VerificationError."""
        now = time.time() if now is None else now

        for field in ("command", "counter", "timestamp", "hmac"):
            if field not in message:
                raise VerificationError(f"missing field: {field}")

        # 1. Authenticity and integrity. Recompute the tag over everything except
        #    the tag itself and compare in constant time.
        envelope = {k: message[k] for k in ("command", "counter", "timestamp")}
        expected = hmac.new(self.key, _canonical(envelope), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(message["hmac"])):
            raise VerificationError("bad HMAC (forged, altered, or wrong key)")

        # 2. Freshness. Bounds how long a sniffed message remains usable.
        age = now - float(message["timestamp"])
        if age > self.max_age_s:
            raise VerificationError(f"stale message ({age:.2f}s old)")
        if age < -self.max_age_s:
            raise VerificationError("timestamp is in the future")

        # 3. Replay. The counter must strictly advance.
        counter = int(message["counter"])
        if counter <= self.last_counter:
            raise VerificationError(
                f"replay or out-of-order (counter {counter} <= last {self.last_counter})")

        self.last_counter = counter
        return message["command"]


class SigningPublisher:
    """Convenience wrapper that maintains the counter for a publisher."""

    def __init__(self, key: bytes):
        self.key = key
        self._counter = 0

    def wrap(self, command: dict) -> dict:
        self._counter += 1
        return sign(self.key, command, self._counter)

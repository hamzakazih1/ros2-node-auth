"""
Standalone simulation of a node-spoofing attack on a ROS-style command topic,
and the token-authentication defence that stops it.

No ROS install is needed: a tiny in-process message bus stands in for a DDS
topic, so the attack and the defence can be demonstrated and tested anywhere.
The nodes here use the same message_auth module as the real ROS 2 nodes in
ros2_ws/, so what this proves about the logic holds there too.

Scenario: a robot base subscribes to /cmd_vel. A legitimate controller drives
it. An attacker who knows the topic name injects its own commands.

Run:
    python sim/simulate.py                 # full narrated demo
    python sim/simulate.py --scenario unsecured
    python sim/simulate.py --scenario secured
    python sim/simulate.py --scenario replay
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "ros2_ws" / "src" / "secure_ros_demo"))
from secure_ros_demo.message_auth import SigningPublisher, Verifier, VerificationError


# --------------------------------------------------------------- message bus

class Topic:
    """A minimal stand-in for a DDS topic: publishers push, subscribers are called."""

    def __init__(self, name: str):
        self.name = name
        self._subscribers = []

    def subscribe(self, callback):
        self._subscribers.append(callback)

    def publish(self, message):
        # Every subscriber sees every message, exactly as an open DDS topic does.
        for callback in self._subscribers:
            callback(message)


# ------------------------------------------------------------------- robot

class RobotBase:
    """
    The subscriber under attack. Holds the physical state a spoofed command
    would corrupt: its commanded velocity.
    """

    SAFE_MAX = 2.0  # m/s; a plausible ceiling for a factory AGV

    def __init__(self, verifier: Verifier | None = None):
        self.verifier = verifier
        self.velocity = 0.0
        self.accepted = 0
        self.rejected = 0
        self.log = []

    def on_message(self, message):
        if self.verifier is None:
            # Unsecured: whatever arrives is obeyed. This is ROS 2's default.
            self._apply(message["command"], source="unauthenticated")
            return
        try:
            command = self.verifier.verify(message)
        except VerificationError as exc:
            self.rejected += 1
            self.log.append(("REJECT", str(exc)))
            return
        self._apply(command, source="verified")

    def _apply(self, command, source):
        self.accepted += 1
        self.velocity = command.get("linear_x", 0.0)
        flag = "  << UNSAFE" if abs(self.velocity) > self.SAFE_MAX else ""
        self.log.append(("ACCEPT", f"{source}: linear_x={self.velocity}{flag}"))


# --------------------------------------------------------------- scenarios

def _print_log(robot: RobotBase):
    for verdict, detail in robot.log:
        mark = "ok " if verdict == "ACCEPT" else "no "
        print(f"    [{mark}] {detail if verdict=='ACCEPT' else 'rejected: ' + detail}")
    print(f"    accepted {robot.accepted}, rejected {robot.rejected}, "
          f"final velocity {robot.velocity} m/s")


def scenario_unsecured():
    """Default ROS 2: the attacker's command is obeyed."""
    print("\n=== UNSECURED (ROS 2 default DDS) ===")
    topic = Topic("/cmd_vel")
    robot = RobotBase(verifier=None)
    topic.subscribe(robot.on_message)

    print("  legitimate controller commands 1.0 m/s")
    topic.publish({"command": {"linear_x": 1.0}})

    print("  attacker injects 9.0 m/s (well over the 2.0 m/s safe limit)")
    topic.publish({"command": {"linear_x": 9.0}})

    _print_log(robot)
    assert robot.velocity == 9.0, "attack should have succeeded here"
    print("  RESULT: the spoofed command was obeyed. The robot is unsafe.")
    return robot


def scenario_secured(key=b"shared-secret-key-32-bytes-long!!"):
    """With token auth: the legitimate command is accepted, the spoof is refused."""
    print("\n=== SECURED (token authentication) ===")
    topic = Topic("/cmd_vel")
    robot = RobotBase(verifier=Verifier(key))
    topic.subscribe(robot.on_message)
    controller = SigningPublisher(key)

    print("  legitimate controller signs and sends 1.0 m/s")
    topic.publish(controller.wrap({"linear_x": 1.0}))

    print("  attacker injects 9.0 m/s with no valid tag")
    topic.publish({"command": {"linear_x": 9.0}, "counter": 999,
                   "timestamp": time.time(), "hmac": "0" * 64})

    print("  attacker guesses a key and re-signs 9.0 m/s")
    wrong = SigningPublisher(b"attacker-guessed-key-wrong-32byte")
    topic.publish(wrong.wrap({"linear_x": 9.0}))

    print("  legitimate controller sends 0.5 m/s")
    topic.publish(controller.wrap({"linear_x": 0.5}))

    _print_log(robot)
    assert robot.velocity == 0.5, "only legitimate commands should take effect"
    assert robot.rejected == 2
    print("  RESULT: both spoof attempts refused; only signed commands obeyed.")
    return robot


def scenario_replay(key=b"shared-secret-key-32-bytes-long!!"):
    """The attacker captures a genuine signed message and resends it."""
    print("\n=== REPLAY (attacker resends a captured genuine message) ===")
    topic = Topic("/cmd_vel")
    robot = RobotBase(verifier=Verifier(key))
    topic.subscribe(robot.on_message)
    controller = SigningPublisher(key)

    print("  controller sends a genuine 1.0 m/s; attacker sniffs it off the wire")
    genuine = controller.wrap({"linear_x": 1.0})
    captured = dict(genuine)
    topic.publish(genuine)

    print("  attacker replays the identical captured message")
    topic.publish(captured)

    _print_log(robot)
    assert robot.accepted == 1 and robot.rejected == 1
    print("  RESULT: the replay was refused because its counter did not advance.")
    return robot


SCENARIOS = {"unsecured": scenario_unsecured,
             "secured": scenario_secured,
             "replay": scenario_replay}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario", choices=list(SCENARIOS) + ["all"], default="all")
    args = ap.parse_args(argv)

    if args.scenario == "all":
        scenario_unsecured()
        scenario_secured()
        scenario_replay()
        print("\nSummary: the attack succeeds without authentication and fails with it,")
        print("against forgery, key-guessing and replay.")
    else:
        SCENARIOS[args.scenario]()
    return 0


if __name__ == "__main__":
    sys.exit(main())

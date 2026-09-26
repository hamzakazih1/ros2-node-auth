"""
Tests for the message-authentication logic and the attack simulation.

    python -m unittest discover tests -v
"""

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws" / "src" / "secure_ros_demo"))
sys.path.insert(0, str(ROOT / "sim"))

from secure_ros_demo.message_auth import (
    SigningPublisher, Verifier, VerificationError, sign)
import simulate

KEY = b"a" * 32
OTHER = b"b" * 32


class TestVerification(unittest.TestCase):

    def setUp(self):
        self.pub = SigningPublisher(KEY)
        self.ver = Verifier(KEY)

    def test_genuine_message_accepted(self):
        msg = self.pub.wrap({"linear_x": 1.0})
        self.assertEqual(self.ver.verify(msg), {"linear_x": 1.0})

    def test_forged_tag_rejected(self):
        msg = self.pub.wrap({"linear_x": 1.0})
        msg["hmac"] = "0" * 64
        with self.assertRaises(VerificationError):
            self.ver.verify(msg)

    def test_wrong_key_rejected(self):
        msg = SigningPublisher(OTHER).wrap({"linear_x": 9.0})
        with self.assertRaises(VerificationError):
            self.ver.verify(msg)

    def test_altered_command_rejected(self):
        """The attacker keeps the tag but changes the velocity."""
        msg = self.pub.wrap({"linear_x": 1.0})
        msg["command"]["linear_x"] = 9.0            # tamper after signing
        with self.assertRaises(VerificationError):
            self.ver.verify(msg)

    def test_replay_rejected(self):
        msg = self.pub.wrap({"linear_x": 1.0})
        self.ver.verify(msg)
        with self.assertRaises(VerificationError) as cm:
            self.ver.verify(msg)
        self.assertIn("replay", str(cm.exception))

    def test_out_of_order_rejected(self):
        first = self.pub.wrap({"linear_x": 1.0})
        second = self.pub.wrap({"linear_x": 2.0})
        self.ver.verify(second)                     # accept counter 2
        with self.assertRaises(VerificationError):
            self.ver.verify(first)                  # counter 1 now too old

    def test_stale_message_rejected(self):
        old = sign(KEY, {"linear_x": 1.0}, counter=1, timestamp=time.time() - 10)
        with self.assertRaises(VerificationError) as cm:
            self.ver.verify(old)
        self.assertIn("stale", str(cm.exception))

    def test_future_message_rejected(self):
        future = sign(KEY, {"linear_x": 1.0}, counter=1, timestamp=time.time() + 10)
        with self.assertRaises(VerificationError):
            self.ver.verify(future)

    def test_missing_field_rejected(self):
        with self.assertRaises(VerificationError):
            self.ver.verify({"command": {"linear_x": 1.0}})  # no counter/timestamp/hmac

    def test_constant_time_comparison_used(self):
        """Guards against reintroducing a plain == comparison of tags."""
        import inspect
        from secure_ros_demo import message_auth
        source = inspect.getsource(message_auth.Verifier.verify)
        self.assertIn("compare_digest", source)


class TestScenarios(unittest.TestCase):

    def test_unsecured_attack_succeeds(self):
        robot = simulate.scenario_unsecured()
        self.assertEqual(robot.velocity, 9.0)
        self.assertGreater(robot.velocity, robot.SAFE_MAX)

    def test_secured_blocks_spoof(self):
        robot = simulate.scenario_secured()
        self.assertEqual(robot.velocity, 0.5)
        self.assertEqual(robot.rejected, 2)
        self.assertLessEqual(robot.velocity, robot.SAFE_MAX)

    def test_replay_blocked(self):
        robot = simulate.scenario_replay()
        self.assertEqual(robot.accepted, 1)
        self.assertEqual(robot.rejected, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

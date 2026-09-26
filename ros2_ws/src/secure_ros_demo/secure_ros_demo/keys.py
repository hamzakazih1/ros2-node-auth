"""Load the shared key from SECURE_ROS_KEY, or a bundled demo key for convenience."""
import os

_DEMO_KEY = b"demo-shared-key-not-for-production-use!"[:32].ljust(32, b"!")


def load_shared_key() -> bytes:
    env = os.environ.get("SECURE_ROS_KEY", "").encode()
    if env:
        return env[:32].ljust(32, b"\0")
    return _DEMO_KEY

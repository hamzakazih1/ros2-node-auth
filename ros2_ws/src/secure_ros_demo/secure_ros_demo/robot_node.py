"""
Robot base: subscribes to /cmd_vel and applies commands.

--secure (the default via the launch file) verifies every message and refuses
anything that is not a fresh, correctly signed, non-replayed command. Without
it, the node behaves like a default ROS 2 subscriber and obeys whatever arrives.

    ros2 run secure_ros_demo robot --ros-args -p secure:=true
"""
import rclpy
from rclpy.node import Node
from std_msgs.msg import String
import json
from secure_ros_demo.message_auth import Verifier, VerificationError
from secure_ros_demo.keys import load_shared_key

SAFE_MAX = 2.0


class Robot(Node):
    def __init__(self):
        super().__init__("robot")
        self.declare_parameter("secure", True)
        self.secure = self.get_parameter("secure").value
        self.verifier = Verifier(load_shared_key()) if self.secure else None
        self.velocity = 0.0
        self.sub = self.create_subscription(String, "/cmd_vel", self.on_msg, 10)
        self.get_logger().info(f"robot up: secure={self.secure}")

    def on_msg(self, msg):
        data = json.loads(msg.data)
        if self.verifier is None:
            self.apply(data["command"], "unauthenticated")
            return
        try:
            command = self.verifier.verify(data)
        except VerificationError as exc:
            self.get_logger().warn(f"REJECTED: {exc}")
            return
        self.apply(command, "verified")

    def apply(self, command, source):
        self.velocity = command.get("linear_x", 0.0)
        if abs(self.velocity) > SAFE_MAX:
            self.get_logger().error(
                f"applied {source} command linear_x={self.velocity} -- EXCEEDS SAFE LIMIT")
        else:
            self.get_logger().info(f"applied {source} command linear_x={self.velocity}")


def main():
    rclpy.init()
    try:
        rclpy.spin(Robot())
    except KeyboardInterrupt:
        pass
    finally:
        rclpy.shutdown()


if __name__ == "__main__":
    main()

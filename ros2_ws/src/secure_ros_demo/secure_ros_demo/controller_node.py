"""
Legitimate controller: signs each command before publishing.

    ros2 run secure_ros_demo controller
"""
import rclpy
from rclpy.node import Node
from std_msgs.msg import String
import json
from secure_ros_demo.message_auth import SigningPublisher
from secure_ros_demo.keys import load_shared_key


class Controller(Node):
    def __init__(self):
        super().__init__("controller")
        self.pub = self.create_publisher(String, "/cmd_vel", 10)
        self.signer = SigningPublisher(load_shared_key())
        self.step = 0
        self.timer = self.create_timer(1.0, self.tick)
        self.get_logger().info("controller up: sending signed commands")

    def tick(self):
        self.step += 1
        speed = 0.5 + 0.1 * (self.step % 5)          # a gentle, always-safe profile
        message = self.signer.wrap({"linear_x": round(speed, 2)})
        self.pub.publish(String(data=json.dumps(message)))
        self.get_logger().info(f"sent signed command linear_x={speed:.2f}")


def main():
    rclpy.init()
    try:
        rclpy.spin(Controller())
    except KeyboardInterrupt:
        pass
    finally:
        rclpy.shutdown()


if __name__ == "__main__":
    main()

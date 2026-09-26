"""
Launch the robot, the legitimate controller and the attacker together.

    ros2 launch secure_ros_demo demo.launch.py            # secured (default)
    ros2 launch secure_ros_demo demo.launch.py secure:=false

With secure:=true the robot logs the attacker's messages as REJECTED and follows
only the controller. With secure:=false the attacker's 9.0 m/s overrides the
controller and the robot logs it as exceeding the safe limit.
"""
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    secure = LaunchConfiguration("secure")
    return LaunchDescription([
        DeclareLaunchArgument("secure", default_value="true"),
        Node(package="secure_ros_demo", executable="robot", name="robot",
             parameters=[{"secure": secure}], output="screen"),
        Node(package="secure_ros_demo", executable="controller", name="controller",
             output="screen"),
        Node(package="secure_ros_demo", executable="attacker", name="attacker",
             output="screen"),
    ])

from setuptools import setup

package_name = "secure_ros_demo"

setup(
    name=package_name,
    version="1.0.0",
    packages=[package_name],
    data_files=[
        ("share/ament_index/resource_index/packages", ["resource/" + package_name]),
        ("share/" + package_name, ["package.xml"]),
        ("share/" + package_name + "/launch", ["launch/demo.launch.py"]),
    ],
    install_requires=["setuptools"],
    zip_safe=True,
    maintainer="Hamza Kazi",
    maintainer_email="2560347@brunel.ac.uk",
    description="Node-spoofing attack and token-authentication defence for ROS 2.",
    license="MIT",
    entry_points={
        "console_scripts": [
            "robot = secure_ros_demo.robot_node:main",
            "controller = secure_ros_demo.controller_node:main",
            "attacker = secure_ros_demo.attacker_node:main",
        ],
    },
)

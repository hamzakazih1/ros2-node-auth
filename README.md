# ROS 2 Node Spoofing and Token Authentication

*Personal project, 2026 — a continuation of my MSc thesis that builds and verifies the runtime defence the thesis discussed but did not implement.*

A demonstration that ROS 2's default configuration lets an unauthorised node inject commands onto a topic, and a token-authentication layer that stops it — resisting forgery, key-guessing and replay.

Two ways to run it:

- **`sim/`** — a standalone simulation of the attack and defence that runs anywhere, no ROS install needed. Same authentication code as the real nodes.
- **`ros2_ws/`** — a real `ament_python` ROS 2 package with attacker, controller and robot nodes and a launch file.

## The problem

ROS 2 carries messages over DDS. In its default configuration a topic accepts a message from any publisher that knows the topic name. A subscriber cannot tell a genuine command from a forged one. An attacker who reaches the network — a compromised machine, an open Wi-Fi bridge, a rogue container — can publish to `/cmd_vel` and drive the robot. This is node spoofing.

## The defence

Trusted publishers and the subscriber share a secret key. Each command is wrapped with:

- an **HMAC-SHA256 tag** over the command, a counter and a timestamp — proving it came from a key holder and was not altered;
- a **monotonic counter** — so a captured message cannot be replayed;
- a **timestamp** — bounding how long a captured message stays usable.

The subscriber accepts a command only if the tag verifies, the counter has advanced, and the timestamp is recent. HMAC rather than encryption because the goal is authenticity, not secrecy: a velocity setpoint is not confidential, but acting on a forged one is dangerous.

## Run the simulation

```bash
pip install cryptography   # only needed for the ROS-side keys; sim uses stdlib hmac
python sim/simulate.py
```

Output, condensed:

```
=== UNSECURED (ROS 2 default DDS) ===
  attacker injects 9.0 m/s ...
    [ok ] unauthenticated: linear_x=9.0  << UNSAFE
  RESULT: the spoofed command was obeyed. The robot is unsafe.

=== SECURED (token authentication) ===
    [no ] rejected: bad HMAC (forged, altered, or wrong key)
    [no ] rejected: bad HMAC (forged, altered, or wrong key)
  RESULT: both spoof attempts refused; only signed commands obeyed.

=== REPLAY (attacker resends a captured genuine message) ===
    [no ] rejected: replay or out-of-order (counter 1 <= last 1)
  RESULT: the replay was refused because its counter did not advance.
```

Run a single scenario with `--scenario unsecured|secured|replay`.

## Run the real ROS 2 nodes

Requires ROS 2 (Humble or newer).

```bash
cd ros2_ws
colcon build
source install/setup.bash

# Secured: the robot rejects the attacker and follows the controller
ros2 launch secure_ros_demo demo.launch.py

# Unsecured: the attacker's 9.0 m/s overrides the controller
ros2 launch secure_ros_demo demo.launch.py secure:=false
```

In the secured run the robot logs the attacker's messages as `REJECTED` and applies only the controller's signed commands. In the unsecured run it logs the spoofed command as exceeding the safe limit.

Set a real key with `export SECURE_ROS_KEY=...` before launching; otherwise a bundled demo key is used.

## Tests

```bash
python -m unittest discover tests -v
```

13 tests: genuine messages accepted; forged, altered, wrong-key, stale, future, replayed and out-of-order messages rejected; the three attack scenarios; and a check that tag comparison stays constant-time.

## Why this project exists

My MSc thesis (*IoT Anonymization for Factories and Workplaces*, LJMU, 2025)
analysed manipulation attacks on ROS systems and proposed protecting control
parameters at rest, in the launch files on disk. Revisiting that work, two gaps
were clear:

1. **The thesis defended the file, not the running system.** Protecting a launch
   file on disk does nothing about commands injected onto a live topic once the
   nodes are running. That runtime path — node spoofing — is the more direct
   attack, and the thesis did not implement a defence for it.
2. **The runtime defence needed to be built and tested, not just described.**

This project closes both gaps. It builds a working node-spoofing attack, a
token-authentication defence that stops it, and a test suite that verifies the
defence against forgery, key-guessing and replay. It is a deliberate
continuation of the thesis rather than a restatement of it: different layer of
the same threat, and working code where the thesis had a proposal.

A companion project, `ros-param-crypt`, separately corrects and hardens the
file-level tool from the thesis appendix — replacing its reversible hashing with
authenticated encryption. Together the two cover the threat at rest and at
runtime.

## What this is and is not

**Is:** a clear, tested demonstration that unauthenticated pub/sub is exploitable, and that message-level authentication with replay and freshness protection defeats the attack.

**Is not:** a drop-in production security stack. For real deployments ROS 2 provides **SROS2**, which uses the DDS Security plugins for authentication, access control and encryption at the transport layer — enforced by the middleware rather than in application code. This project makes the threat and the mitigation legible; SROS2 is what you would actually deploy. Key management here is deliberately simple (a shared key from an environment variable); production keys belong in a hardware-backed store.

## Layout

```
├── sim/simulate.py                     standalone attack/defence demo
├── ros2_ws/src/secure_ros_demo/
│   ├── secure_ros_demo/
│   │   ├── message_auth.py             the shared authentication logic
│   │   ├── robot_node.py               subscriber, secure or unsecured
│   │   ├── controller_node.py          legitimate signing publisher
│   │   ├── attacker_node.py            spoofing publisher
│   │   └── keys.py                     shared-key loader
│   ├── launch/demo.launch.py
│   ├── package.xml
│   └── setup.py
└── tests/test_auth.py

MIT licensed.
```

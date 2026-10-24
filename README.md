# CS456 – Modern Cybersecurity: Mini Group Project 1
## Resilient Security Systems – Part 1 (Failure Detection)

**Repository:** `https://github.com/pken891/CS456-Security-Group-Project`

### 👥 Team Members
* **Cameron Will** (`@CameronWill02`) – Critical Service Engineer (`service.py`)
* **Peter Kenoian** (`@pken891`) – Heartbeat Monitor Engineer (`monitor.py`)
* **Cameron Hugg** (`@CameronHugg`) – Adversarial Security Auditor (`attacker.py`)

---

How To Run Critical Service Section: for Demo

# Terminal 1 — start the monitor first
python3 files/monitor.py

# Terminal 2 — start the critical service
python3 files/service.py
# optional: --host 127.0.0.1 --port 9999 --interval 1.0 --crash-prob 0.08 --cycle 1.0



## 📌 1. Project Objective & Service Overview

### Chosen Security Domain: Authentication & Session Ticket Service (`service.py`)
In mission-critical security infrastructure, **Availability** is a core pillar of the CIA triad alongside Confidentiality and Integrity. If an Authentication Server or Key Distribution Center (KDC) goes offline due to an exploitative crash or resource exhaustion, authorized users are locked out or downstream services fail open/closed.

Our prototype implements a lightweight **Authentication & Session Ticket Service** (`auth-ticket-daemon`) that continuously validates client credentials and issues cryptographic session tickets while emitting periodic liveness signals to an independent **Heartbeat Monitor** (`monitor.py`).

### Non-Deterministic Failure Simulation
Per Task 3 requirements, the critical service does **not** use a static counter to crash. Instead, `service.py` models realistic, unpredictable process crashes using a **stochastic fault-injection mechanism**:
* During each operational cycle (processing authentication requests), the service evaluates a randomized probability trigger (`random.random() < 0.08`, an 8% fault probability per cycle).
* When triggered, the service simulates a fatal memory corruption / segmentation fault caused by a malformed authentication payload, logs a fatal crash diagnostic with a UTC/local timestamp, and immediately terminates the OS process via `os._exit(1)`.
* Because `os._exit(1)` halts the entire process and all child threads immediately without cleanup, the background heartbeat thread stops transmitting datagrams, accurately modeling an abrupt production daemon crash.

---

## ⚙️ 2. Architectural Parameter Justification

### Heartbeat Pattern: Option A — Push-Based Unidirectional UDP Heartbeat
We selected a **Push-Based (Unidirectional Notification)** heartbeat model over UDP (`127.0.0.1:9999`) for the following architectural reasons:
1. **Decoupled Thread Concurrency:** `service.py` spawns a dedicated background daemon thread (`threading.Thread(daemon=True)`) responsible solely for emitting heartbeats every $T$ milliseconds. This decouples liveness reporting from synchronous authentication request processing on the main thread, preventing heavy authentication load from causing false-positive heartbeat delays.
2. **Low Protocol Overhead & Monitor Isolation:** Using connectionless UDP (`SOCK_DGRAM`) avoids TCP connection-state exhaustion and `BrokenPipeError` / `ConnectionResetError` handling on the monitor when the service abruptly exits. The monitor (`monitor.py`) remains completely insulated from crashes in `service.py`.

### Timing Calibration ($T$, $N$, and $W$)
| Parameter | Symbol | Chosen Value | Engineering Justification |
| :--- | :---: | :---: | :--- |
| **Heartbeat Interval** | $T$ | `1.0s` (`1000 ms`) | Emitting a 110-byte JSON UDP datagram once per second incurs negligible CPU and socket overhead while providing granular visibility into process liveness. |
| **Missed-Beat Threshold** | $N$ | `3` missed beats | Allowing up to 3 consecutive missed beats prevents transient OS thread scheduling jitter or loopback buffer contention from triggering false-positive alerts. |
| **Timeout Window (MTTD)** | $W$ | `3.0s` (`3000 ms`) | Calculated as $W = N \times T = 3.0\text{ seconds}$. This achieves a fast **Mean Time To Detect (MTTD) of 3.0 seconds**, ensuring rapid fault detection without alert fatigue. |

### Wire Payload Schema (JSON over UDP)
```json
{
  "type": "HEARTBEAT",
  "service": "auth-ticket-daemon",
  "seq": 14,
  "timestamp": 1729450000.123,
  "status": "HEALTHY"
}

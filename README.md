Peter Kenoian, Cameron Will, Cameron Hugg
CS456-001 MP1.1

Language: Python 3 (standard library only: socket, threading, json, time, random, os — zero pip install needed).
Security Domain: Authentication/Ticket Service (validates dummy login tokens while emitting background heartbeats).   
Heartbeat Model: Option A (Push-Based UDP Heartbeat).     

JSON Wire Payload Schema: 
{
  "type": "HEARTBEAT",
  "service": "auth-ticket-daemon",
  "seq": 14,
  "timestamp": 1729450000.123,
  "status": "HEALTHY"
}

1. Critical Service Engineer — [Cameron Will] Core Script (service.py):Implements the lightweight Authentication/Ticket Service process.Runs a decoupled background daemon thread (threading.Thread) that emits a JSON HEARTBEAT UDP datagram to 127.0.0.1:9999 every $T = 1.0\text{s}$.Implements a non-deterministic crash trigger (stochastic fault injection via random.random() < 0.08) that simulates a fatal memory corruption/segmentation fault, logs the crash timestamp, and terminates the process completely using os._exit(1).Documentation & Repo Deliverables:Authors the Service Overview and Execution & Setup Instructions sections of the final PDF report.Initializes the GitHub repository structure, maintains CONTRIBUTIONS.md, and compiles the final PDF report.

2. Heartbeat Monitor Engineer — [Peter Kenoian ]Core Script (monitor.py):Implements the independent Heartbeat Monitor process listening on UDP socket 127.0.0.1:9999.Enforces the sliding timeout window ($W = 3.0\text{s}$ across $N = 3$ missed beats at $T = 1.0\text{s}$ intervals).Prints real-time timestamped acknowledgments for valid incoming heartbeats.Detects service crashes when the timeout threshold is exceeded, outputs a timestamped [CRITICAL ALERT] to stdout, records the outage in monitor_incidents.log, and remains operational without crashing.Documentation Deliverables:Authors the Architectural Parameter Justification section of the PDF report, justifying the Push-based model and how $T$, $W$, and $N$ balance Mean Time To Detect (MTTD) against false positives.

3. Adversarial Security Auditor — [Cameron Hugg] Core Script (attacker.py):Implements the standalone Adversarial Audit Script targeting the monitor at 127.0.0.1:9999.Attack 1 — Heartbeat Spoofing (--attack spoof): Transmits forged UDP heartbeat datagrams to the monitor after service.py crashes to mask downtime and force false-positive HEALTHY status reporting.Attack 2 — Replay / Tampering (--attack replay): Captures and indefinitely replays a static heartbeat payload with a stale timestamp and sequence number to test freshness validation.Documentation & Demo Deliverables:Authors the Adversarial Audit Summary section of the PDF report analyzing baseline heartbeat vulnerabilities and cryptographic mitigations (e.g., HMAC-SHA256 + monotonic sequence validation).Leads the recording, editing, and voiceover for the <3-minute Video Demonstration.

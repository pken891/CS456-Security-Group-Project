# Contributions

## Cameron Will — Monitor Failover Controller & Client
- Wrote INTERFACE.md, the team's Part 2 contract (heartbeat fields, client TCP API, checkpoint format, standby launch)
- Extended monitor.py into an automated failover controller: crash detection, PID fencing to prevent split-brain, standby spawning, timestamped Crash Detected → Failover Triggered → Service Restored logging with MTTR, and a crash-loop guard
- Wrote client.py: demo and interactive modes, auto-retry during failover, post-failover state verification
- Report: architecture diagram and Redundancy Justification

## Cameron Hugg — Service, Replica & Checkpointing

## Peter Kenoian — Adversarial Auditor, Video & Final PDF


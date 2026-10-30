# Contributions

## Cameron Will — Monitor Failover Controller & Client
- Wrote INTERFACE.md, the team's Part 2 contract (heartbeat fields, client TCP API, checkpoint format, standby launch)
- Extended monitor.py into an automated failover controller: crash detection, PID fencing to prevent split-brain, standby spawning, timestamped Crash Detected → Failover Triggered → Service Restored logging with MTTR, and a crash-loop guard
- Wrote client.py: demo and interactive modes, auto-retry during failover, post-failover state verification
- Report: architecture diagram and Redundancy Justification

## Cameron Hugg — Service, Replica & Checkpointing

## Peter Kenoian — Adversarial Auditor, Video & Final PDF
* **Part 2 Adversarial Audit (`attacker.py`):** Tested the system against recovery-phase threats:
  * **Split-Brain Attack (`--attack split-brain`):** Suspended the live primary process in memory for 4.5 seconds to force a timeout, and verified that `monitor.py` successfully detects the unresponsive node, checks its PID, and force-terminates it prior to standby promotion.
  * **Checkpoint Tampering Attack (`--attack tamper`):** Injected unauthorized session tokens (`--tamper-mode inject`) into `checkpoint.json` without updating the HMAC-SHA256 tag, verifying that the standby node detects the HMAC mismatch, rejects the poisoned state, and gracefully falls back to `checkpoint.json.bak`.
* **Adversarial Audit Summary & Report Compilation:** Wrote the Part 2 audit findings and compiled all team sections into the final PDF report.
* **Video Demonstration:** Produced and narrated the under-3-minute video showing client state creation, non-deterministic primary crash, automated failover (`[Crash Detected] -> [Failover Triggered] -> [Service Restored]`), and pre-crash state recovery.


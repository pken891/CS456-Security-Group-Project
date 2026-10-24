# Contributions

## Cameron Will — Critical Service Engineer
- Designed and implemented `files/service.py` (auth-ticket-daemon): simulated credential validation against salted password hashes and session-ticket issuance
- Built the background UDP heartbeat thread (push model, T = 1.0 s) using the JSON payload schema in the README
- Implemented stochastic crash injection (8% chance per cycle, terminated with `os._exit(1)`) and timestamped crash logging
- Tested the service against a stand-in listener and against `monitor.py` to confirm crashes are detected
- Wrote the Service Overview and setup-command sections of the report

## Peter Kenoian — Heartbeat Monitor Engineer
- Built the Heartbeat Monitor (monitor.py): Created an independent Python UDP watchdog script listening on 127.0.0.1:9999 to track periodic liveness messages from the critical security service.
- Implemented Sliding-Window Timeout Logic: Configured the monitor to check for a $1.0\text{ s}$ heartbeat interval ($T$) and trigger a failure alert after $N = 3$ missed beats ($W = 3.0\text{ s}$ timeout window).
- Added Real-Time Alerting and Incident Logging: Programmed the monitor to print timestamped status updates to the terminal and record crash alerts in monitor_incidents.log while staying online after the service crashes.
- Wrote the Architectural Parameter Justification: Authored the report section explaining why our team chose a Push-Based UDP heartbeat pattern and how our $T$, $N$, and $W$ values balance fast crash detection (MTTD) against false positives.
- Set Up Repository Documentation: Cleaned up and organized the GitHub repository's README.md and CONTRIBUTIONS.md files to document the team's workflow and setup instructions.
- Created GitHub repository

## Cameron Hugg — Adversarial Security Auditor
-

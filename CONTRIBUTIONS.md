# Contributions

## Cameron Will — Critical Service Engineer
- Designed and implemented `files/service.py` (auth-ticket-daemon): simulated credential validation against salted password hashes and session-ticket issuance
- Built the background UDP heartbeat thread (push model, T = 1.0 s) using the JSON payload schema in the README
- Implemented stochastic crash injection (8% chance per cycle, terminated with `os._exit(1)`) and timestamped crash logging
- Tested the service against a stand-in listener and against `monitor.py` to confirm crashes are detected
- Wrote the Service Overview and setup-command sections of the report

## Peter Kenoian — Heartbeat Monitor Engineer
- 

## Cameron Hugg — Adversarial Security Auditor
-

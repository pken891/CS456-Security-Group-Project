#!/usr/bin/env python3
"""
CS456 - Mini Group Project 1 (Part 1: Failure Detection)
Role: Heartbeat Monitor Process (monitor.py)
Author: Peter Kenoian

Description:
Independent watchdog monitoring agent that listens for periodic UDP heartbeat
datagrams from the critical security service (service.py). Enforces a sliding
timeout window W = N * T (3.0 seconds), logs crash incidents with timestamps
to stdout and monitor_incidents.log, and remains operational across crashes.
"""

import argparse
import datetime
import json
import socket
import sys
import time

# Default Architectural Parameters
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
HEARTBEAT_INTERVAL_T = 1.0   # Expected heartbeat period T = 1.0s (1000 ms)
MISSED_THRESHOLD_N = 3       # Missed beat threshold N = 3 consecutive beats
TIMEOUT_WINDOW_W = HEARTBEAT_INTERVAL_T * MISSED_THRESHOLD_N  # W = 3.0s
SOCKET_POLL_INTERVAL = 0.25  # Non-blocking poll granularity (250 ms)
LOG_FILE = "monitor_incidents.log"


def get_timestamp() -> str:
    """Return a formatted local timestamp string with millisecond precision."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def log_incident(message: str, log_filepath: str = LOG_FILE) -> None:
    """Print critical alert to stdout and append persistently to the incident log."""
    timestamped_entry = f"[{get_timestamp()}] {message}"
    print(timestamped_entry, flush=True)
    try:
        with open(log_filepath, "a", encoding="utf-8") as f:
            f.write(timestamped_entry + "\n")
    except OSError as err:
        print(f"[{get_timestamp()}] [LOG ERROR] Could not write to {log_filepath}: {err}", file=sys.stderr)


def run_monitor(host: str, port: int, interval_t: float, threshold_n: int) -> None:
    """Main watchdog loop monitoring incoming UDP heartbeats."""
    timeout_w = interval_t * threshold_n

    # Create UDP socket (SOCK_DGRAM) so service crashes never break a TCP pipe
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(SOCKET_POLL_INTERVAL)

    print("=" * 72)
    print(f"[{get_timestamp()}] [INIT] CS456 Heartbeat Monitor Agent Started")
    print(f"[{get_timestamp()}] [CFG ] Listening on UDP {host}:{port}")
    print(f"[{get_timestamp()}] [CFG ] Interval (T): {interval_t:.1f}s | "
          f"Missed Threshold (N): {threshold_n} | Timeout Window (W): {timeout_w:.1f}s")
    print(f"[{get_timestamp()}] [WAIT] Waiting for initial heartbeat from critical service...")
    print("=" * 72, flush=True)

    service_online = False
    alert_triggered = False
    last_beat_time = None
    last_seq = None
    monitored_service_name = "auth-ticket-daemon"

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                now = time.monotonic()

                # Parse JSON heartbeat payload
                try:
                    payload = json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    print(f"[{get_timestamp()}] [WARN] Malformed non-JSON packet from {addr[0]}:{addr[1]} ignored.", flush=True)
                    continue

                if payload.get("type") != "HEARTBEAT":
                    print(f"[{get_timestamp()}] [WARN] Unexpected packet type '{payload.get('type')}' from {addr[0]}:{addr[1]}", flush=True)
                    continue

                # Extract telemetry fields
                seq = payload.get("seq", "?")
                status = payload.get("status", "UNKNOWN")
                monitored_service_name = payload.get("service", monitored_service_name)
                pkt_timestamp = payload.get("timestamp", "N/A")

                # Detect first connection or recovery after an outage
                if not service_online:
                    if alert_triggered:
                        log_incident(
                            f"[RECOVERY] Service '{monitored_service_name}' resumed heartbeats from "
                            f"{addr[0]}:{addr[1]} (seq={seq}). Marking status HEALTHY."
                        )
                    else:
                        log_incident(
                            f"[CONNECTED] First heartbeat received from '{monitored_service_name}' "
                            f"at {addr[0]}:{addr[1]} (seq={seq}). Monitoring active."
                        )
                    service_online = True
                    alert_triggered = False

                last_beat_time = now
                last_seq = seq

                print(
                    f"[{get_timestamp()}] [OK] Heartbeat #{seq} received from {addr[0]}:{addr[1]} | "
                    f"Service: {monitored_service_name} | Status: {status} | PktTime: {pkt_timestamp}",
                    flush=True,
                )

            except socket.timeout:
                # Periodically evaluate sliding window timeout if a service was previously active
                if last_beat_time is not None:
                    elapsed = time.monotonic() - last_beat_time
                    missed_beats = int(elapsed // interval_t)

                    if elapsed >= timeout_w and not alert_triggered:
                        alert_triggered = True
                        service_online = False
                        log_incident(
                            f"[CRITICAL ALERT] FAULT DETECTED! Service '{monitored_service_name}' is UNRESPONSIVE / CRASHED. "
                            f"Elapsed since last beat (seq={last_seq}): {elapsed:.2f}s "
                            f"(Exceeded W={timeout_w:.1f}s / N={threshold_n} missed beats)."
                        )
                    elif not alert_triggered and missed_beats >= 1:
                        # Optional warning when 1 or 2 beats are late but still inside window W
                        pass

    except KeyboardInterrupt:
        print(f"\n[{get_timestamp()}] [SHUTDOWN] Monitor stopped cleanly by operator.")
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CS456 Independent UDP Heartbeat Monitor")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind IP address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Bind UDP port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--interval", type=float, default=HEARTBEAT_INTERVAL_T, help="Heartbeat interval T in seconds (default: 1.0)")
    parser.add_argument("-n", "--threshold", type=int, default=MISSED_THRESHOLD_N, help="Missed beat threshold N (default: 3)")
    args = parser.parse_args()

    run_monitor(args.host, args.port, args.interval, args.threshold)


if __name__ == "__main__":
    main()

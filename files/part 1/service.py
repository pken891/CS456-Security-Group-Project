#!/usr/bin/env python3
"""
auth-ticket-daemon: a simulated Authentication & Session Ticket Service.

CS456 Mini Group Project 1, Resilient Security Systems Part 1 (Failure Detection).
Role: Critical Service Engineer.

Overview
--------
This module is the critical service that the Heartbeat Monitor (monitor.py)
watches. It models a small authentication server, similar to a Kerberos KDC.
The main thread loops forever. Each cycle it:

    1. receives a simulated client authentication request (a random dummy
       user with either the correct or an incorrect password),
    2. checks the credentials against salted PBKDF2 password hashes, and
    3. on success, issues a random session ticket that expires after a set time.

The business logic is kept minimal on purpose. The project is about liveness
monitoring, not authentication.

Heartbeat design (push model, Option A in README.md)
-----------------------------------------------------
A separate background thread (``threading.Thread(daemon=True)``) sends a UDP
datagram to the monitor at 127.0.0.1:9999 every T = 1.0 s. The payload is
JSON:

    {"type": "HEARTBEAT", "service": "auth-ticket-daemon",
     "seq": <int, starts at 1>, "timestamp": <time.time()>, "status": "HEALTHY"}

The heartbeat is not tied to the authentication loop, so slow request
processing cannot delay beats and cause false alarms. UDP is connectionless,
so the service keeps running even when no monitor is listening. Send errors
are caught and logged, never raised.

Crash model (Task 3: non-deterministic failure)
-----------------------------------------------
There is no fixed crash point such as ``if count == 5``. Each operational
cycle checks ``random.random() < CRASH_PROBABILITY`` (default 0.08). When the
check fires, the service logs a FATAL diagnostic that simulates a segmentation
fault caused by a malformed authentication payload, then calls
``os._exit(1)``. That kills the whole process at once, heartbeat thread
included, without running cleanup handlers. From the monitor's point of view
the beats just stop, which is how a real daemon crash looks.

A cycle lasts about CYCLE_INTERVAL (1.0 s) plus a small random jitter, so the
number of cycles before a crash follows a geometric distribution. The expected
uptime is 1 / 0.08 = 12.5 cycles, or roughly 12 seconds.

Usage
-----
    python3 files/service.py [--host HOST] [--port PORT] [--interval T]
                             [--crash-prob P] [--cycle SECONDS]
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
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration defaults. These must match the design contract in README.md.
# Each one can be overridden from the command line (see parse_args()).
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"          # Monitor address (UDP heartbeat destination)
PORT = 9999                 # Monitor UDP port
HEARTBEAT_INTERVAL = 1.0    # T: seconds between heartbeats
CRASH_PROBABILITY = 0.08    # Per-cycle probability of a fatal fault
CYCLE_INTERVAL = 1.0        # Nominal seconds per authentication cycle

SERVICE_NAME = "auth-ticket-daemon"
CYCLE_JITTER = 0.15         # +/- seconds of random jitter added to each cycle
TICKET_TTL = 300            # Session ticket lifetime in seconds
VALID_ATTEMPT_RATE = 0.7    # Fraction of simulated requests that use the right password

# Log file lives at <repo root>/logs/service.log, wherever the script is run from.
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_FILE = LOG_DIR / "service.log"

# Dummy user database: username -> plaintext password. These are hashed at
# startup (see build_credential_store()), so only salted hashes are kept in
# memory while the service runs.
DUMMY_USERS = {
    "alice": "correct-horse-battery",
    "bob": "hunter2",
    "carol": "s3cur3-p@ss",
    "dave": "letmein!",
}
# Usernames that are not in the database, used to simulate unknown-user attempts.
UNKNOWN_USERS = ["mallory", "eve", "root"]

PBKDF2_ITERATIONS = 10_000  # Kept low so startup stays fast; this is a demo

log = logging.getLogger(SERVICE_NAME)

# The last heartbeat sequence number sent. The heartbeat thread writes it and
# the main thread reads it for the crash diagnostic, so a lock guards it.
_last_seq = 0
_seq_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------
def parse_args():
    """Parse command-line overrides for the configuration constants.

    Returns:
        argparse.Namespace with host, port, interval, crash_prob, and cycle.
    """
    parser = argparse.ArgumentParser(
        description=f"{SERVICE_NAME}: simulated authentication service "
                    "with a UDP push heartbeat and random crash injection.")
    parser.add_argument("--host", default=HOST,
                        help=f"monitor host for heartbeats (default: {HOST})")
    parser.add_argument("--port", type=int, default=PORT,
                        help=f"monitor UDP port (default: {PORT})")
    parser.add_argument("--interval", type=float, default=HEARTBEAT_INTERVAL,
                        help="heartbeat interval T in seconds "
                             f"(default: {HEARTBEAT_INTERVAL})")
    parser.add_argument("--crash-prob", type=float, default=CRASH_PROBABILITY,
                        help="per-cycle crash probability, 0.0 to 1.0 "
                             f"(default: {CRASH_PROBABILITY})")
    parser.add_argument("--cycle", type=float, default=CYCLE_INTERVAL,
                        help="nominal auth cycle duration in seconds "
                             f"(default: {CYCLE_INTERVAL})")
    args = parser.parse_args()

    if not 0.0 <= args.crash_prob <= 1.0:
        parser.error("--crash-prob must be between 0.0 and 1.0")
    if args.interval <= 0 or args.cycle <= 0:
        parser.error("--interval and --cycle must be positive")
    if not 0 < args.port < 65536:
        parser.error("--port must be between 1 and 65535")
    return args


def setup_logging():
    """Send timestamped log lines to the console and to logs/service.log.

    The logs/ directory is created if it does not exist. Both handlers flush
    after every record, so nothing is lost when os._exit() is called.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logfile = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    logfile.setFormatter(formatter)

    log.setLevel(logging.INFO)
    log.addHandler(console)
    log.addHandler(logfile)


def hash_password(password, salt):
    """Return the PBKDF2-HMAC-SHA256 digest of password with the given salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                               PBKDF2_ITERATIONS)


def build_credential_store():
    """Hash the dummy passwords so only salted hashes are kept in memory.

    Returns:
        dict mapping username -> (salt, password_hash).
    """
    store = {}
    for user, password in DUMMY_USERS.items():
        salt = secrets.token_bytes(16)
        store[user] = (salt, hash_password(password, salt))
    return store


# ---------------------------------------------------------------------------
# Heartbeat (background daemon thread)
# ---------------------------------------------------------------------------
def heartbeat_loop(host, port, interval):
    """Send a HEARTBEAT datagram to (host, port) every `interval` seconds.

    This runs as the target of a daemon thread. Sequence numbers start at 1
    and go up by one per beat. Beats follow a fixed monotonic schedule, so
    the time spent sending does not make the interval drift. If a send fails
    (for example, the network is unreachable), the error is logged and the
    loop keeps going. The thread exits only when the process does.
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
        }
        try:
            sock.sendto(json.dumps(payload).encode("utf-8"), (host, port))
            with _seq_lock:
                _last_seq = seq
            log.info("[HEARTBEAT] seq=%d sent to %s:%d", seq, host, port)
        except OSError as exc:
            # UDP has no connection, but sendto() can still fail because of
            # local errors such as a bad address or an ICMP error left over
            # from a previous send. Never let that kill the thread.
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
    thread = threading.Thread(target=heartbeat_loop,
                              args=(host, port, interval),
                              name="heartbeat", daemon=True)
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# Authentication logic (main thread)
# ---------------------------------------------------------------------------
def generate_auth_request():
    """Simulate an incoming client authentication request.

    Returns:
        (username, password). The mix covers known users with the correct
        password, known users with a wrong password, and unknown users.
    """
    if random.random() < 0.15:
        return random.choice(UNKNOWN_USERS), secrets.token_urlsafe(8)
    user = random.choice(list(DUMMY_USERS))
    if random.random() < VALID_ATTEMPT_RATE:
        return user, DUMMY_USERS[user]
    return user, DUMMY_USERS[user] + "-typo"


def validate_credentials(store, username, password):
    """Check a username/password pair against the credential store.

    Unknown users are checked against a dummy hash, so a failed login takes
    about the same time whether or not the user exists. The final comparison
    uses hmac.compare_digest(), which runs in constant time.

    Returns:
        True if the credentials are valid, otherwise False.
    """
    salt, expected = store.get(username, (b"\x00" * 16, b""))
    supplied = hash_password(password, salt)
    return username in store and hmac.compare_digest(supplied, expected)


def issue_ticket(username):
    """Create a session ticket for an authenticated user.

    Returns:
        (ticket, expiry). The ticket is a 128-bit random hex token and the
        expiry is a UTC datetime TICKET_TTL seconds from now.
    """
    ticket = secrets.token_hex(16)
    expiry = datetime.fromtimestamp(time.time() + TICKET_TTL, tz=timezone.utc)
    return ticket, expiry


def crash(cycle, username):
    """Simulate a fatal memory-corruption fault and kill the process at once.

    Logs a FATAL diagnostic with UTC and local timestamps, the cycle number,
    and the last heartbeat seq sent, flushes all output, then calls
    os._exit(1). os._exit() skips exception handling, atexit handlers, and
    thread joins, so the heartbeat thread dies with the process the same way
    it would after a real SIGSEGV.
    """
    now = time.time()
    utc = datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="milliseconds")
    local = datetime.fromtimestamp(now).astimezone().isoformat(timespec="milliseconds")
    with _seq_lock:
        last_seq = _last_seq

    log.critical("[FATAL] Segmentation fault (SIGSEGV): memory corruption while "
                 "parsing malformed authentication payload from user=%r", username)
    log.critical("[FATAL] cycle=%d last_heartbeat_seq=%d pid=%d",
                 cycle, last_seq, os.getpid())
    log.critical("[FATAL] crash_time_utc=%s crash_time_local=%s", utc, local)
    log.critical("[FATAL] %s terminated abnormally (exit code 1). "
                 "Heartbeats stopped.", SERVICE_NAME)

    for handler in log.handlers:
        handler.flush()
    sys.stdout.flush()
    os._exit(1)


def run_service(cycle_interval, crash_prob):
    """Run the authentication loop on the main thread until the crash fires.

    Each cycle receives one simulated request, checks whether a random fault
    happens, then validates the credentials and issues a ticket on success.
    Each cycle lasts about cycle_interval +/- CYCLE_JITTER seconds.
    """
    store = build_credential_store()
    cycle = 0

    while True:
        cycle += 1
        started = time.monotonic()
        username, password = generate_auth_request()

        # Non-deterministic fault injection: the same check runs every cycle
        # with no counters or fixed thresholds, so the crash point is random.
        if random.random() < crash_prob:
            crash(cycle, username)

        if validate_credentials(store, username, password):
            ticket, expiry = issue_ticket(username)
            log.info("[AUTH] cycle=%d user=%s result=GRANTED ticket=%s expires=%s",
                     cycle, username, ticket,
                     expiry.strftime("%Y-%m-%dT%H:%M:%SZ"))
        else:
            log.info("[AUTH] cycle=%d user=%s result=DENIED reason=invalid credentials",
                     cycle, username)

        # Sleep for whatever is left of this cycle's jittered duration.
        target = max(0.0, cycle_interval + random.uniform(-CYCLE_JITTER, CYCLE_JITTER))
        remaining = target - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)


def main():
    """Entry point: parse args, set up logging, start the heartbeat, run the loop."""
    args = parse_args()
    setup_logging()

    log.info("[STARTUP] %s starting (pid=%d)", SERVICE_NAME, os.getpid())
    log.info("[STARTUP] heartbeat -> udp://%s:%d every %.2fs | "
             "crash_prob=%.3f per cycle | cycle=%.2fs | log=%s",
             args.host, args.port, args.interval, args.crash_prob,
             args.cycle, LOG_FILE)

    start_heartbeat(args.host, args.port, args.interval)
    try:
        run_service(args.cycle, args.crash_prob)
    except KeyboardInterrupt:
        # A manual Ctrl+C is a clean shutdown, not a simulated failure.
        log.info("[SHUTDOWN] %s stopped by operator (Ctrl+C)", SERVICE_NAME)


if __name__ == "__main__":
    main()

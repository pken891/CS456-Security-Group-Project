#!/usr/bin/env python3
"""
CS456 - Mini Group Project 1 (Part 2: Recovery)
Role: Client (client.py)
Author: Cameron Will

Description:
TCP client for the auth-ticket-daemon client API (127.0.0.1:8000,
newline-delimited JSON, see INTERFACE.md). The default demo mode builds
up some state before a crash, then keeps polling across the failover:

    1. log in as alice and keep her session ticket,
    2. fail bob's login 3 times so he is locked out,
    3. every second, validate alice's ticket, query bob's status and the
       serving node's pid,
    4. when the service disappears, retry every 0.5 s until the promoted
       standby answers, then check that alice's ticket is still valid and
       bob is still locked (the pre-crash state survived the failover).

--mode interactive gives a small prompt for manual requests.

All commands are run from inside "files/part 2/" (see INTERFACE.md).
"""

import argparse
import datetime
import json
import socket
import sys
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_POLL = 1.0           # Seconds between demo polls
RETRY_INTERVAL = 0.5         # Seconds between reconnect attempts
CONNECT_TIMEOUT = 0.5        # Short connect timeout while the service is down
REQUEST_TIMEOUT = 2.0        # A reply slower than this counts as "unavailable" (e.g. frozen primary)
MAX_LINE = 65536

DEMO_USER = ("alice", "alice123")
LOCKED_USER = ("bob", "wrong-password")
LOCKOUT_ATTEMPTS = 3


def get_timestamp() -> str:
    """Return a formatted local timestamp string with millisecond precision."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def log(tag: str, message: str) -> None:
    print(f"[{get_timestamp()}] [{tag}] {message}", flush=True)


class ServiceUnavailable(Exception):
    """The service could not be reached or the connection broke mid-request."""


class BadResponse(Exception):
    """The service answered, but not with a JSON object."""


class ServiceClient:
    """One persistent TCP connection carrying newline-delimited JSON requests."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock = None
        self.buf = b""

    def connect(self, timeout: float = CONNECT_TIMEOUT) -> None:
        self.close()
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
            self.sock.settimeout(REQUEST_TIMEOUT)
        except OSError as err:
            self.sock = None
            raise ServiceUnavailable(describe(err)) from err

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.buf = b""

    def request(self, obj: dict) -> dict:
        if self.sock is None:
            self.connect()
        try:
            self.sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))
            line = self._readline()
        except OSError as err:
            self.close()
            raise ServiceUnavailable(describe(err)) from err
        try:
            resp = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BadResponse(f"non-JSON response: {line[:80]!r}")
        if not isinstance(resp, dict):
            raise BadResponse(f"response is not a JSON object: {line[:80]!r}")
        return resp

    def _readline(self) -> bytes:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionResetError("connection closed by server")
            self.buf += chunk
            if len(self.buf) > MAX_LINE:
                raise ConnectionResetError("response line too long")
        line, self.buf = self.buf.split(b"\n", 1)
        return line


def describe(err: Exception) -> str:
    if isinstance(err, socket.timeout):
        return "timed out (no response)"
    if isinstance(err, ConnectionRefusedError):
        return "connection refused"
    if isinstance(err, ConnectionResetError):
        return f"connection reset ({err})"
    return f"{type(err).__name__}: {err}"


def pass_fail(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


# ==============================================================================
# Demo mode
# ==============================================================================

class Demo:
    def __init__(self, client: ServiceClient, poll: float) -> None:
        self.client = client
        self.poll = poll
        self.node_pid = None
        self.ticket = None
        self.ticket_expires = None

    def run(self) -> None:
        print("=" * 72)
        log("INIT", f"CS456 Client Demo -> tcp://{self.client.host}:{self.client.port} "
                    f"(poll every {self.poll:.1f}s)")
        print("=" * 72, flush=True)
        self.wait_for_service()
        if not self.login_alice():
            return
        self.lock_bob()
        log("DEMO", "Pre-crash state ready. Polling; crash the primary any time.")
        self.poll_loop()

    def wait_for_service(self) -> None:
        attempts = 0
        while True:
            try:
                state = self.client.request({"op": "state"})
                self.node_pid = state.get("node_pid")
                log("CONNECTED", f"node_pid={self.node_pid} role={state.get('role')} "
                                 f"checkpoint_loaded={state.get('checkpoint_loaded')}")
                return
            except (ServiceUnavailable, BadResponse) as err:
                attempts += 1
                if attempts == 1:
                    log("WAIT", f"service not reachable yet ({err}); retrying every {RETRY_INTERVAL}s...")
                time.sleep(RETRY_INTERVAL)

    def call(self, obj: dict) -> dict:
        """Send one request, riding out an outage (reconnect, then resend) if needed."""
        while True:
            try:
                return self.client.request(obj)
            except ServiceUnavailable as err:
                self.reconnect(str(err), check_state=False)
            except BadResponse as err:
                log("WARN", f"bad response to {obj.get('op')}: {err}")
                return {}

    def login_alice(self) -> bool:
        user, password = DEMO_USER
        for _ in range(3):
            resp = self.call({"op": "login", "user": user, "password": password})
            if resp.get("ok") and isinstance(resp.get("ticket"), str):
                self.ticket = resp["ticket"]
                self.ticket_expires = resp.get("expires")
                log("LOGIN", f"{user} (correct password) -> OK ticket={self.ticket} expires={self.ticket_expires}")
                return True
            log("LOGIN", f"{user} (correct password) -> unexpected response {resp}")
            time.sleep(1.0)
        log("ERROR", f"could not log in as {user}; demo cannot continue.")
        return False

    def lock_bob(self) -> None:
        user, password = LOCKED_USER
        for i in range(1, LOCKOUT_ATTEMPTS + 1):
            resp = self.call({"op": "login", "user": user, "password": password})
            log("LOGIN", f"{user} (wrong password) attempt {i}/{LOCKOUT_ATTEMPTS} -> "
                         f"{resp.get('error', resp)} failed_count={resp.get('failed_count', '-')}")
        status = self.call({"op": "status", "user": user})
        log("STATUS", f"{user}: failed_count={status.get('failed_count')} locked={status.get('locked')} "
                      f"active_sessions={status.get('active_sessions')}")
        if status.get("locked") is not True:
            log("WARN", f"{user} is not locked; the bob STATE CHECK will FAIL.")

    def snapshot(self) -> tuple[dict, dict, dict]:
        validate = self.client.request({"op": "validate", "ticket": self.ticket})
        status = self.client.request({"op": "status", "user": LOCKED_USER[0]})
        state = self.client.request({"op": "state"})
        return validate, status, state

    def poll_loop(self) -> None:
        while True:
            try:
                validate, status, state = self.snapshot()
            except ServiceUnavailable as err:
                self.reconnect(str(err), check_state=True)
                continue
            except BadResponse as err:
                log("WARN", f"bad response during poll: {err}")
                time.sleep(self.poll)
                continue
            self.node_pid = state.get("node_pid", self.node_pid)
            log("POLL", f"node_pid={self.node_pid} alice_ticket_valid={validate.get('valid')} "
                        f"bob_locked={status.get('locked')} sessions={state.get('sessions')} "
                        f"locked_users={state.get('locked_users')}")
            time.sleep(self.poll)

    def reconnect(self, reason: str, check_state: bool) -> None:
        old_pid = self.node_pid
        down_since = time.monotonic()
        log("SERVICE UNAVAILABLE", f"{reason} (last node_pid={old_pid}); "
                                   f"retrying every {RETRY_INTERVAL}s...")
        attempt = 0
        while True:
            attempt += 1
            time.sleep(RETRY_INTERVAL)
            try:
                self.client.connect(CONNECT_TIMEOUT)
                state = self.client.request({"op": "state"})
                break
            except (ServiceUnavailable, BadResponse) as err:
                log("RETRY", f"#{attempt} still unavailable ({err})")

        downtime = time.monotonic() - down_since
        self.node_pid = state.get("node_pid")
        log("RECONNECTED", f"after {downtime:.2f} s of downtime ({attempt} retries) | node_pid "
                           f"{old_pid} -> {self.node_pid} role={state.get('role')} "
                           f"checkpoint_loaded={state.get('checkpoint_loaded')}")
        if check_state and self.ticket is not None:
            self.state_check()

    def state_check(self) -> None:
        validate = self.call({"op": "validate", "ticket": self.ticket})
        status = self.call({"op": "status", "user": LOCKED_USER[0]})
        alice_ok = validate.get("ok") is True and validate.get("valid") is True
        bob_ok = status.get("locked") is True
        note = ""
        if not alice_ok and isinstance(self.ticket_expires, (int, float)) and time.time() > self.ticket_expires:
            note = " (note: ticket TTL has expired naturally)"
        log("STATE CHECK", f"alice ticket still valid: {pass_fail(alice_ok)} | "
                           f"bob still locked: {pass_fail(bob_ok)}{note}")


# ==============================================================================
# Interactive mode
# ==============================================================================

HELP = """commands:
  login <user> <password>   log in (saves the ticket)
  validate [ticket]         validate a ticket (default: last ticket from login)
  status <user>             failed count / lockout for a user
  state                     node pid, role, sessions, locked users
  raw <json>                send a raw JSON line
  help | quit"""


def run_interactive(client: ServiceClient) -> None:
    log("INIT", f"CS456 Client (interactive) -> tcp://{client.host}:{client.port}. Type 'help'.")
    last_ticket = None
    while True:
        try:
            line = input("client> ").strip()
        except EOFError:
            break
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        args = rest.split()
        cmd = cmd.lower()
        if cmd in ("quit", "exit", "q"):
            break
        if cmd == "help":
            print(HELP)
            continue
        if cmd == "login" and len(args) == 2:
            req = {"op": "login", "user": args[0], "password": args[1]}
        elif cmd == "validate" and (args or last_ticket):
            req = {"op": "validate", "ticket": args[0] if args else last_ticket}
        elif cmd == "status" and len(args) == 1:
            req = {"op": "status", "user": args[0]}
        elif cmd == "state" and not args:
            req = {"op": "state"}
        elif cmd == "raw" and rest:
            try:
                req = json.loads(rest)
            except json.JSONDecodeError as err:
                log("ERROR", f"invalid JSON: {err}")
                continue
        else:
            print(HELP)
            continue

        # One automatic reconnect attempt, so a request right after a failover still works.
        for attempt in (1, 2):
            try:
                resp = client.request(req)
            except ServiceUnavailable as err:
                if attempt == 1:
                    client.close()
                    continue
                log("SERVICE UNAVAILABLE", f"{err}; try again in a moment.")
                break
            except BadResponse as err:
                log("WARN", str(err))
                break
            log("RESPONSE", json.dumps(resp))
            if req.get("op") == "login" and isinstance(resp.get("ticket"), str):
                last_ticket = resp["ticket"]
            break
    log("SHUTDOWN", "client exiting.")


def main() -> None:
    parser = argparse.ArgumentParser(description="CS456 auth-ticket-daemon client (failover demo)")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Service host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Service TCP port (default: {DEFAULT_PORT})")
    parser.add_argument("--mode", choices=["demo", "interactive"], default="demo",
                        help="demo (default): scripted failover demo; interactive: manual prompt")
    parser.add_argument("--poll", type=float, default=DEFAULT_POLL,
                        help=f"Seconds between demo polls (default: {DEFAULT_POLL})")
    args = parser.parse_args()
    if args.poll <= 0:
        parser.error("--poll must be positive")

    client = ServiceClient(args.host, args.port)
    try:
        if args.mode == "demo":
            Demo(client, args.poll).run()
        else:
            run_interactive(client)
    except KeyboardInterrupt:
        print()
        log("SHUTDOWN", "client stopped by operator.")
    finally:
        client.close()


if __name__ == "__main__":
    main()

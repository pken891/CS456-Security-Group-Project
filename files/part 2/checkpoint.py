#!/usr/bin/env python3


import argparse
import hashlib
import hmac
import json
import os
import sys

DEFAULT_PATH = "checkpoint.json"
KEY = os.environ.get("CKPT_KEY", "cs456-dev-checkpoint-key").encode()
MAX_CHECKPOINT_BYTES = 4 * 1024 * 1024   # Refuse absurdly large files


class CheckpointError(Exception):
    """A checkpoint is missing, unreadable, not valid JSON, malformed, or fails its HMAC."""


def backup_path(path: str) -> str:
    return path + ".bak"


def sign(state: dict, timestamp: float) -> str:
    """HMAC-SHA256 (hex) over the canonical JSON of state + timestamp (INTERFACE.md section 6)."""
    msg = json.dumps({"state": state, "timestamp": timestamp},
                     sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(KEY, msg, hashlib.sha256).hexdigest()


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_state(state) -> None:
    """Check the shape of a state dict. Raises CheckpointError on anything unexpected.

    The HMAC already proves the primary wrote the data, so this is defence in
    depth: the standby must never crash on a checkpoint, whatever is in it.
    """
    if not isinstance(state, dict):
        raise CheckpointError("malformed: state is not an object")
    sessions = state.get("sessions")
    failed = state.get("failed_counts")
    lockouts = state.get("lockouts")
    if not isinstance(sessions, dict) or not isinstance(failed, dict) or not isinstance(lockouts, list):
        raise CheckpointError("malformed: missing sessions, failed_counts or lockouts")
    for ticket, info in sessions.items():
        if not (isinstance(info, dict) and isinstance(info.get("user"), str)
                and _is_number(info.get("expires"))):
            raise CheckpointError(f"malformed: bad session entry {ticket[:16]!r}")
    for user, count in failed.items():
        if not (isinstance(count, int) and not isinstance(count, bool) and count >= 0):
            raise CheckpointError(f"malformed: bad failed_count for {user!r}")
    if not all(isinstance(user, str) for user in lockouts):
        raise CheckpointError("malformed: lockouts must be a list of usernames")


def load(path: str = DEFAULT_PATH) -> dict:
    """Read and verify one checkpoint file and return its state dict.

    Raises CheckpointError with a short reason, e.g. "missing",
    "not valid JSON", "HMAC mismatch (tampered)".
    """
    try:
        if os.path.getsize(path) > MAX_CHECKPOINT_BYTES:
            raise CheckpointError("file too large")
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise CheckpointError("missing") from None
    except OSError as err:
        raise CheckpointError(f"unreadable ({err})") from None

    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CheckpointError("not valid JSON (corrupted)") from None
    if not isinstance(doc, dict) or "state" not in doc or not isinstance(doc.get("hmac"), str):
        raise CheckpointError("malformed: missing state or hmac")
    if not _is_number(doc.get("timestamp")):
        raise CheckpointError("malformed: missing timestamp")

    try:
        expected = sign(doc["state"], doc["timestamp"])
    except (TypeError, ValueError):
        raise CheckpointError("malformed: state cannot be serialized") from None
    if not hmac.compare_digest(expected, doc["hmac"]):
        raise CheckpointError("HMAC mismatch (tampered)")

    validate_state(doc["state"])
    return doc["state"]


def load_with_fallback(path: str = DEFAULT_PATH, log=None):
    """Load checkpoint.json, else checkpoint.json.bak, else nothing.

    log is called with one line per file tried, in the INTERFACE.md format:
        [CHECKPOINT] REJECTED checkpoint.json: HMAC mismatch (tampered)
        [CHECKPOINT] loaded checkpoint.json.bak (sessions=1, lockouts=['bob'])

    Returns (state, source_filename), or (None, None) if neither file verifies.
    """
    for candidate in (path, backup_path(path)):
        name = os.path.basename(candidate)
        try:
            state = load(candidate)
        except CheckpointError as err:
            if log is not None:
                log(f"[CHECKPOINT] REJECTED {name}: {err}")
            continue
        if log is not None:
            log(f"[CHECKPOINT] loaded {name} (sessions={len(state['sessions'])}, "
                f"lockouts={state['lockouts']})")
        return state, name
    return None, None


def _atomic_write(path: str, data: bytes) -> None:
    """Write data to a temp file in the same directory, fsync it, then os.replace() it over path."""
    directory = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(directory, f".{os.path.basename(path)}.tmp-{os.getpid()}")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save(state: dict, timestamp: float, path: str = DEFAULT_PATH) -> dict:
    """Sign state and write it atomically to checkpoint.json and checkpoint.json.bak.

    Both files get the same signed document, built from the in-memory state.
    Returns the document that was written.
    """
    doc = {"state": state, "timestamp": timestamp, "hmac": sign(state, timestamp)}
    data = json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")
    _atomic_write(path, data)
    _atomic_write(backup_path(path), data)
    return doc


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect or verify auth-ticket-daemon checkpoints.")
    parser.add_argument("command", choices=["verify", "show"],
                        help="verify: check checkpoint.json and .bak (exit 1 if neither is valid); "
                             "show: print the newest valid state")
    parser.add_argument("--path", default=DEFAULT_PATH,
                        help=f"checkpoint file (default: {DEFAULT_PATH})")
    args = parser.parse_args()

    if args.command == "verify":
        ok = False
        for candidate in (args.path, backup_path(args.path)):
            try:
                state = load(candidate)
            except CheckpointError as err:
                print(f"{candidate}: INVALID ({err})")
            else:
                ok = True
                print(f"{candidate}: OK (sessions={len(state['sessions'])}, "
                      f"failed_counts={state['failed_counts']}, lockouts={state['lockouts']})")
        sys.exit(0 if ok else 1)

    state, source = load_with_fallback(args.path, log=lambda line: print(line, file=sys.stderr))
    if state is None:
        print("no valid checkpoint found")
        sys.exit(1)
    print(json.dumps(state, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

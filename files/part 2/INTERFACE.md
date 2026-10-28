# Part 2 Interface Contract (Recovery / Passive Redundancy)

This is the contract that `service.py` + `checkpoint.py` (Cameron Hugg),
`monitor.py` + `client.py` (Cameron Will) and `attacker.py` (Peter Kenoian)
are all built against. If you need to change something here, tell the team
first; the other scripts depend on it.

---

## 1. Runtime environment

- **Python 3.10+** (`attacker.py` uses `int | None` syntax). **Standard library only.**
- **All commands are run from inside `files/part 2/`**:

  ```bash
  cd "files/part 2"
  ```

- `checkpoint.json` (and `checkpoint.json.bak`) live in that working directory.
  `attacker.py --attack tamper` defaults to `./checkpoint.json`.
- Generated files (`logs/`, `checkpoint.json*`, `captured_beat.bin`,
  `monitor_incidents.log`) are git-ignored.

## 2. Processes and roles

| Process | Started by | Command (from `files/part 2/`) |
| :--- | :--- | :--- |
| Monitor / failover controller | operator | `python monitor.py` |
| Primary service | operator | `python service.py --role primary` |
| Standby service | **the monitor**, on failover only | `<sys.executable> service.py --role standby` (cwd = `files/part 2/`) |
| Client | operator | `python client.py` |

- There is **no always-running standby**. The monitor spawns a standby only
  after it detects a crash and has fenced (killed) the old primary.
- After a failover there is **exactly one** `service.py` process.
- The standby is spawned with **no other arguments** than `--role standby`, so
  every other option must have a working default.
- `service.py` must **not fork, daemonize, or re-exec itself**. The `pid` in
  its heartbeats must be the pid of the process the monitor spawned.
- Do not put the string `service.py` in the command line of any other script
  (`attacker.py` finds service processes by matching that string).

## 3. Heartbeat (UDP)

- UDP datagram to **`127.0.0.1:9999`** every **T = 1.0 s**, from a daemon thread (same as Part 1).
- Same JSON as Part 1, **plus** `pid` and `role`:

  ```json
  {"type": "HEARTBEAT", "service": "auth-ticket-daemon", "seq": 14,
   "timestamp": 1729450000.123, "status": "HEALTHY",
   "pid": 12345, "role": "primary"}
  ```

  | Field | Type | Meaning |
  | :--- | :--- | :--- |
  | `pid` | int | `os.getpid()` of the serving process |
  | `role` | str | always `"primary"` once the node is serving clients |

- A standby **must not send any heartbeat until it has been promoted**, which
  means the checkpoint has been loaded and TCP 8000 is bound and listening.
  The monitor takes the first heartbeat from the spawned pid to mean
  "service restored" and computes MTTR from it.
- The monitor fails the attempt and retries once if the standby sends no
  heartbeat within **10 s** of being spawned. Startup must fit well inside
  that.

Monitor timing: T = 1.0 s, N = 3, W = N x T = 3.0 s.

## 4. Client API (TCP)

- **TCP `127.0.0.1:8000`**, newline-delimited JSON: the client sends one JSON
  object per line, and the server answers with **exactly one JSON object on one
  line** (terminated by `\n`) per request.
- A connection can carry **many requests** (the client keeps one connection
  open and polls once per second). Several clients may be connected at the
  same time, so use one thread per connection or similar.
- Respond within about 1 s. The client treats a response that takes longer
  than 2 s as "service unavailable" (this is what happens to a primary frozen
  with SIGSTOP).
- Unknown `op`, missing fields, or invalid JSON must return
  `{"ok": false, "error": "bad_request"}`. **Never crash or close the
  connection because of it.**

### `login`

```json
{"op": "login", "user": "alice", "password": "alice123"}
```

| Case | Response |
| :--- | :--- |
| success | `{"ok": true, "ticket": "9f2c...e1", "expires": 1729450300.0}` |
| wrong password / unknown user | `{"ok": false, "error": "invalid_credentials", "failed_count": 2}` |
| user is locked (even with the right password) | `{"ok": false, "error": "locked_out"}` |

- `ticket`: random hex token (`secrets.token_hex(16)`). `expires`: epoch seconds, TTL >= 300 s.
- **Lockout after 3 consecutive failed logins.** A successful login resets the
  user's `failed_count` to 0. The login that makes the count reach 3 still
  returns `invalid_credentials` with `"failed_count": 3`. Later attempts return
  `locked_out`.

### `validate`

```json
{"op": "validate", "ticket": "9f2c...e1"}
```

| Case | Response |
| :--- | :--- |
| ticket known and not expired | `{"ok": true, "valid": true, "user": "alice"}` |
| unknown / expired | `{"ok": true, "valid": false}` |

### `status`

```json
{"op": "status", "user": "bob"}
```

```json
{"ok": true, "user": "bob", "failed_count": 3, "locked": true, "active_sessions": 0}
```

`active_sessions` = number of unexpired tickets held by that user.

### `state`

```json
{"op": "state"}
```

```json
{"ok": true, "node_pid": 12345, "role": "primary", "sessions": 1,
 "locked_users": ["bob"], "checkpoint_loaded": true}
```

- `node_pid` = `os.getpid()`, the same value as the heartbeat `pid`.
- `sessions` = count of unexpired tickets.
- `checkpoint_loaded` = `true` if this node restored its state from a verified
  checkpoint (`checkpoint.json` or `.bak`), otherwise `false`.

### Dummy users

| user | password |
| :--- | :--- |
| alice | alice123 |
| bob | bob123 |
| carol | carol123 |
| dave | dave123 |
| root | toor |

## 5. Startup by role

**`--role primary`** (started manually)
1. Start with empty state (`checkpoint_loaded: false`) and write a fresh checkpoint.
2. Bind TCP 8000 (`SO_REUSEADDR`), start heartbeats with `role: "primary"`.

**`--role standby`** (spawned by the monitor after it has killed the old primary)
1. Load and verify `checkpoint.json` (HMAC, see section 6).
2. If it is missing, not valid JSON, or the HMAC does not match, **reject it**,
   log why, and try `checkpoint.json.bak`. If that also fails, start with
   **empty state**. **Log which source was used**, for example:
   `[CHECKPOINT] REJECTED checkpoint.json: HMAC mismatch (tampered)` followed by
   `[CHECKPOINT] loaded checkpoint.json.bak (sessions=1, lockouts=['bob'])`.
3. Bind TCP 8000 with `SO_REUSEADDR`. **Retry the bind for a few seconds**
   (e.g. every 0.2 s for up to 5 s) in case the old socket is still closing.
4. Log that it was promoted, e.g. `[PROMOTED] standby -> PRIMARY (pid=..., checkpoint=...)`.
5. Only then start heartbeats, with `role: "primary"`, and keep checkpointing
   after every state change, exactly like a primary.

## 6. Checkpoint format (`checkpoint.json`)

This matches what `attacker.py --attack tamper` reads and edits:

```json
{
  "state": {
    "sessions": {
      "9f2c...e1": {"user": "alice", "expires": 1729450300.0}
    },
    "failed_counts": {"bob": 3},
    "lockouts": ["bob"]
  },
  "timestamp": 1729450012.345,
  "hmac": "3b1f...<64 hex chars>"
}
```

- `sessions`: ticket -> `{"user", "expires"}`. `failed_counts`: user -> int. `lockouts`: list of users.
- **HMAC**: HMAC-SHA256, hex digest, computed over the canonical JSON of
  `state` + `timestamp`:

  ```python
  import hashlib, hmac, json, os
  KEY = os.environ.get("CKPT_KEY", "cs456-dev-checkpoint-key").encode()

  def sign(state, timestamp):
      msg = json.dumps({"state": state, "timestamp": timestamp},
                       sort_keys=True, separators=(",", ":")).encode()
      return hmac.new(KEY, msg, hashlib.sha256).hexdigest()

  # verify: hmac.compare_digest(sign(doc["state"], doc["timestamp"]), doc["hmac"])
  ```

- **Write it after every state change** (login success, failed login, lockout,
  ticket expiry purge), **atomically**: write to a temp file in the same
  directory, `flush()` + `os.fsync()`, then `os.replace(tmp, "checkpoint.json")`.
- **`checkpoint.json.bak`** holds the last good copy. Write the *same signed
  document* to `checkpoint.json.bak` (atomically too) every time you write
  `checkpoint.json`. Build it from the in-memory state, **never by copying the
  file on disk** (that file may have been tampered with). If an attacker
  tampers with `checkpoint.json`, the standby can still recover the
  pre-crash state from `.bak`.
- Read-only requests (`validate`, `status`, `state`) must **not** rewrite the
  checkpoint. Otherwise the primary would overwrite the attacker's tampered
  file before it crashes, and the tamper test would prove nothing.

## 7. Random crash (same as Part 1)

- Each ~1 s operational cycle: `if random.random() < 0.08: ... os._exit(1)`
  (keep the `--crash-prob` flag). Log a `[FATAL]` line with the pid first.
- The cycle should not invent random logins that change state (see the note at
  the end of section 6). Real state changes come from the client.

## 8. What the monitor does on failover (for reference)

```
[CRASH DETECTED]     no heartbeat for >= W=3.0s (last seq, pid, elapsed)
[FENCING]            is old pid alive? if yes (e.g. SIGSTOP'd) -> SIGKILL / taskkill /F, confirm gone
[FAILOVER TRIGGERED] spawn `python service.py --role standby` (cwd = files/part 2)
[SERVICE RESTORED]   first heartbeat whose pid == spawned pid; prints MTTR
```

- Heartbeats from a fenced pid are ignored (`[FENCED] stale heartbeat ignored`).
- While a failover is in progress, a second failover is never started. The
  monitor retries a failed promotion once, and stops auto-failover
  (`[CRASH LOOP]`) after 5 failovers in 60 s.
- Linux/macOS: standby output goes to `logs/standby_<n>.log`. Windows: the
  standby opens in its own console window.

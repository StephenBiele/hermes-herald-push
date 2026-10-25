"""Encrypted, expiring gateway copy of provider-visible phone messages.

This is a best-effort snapshot, not a complete SMS/RCS archive. It stores no plaintext
message fields in SQLite. The gateway user can read the key, so encryption primarily
protects backups and raw database inspection, not a compromised gateway account.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OPTIONS = (1, 2, 7, 14)
MAX_ROWS = 10000
MAX_BATCH = 40
MAX_BODY = 1000
DAY_MS = 86_400_000


class MessageHistory:
    def __init__(self, root: Path, clock):
        self.root = root
        self.clock = clock

    @contextmanager
    def _db(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        path = self.root / "messages.sqlite3"
        db = sqlite3.connect(path, timeout=10)
        os.chmod(path, 0o600)
        db.execute("PRAGMA secure_delete=ON")
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("CREATE TABLE IF NOT EXISTS retention (device TEXT PRIMARY KEY, days INTEGER NOT NULL, synced INTEGER NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS messages (device TEXT NOT NULL, message_key TEXT NOT NULL, at INTEGER NOT NULL, "
                   "sealed BLOB NOT NULL, PRIMARY KEY(device, message_key))")
        db.execute("CREATE INDEX IF NOT EXISTS message_date ON messages(device, at DESC)")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _key(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.root / "messages.key"
        try:
            return path.read_bytes()
        except FileNotFoundError:
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                return path.read_bytes()
            key = os.urandom(32)
            with os.fdopen(fd, "wb") as out:
                out.write(key)
                out.flush()
                os.fsync(out.fileno())
            return key

    @staticmethod
    def _validate(messages: object):
        if not isinstance(messages, list) or len(messages) > MAX_BATCH:
            raise ValueError("bad message batch")
        checked = []
        for msg in messages:
            if not isinstance(msg, dict) or any(not isinstance(msg.get(k), str) for k in
                ("id", "source", "address", "body", "direction")):
                raise ValueError("bad message")
            thread = msg.get("thread_id")
            if type(thread) is int and thread >= 0:
                thread = str(thread)
            elif thread is None:
                thread = ""
            if not isinstance(thread, str):
                raise ValueError("bad message")
            at = msg.get("date_ms")
            if (type(at) is not int or at <= 0 or
                msg["source"] not in ("sms", "mms", "rcs") or
                msg["direction"] not in ("in", "out", "inbound", "outbound", "draft", "unknown") or
                not msg["id"] or len(msg["id"]) > 64 or
                len(thread) > 64 or len(msg["address"]) > 256 or
                len(msg["body"]) > MAX_BODY or
                any(type(msg.get(k, False)) is not bool for k in ("body_truncated", "address_truncated"))):
                raise ValueError("bad message")
            checked.append({**{k: msg[k] for k in ("id", "source", "address", "body", "date_ms", "direction")},
                            "thread_id": thread,
                            "body_truncated": msg.get("body_truncated", False),
                            "address_truncated": msg.get("address_truncated", False)})
        return checked

    def sync(self, device: str, days: object, messages: object) -> int:
        if type(days) is not int or days not in OPTIONS:
            raise ValueError("bad retention days")
        checked = self._validate(messages)  # Entire batch accepted or rejected, never partial.
        now = int(self.clock() * 1000)
        key = AESGCM(self._key())
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO retention(device, days, synced) VALUES(?, ?, ?)", (device, days, now))
            db.execute("DELETE FROM messages WHERE device=? AND at<?", (device, now - days * DAY_MS))
            for msg in checked:
                if msg["date_ms"] < now - days * DAY_MS or msg["date_ms"] > now + DAY_MS:
                    continue
                id_hash = hashlib.sha256((msg["source"] + ":" + msg["id"]).encode()).hexdigest()
                nonce = os.urandom(12)
                sealed = nonce + key.encrypt(nonce, json.dumps(msg, ensure_ascii=False).encode(), device.encode())
                db.execute("INSERT OR REPLACE INTO messages(device,message_key,at,sealed) VALUES(?,?,?,?)",
                           (device, id_hash, msg["date_ms"], sealed))
            db.execute("DELETE FROM messages WHERE device=? AND message_key IN "
                       "(SELECT message_key FROM messages WHERE device=? ORDER BY at DESC LIMIT -1 OFFSET ?)",
                       (device, device, MAX_ROWS))
        return len(checked)

    def purge(self):
        now = int(self.clock() * 1000)
        with self._db() as db:
            db.execute("DELETE FROM messages WHERE device NOT IN (SELECT device FROM retention)")
            db.execute("DELETE FROM messages WHERE EXISTS "
                       "(SELECT 1 FROM retention WHERE retention.device=messages.device "
                       "AND messages.at < ? - retention.days * ?)", (now, DAY_MS))

    def forget(self, device: str):
        with self._db() as db:
            db.execute("DELETE FROM messages WHERE device=?", (device,))
            db.execute("DELETE FROM retention WHERE device=?", (device,))

    def search(self, device: str, query: str = "", limit: int = 20, thread: str = "") -> dict:
        if not isinstance(query, str) or len(query) > 100 or not isinstance(thread, str) or len(thread) > 64 or \
                type(limit) is not int or limit not in range(1, 51):
            raise ValueError("bad history search")
        self.purge()
        with self._db() as db:
            synced = db.execute("SELECT synced FROM retention WHERE device=?", (device,)).fetchone()
            rows = db.execute("SELECT sealed FROM messages WHERE device=? ORDER BY at DESC LIMIT ?", (device, MAX_ROWS)).fetchall()
        aes = AESGCM(self._key())
        found = []
        for (sealed,) in rows:
            msg = json.loads(aes.decrypt(sealed[:12], sealed[12:], device.encode()))
            if thread and msg["thread_id"] != thread:
                continue
            if query and query.casefold() not in (msg["body"] + " " + msg["address"]).casefold():
                continue
            found.append(msg)
            if len(found) == limit:
                break
        return {"source": "retained", "last_synced_ms": synced[0] if synced else None,
                "complete": False, "messages": found}

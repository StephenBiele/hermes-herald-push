"""The retained message buffer is a distinct, bounded source from live phone search."""
import json
import sqlite3

import pytest

from herald_push.commands import make_handler
from herald_push.phone import Phones
from herald_push.store import Store

PHONE = "0b6f2c1e-1111-4222-8333-944445555666"
KEY = "a" * 64
SECOND = "99999999-aaaa-bbbb-cccc-dddddddddddd"
OTHER_KEY = "b" * 64


def message(mid, at, body="private text"):
    return {"id": mid, "source": "sms", "thread_id": "42", "address": "+15551234567",
            "body": body, "date_ms": at, "direction": "in"}


def test_sync_requires_authorized_phone_and_active_switch(tmp_path):
    now = [1_900_000_000.0]
    phones = Phones(Store(tmp_path), clock=lambda: now[0])
    h = make_handler(phones.store, "test", lambda: False, trusted=lambda: True, phones=phones)
    payload = {"device_id": PHONE, "key": KEY, "retention_days": 7, "messages": [message("1", int(now[0]*1000))]}
    assert json.loads(h("phone sync " + json.dumps(payload)))["ok"] is False
    phones.report(PHONE, KEY, "Pixel", ["phone_battery"])
    assert json.loads(h("phone sync " + json.dumps(payload)))["ok"] is False
    phones.report(PHONE, KEY, "Pixel", ["phone_messages"])
    assert json.loads(h("phone sync " + json.dumps({**payload, "key": OTHER_KEY})))["ok"] is False
    assert json.loads(h("phone sync " + json.dumps(payload)))["ok"] is True


def test_history_offline_dedupe_expiry_and_shortened_retention(tmp_path):
    now = [1_900_000_000.0]
    phones = Phones(Store(tmp_path), clock=lambda: now[0])
    phones.report(PHONE, KEY, "Pixel", ["phone_messages"])
    at = int(now[0] * 1000)
    phones.sync_messages(PHONE, 7, [message("1", at - 1000), message("2", at - 4 * 86400_000)],)
    phones.sync_messages(PHONE, 7, [message("1", at - 1000, "updated")])
    found = json.loads(phones.call("phone_messages", {"action": "history", "query": "updated"}))
    assert [m["body"] for m in found["messages"]] == ["updated"]
    assert found["source"] == "retained"
    # Shortening the retention purges immediately, including without a new sync batch.
    phones.sync_messages(PHONE, 2, [])
    assert [m["id"] for m in json.loads(phones.call("phone_messages", {"action": "history"}))["messages"]] == ["1"]
    now[0] += 3 * 86400
    assert json.loads(phones.call("phone_messages", {"action": "history"}))["messages"] == []


def test_no_plaintext_on_disk_and_switch_off_removes_buffer(tmp_path):
    now = [1_900_000_000.0]
    phones = Phones(Store(tmp_path), clock=lambda: now[0])
    phones.report(PHONE, KEY, "Pixel", ["phone_messages"])
    phones.sync_messages(PHONE, 7, [message("1", int(now[0]*1000), "unmistakable private message")])
    db = tmp_path / "phone" / "messages.sqlite3"
    assert b"unmistakable private message" not in db.read_bytes()
    phones.report(PHONE, KEY, "Pixel", [])
    assert json.loads(phones.call("phone_messages", {"action": "history"}))["error"]
    with sqlite3.connect(db) as con:
        assert con.execute("select count(*) from messages").fetchone()[0] == 0


def test_bad_sync_payload_is_not_partially_stored(tmp_path):
    now = [1_900_000_000.0]
    phones = Phones(Store(tmp_path), clock=lambda: now[0])
    phones.report(PHONE, KEY, "Pixel", ["phone_messages"])
    with pytest.raises(ValueError):
        phones.sync_messages(PHONE, 0, [message("1", int(now[0]*1000))])
    with pytest.raises(ValueError):
        phones.sync_messages(PHONE, 7, [message("1", int(now[0]*1000)), {"body": "bad"}])
    assert json.loads(phones.call("phone_messages", {"action": "history"}))["messages"] == []


def test_android_sync_wire_shape_is_accepted(tmp_path):
    now = [1_900_000_000.0]
    phones = Phones(Store(tmp_path), clock=lambda: now[0])
    phones.report(PHONE, KEY, "Pixel", ["phone_messages"])
    # MessagesTool.responseObject sends numeric or null thread IDs, and inbound/outbound directions.
    payload = {"id": "mms:123", "source": "rcs", "thread_id": 42,
               "address": "+15551234567", "body": "wire contract", "date_ms": int(now[0] * 1000),
               "direction": "inbound", "body_truncated": True}
    assert phones.sync_messages(PHONE, 7, [payload]) == 1
    found = json.loads(phones.call("phone_messages", {"action": "history", "thread_id": "42"}))
    assert found["messages"][0]["body"] == "wire contract"
    assert found["messages"][0]["body_truncated"] is True

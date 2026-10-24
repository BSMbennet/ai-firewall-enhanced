"""API-key lifecycle: creation, secrecy, scopes, revocation and rotation."""
import json
import threading
from datetime import datetime, timedelta, timezone

from conftest import chat, make_key


def test_secret_is_shown_once_and_only_a_hash_is_stored(client, db, world):
    key = make_key(client, db, world["owner"], name="k")
    assert key["key"].startswith("aifw_") and len(key["key"]) > 40
    stored = db.rows("api_keys", id=key["id"])[0]
    assert key["key"] not in json.dumps(stored)
    assert stored["key_hash"] != key["key"]
    listing = client.get("/v1/api-keys", headers=db.token(world["owner"])).json()
    assert key["key"] not in json.dumps(listing)
    assert "key_hash" not in json.dumps(listing)


def test_default_scope_is_chat_and_unknown_scopes_are_rejected(client, db, world):
    key = make_key(client, db, world["owner"])
    assert db.rows("api_keys", id=key["id"])[0]["scopes"] == ["chat"]
    for bad in (["*"], ["admin"], "chat", [""]):
        response = client.post("/v1/api-keys", json={"scopes": bad}, headers=db.token(world["owner"]))
        assert response.status_code == 400, bad


def test_expiry_is_bounded(client, db, world):
    key = make_key(client, db, world["owner"], expires_days=999999)
    expires = datetime.fromisoformat(db.rows("api_keys", id=key["id"])[0]["expires_at"])
    assert expires <= datetime.now(timezone.utc) + timedelta(days=3651)


def test_only_admin_roles_can_create_or_revoke_keys(client, db, world):
    for role in ("developer", "member", "viewer"):
        assert client.post("/v1/api-keys", json={}, headers=db.token(world[role])).status_code == 403
    key = make_key(client, db, world["owner"])
    for role in ("developer", "member", "viewer"):
        assert client.delete(f"/v1/api-keys/{key['id']}", headers=db.token(world[role])).status_code == 403


def test_revoking_unknown_key_is_404_not_success(client, db, world):
    assert client.delete("/v1/api-keys/does-not-exist", headers=db.token(world["owner"])).status_code == 404


def rotate(client, db, user, key_id, **body):
    return client.post(f"/v1/enterprise/api-keys/{key_id}/rotate", json=body, headers=db.token(user))


def test_immediate_rotation_replaces_the_key(client, db, world, provider):
    old = make_key(client, db, world["owner"], name="svc")
    assert chat(client, old["key"]).status_code == 200
    response = rotate(client, db, world["owner"], old["id"])
    assert response.status_code == 200, response.text
    new = response.json()
    assert new["key"] != old["key"]
    assert chat(client, new["key"]).status_code == 200
    assert chat(client, old["key"]).status_code == 401  # reuse of the old key
    old_row = db.rows("api_keys", id=old["id"])[0]
    assert old_row["is_active"] is False and old_row["revoked_at"]
    assert db.rows("api_keys", id=new["id"])[0]["rotated_from"] == old["id"]


def test_rotation_preserves_scopes_and_bindings(client, db, world):
    old = make_key(client, db, world["owner"], name="svc")
    db.rows("api_keys", id=old["id"])[0]["scopes"] = ["chat"]
    new = rotate(client, db, world["owner"], old["id"]).json()
    row = db.rows("api_keys", id=new["id"])[0]
    assert row["scopes"] == ["chat"] and row["organization_id"] == world["org_a"]


def test_rotation_with_grace_expires_the_predecessor(client, db, world, provider):
    old = make_key(client, db, world["owner"], expires_days=365)
    new = rotate(client, db, world["owner"], old["id"], grace_minutes=10).json()
    old_row = db.rows("api_keys", id=old["id"])[0]
    grace_end = datetime.fromisoformat(old_row["expires_at"])
    now = datetime.now(timezone.utc)
    assert now < grace_end <= now + timedelta(minutes=10, seconds=5)
    assert chat(client, old["key"]).status_code == 200 and chat(client, new["key"]).status_code == 200
    old_row["expires_at"] = (now - timedelta(seconds=1)).isoformat()  # grace window elapses
    assert chat(client, old["key"]).status_code == 401
    assert chat(client, new["key"]).status_code == 200


def test_grace_period_is_capped(client, db, world):
    old = make_key(client, db, world["owner"])
    response = rotate(client, db, world["owner"], old["id"], grace_minutes=10**7)
    assert response.status_code == 200
    grace_end = datetime.fromisoformat(db.rows("api_keys", id=old["id"])[0]["expires_at"])
    assert grace_end <= datetime.now(timezone.utc) + timedelta(days=7, minutes=1)


def test_cannot_rotate_a_revoked_or_already_rotated_key(client, db, world):
    old = make_key(client, db, world["owner"])
    assert rotate(client, db, world["owner"], old["id"]).status_code == 200
    assert rotate(client, db, world["owner"], old["id"]).status_code == 409
    other = make_key(client, db, world["owner"])
    client.delete(f"/v1/api-keys/{other['id']}", headers=db.token(world["owner"]))
    assert rotate(client, db, world["owner"], other["id"]).status_code == 409


def test_concurrent_rotation_yields_exactly_one_successor(client, db, world):
    old = make_key(client, db, world["owner"])
    results = []

    def go():
        results.append(rotate(client, db, world["owner"], old["id"], grace_minutes=5).status_code)

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results).count(200) == 1, results
    assert results.count(409) == 7, results
    successors = [r for r in db.rows("api_keys") if r.get("rotated_from") == old["id"]]
    assert len(successors) == 1


def test_failed_rotation_leaves_the_old_key_usable(client, db, world, provider):
    old = make_key(client, db, world["owner"])
    db.fail_inserts.add("api_keys")
    response = rotate(client, db, world["owner"], old["id"])
    db.fail_inserts.clear()
    assert response.status_code >= 500
    assert chat(client, old["key"]).status_code == 200
    assert [r for r in db.rows("api_keys") if r.get("rotated_from")] == []
    assert rotate(client, db, world["owner"], old["id"]).status_code == 200  # claim was released


def test_only_owner_or_admin_may_rotate(client, db, world):
    old = make_key(client, db, world["owner"])
    for role in ("security", "developer", "member", "viewer"):
        assert rotate(client, db, world[role], old["id"]).status_code == 403


def test_secrets_never_appear_in_logs_or_error_bodies(client, db, world, capsys, caplog):
    key = make_key(client, db, world["owner"])
    chat(client, key["key"])
    new = rotate(client, db, world["owner"], key["id"]).json()
    chat(client, key["key"])  # rejected old key
    bad = client.post("/v1/chat/completions", json={}, headers={"Authorization": f"Bearer {new['key']}"})
    client.delete(f"/v1/api-keys/{new['id']}", headers=db.token(world["owner"]))
    rejected = chat(client, new["key"])
    out = capsys.readouterr()
    haystack = out.out + out.err + caplog.text + bad.text + rejected.text
    assert key["key"] not in haystack and new["key"] not in haystack


def test_key_lifecycle_is_audited_without_secrets(client, db, world):
    key = make_key(client, db, world["owner"])
    new = rotate(client, db, world["owner"], key["id"]).json()
    client.delete(f"/v1/api-keys/{new['id']}", headers=db.token(world["owner"]))
    events = db.rows("audit_events", organization_id=world["org_a"])
    assert [e["action"] for e in events] == ["api_key.created", "api_key.rotated", "api_key.revoked"]
    assert all(e["actor_user_id"] == world["owner"] for e in events)
    assert key["key"] not in json.dumps(events) and new["key"] not in json.dumps(events)

import asyncio

from app.audit import GENESIS, record_event, verify_chain


def rows_for(db, org):
    return [r for r in db.rows("audit_events") if r["organization_id"] == org]


def test_chain_links_and_detects_tampering(client, db):
    import app.main as sc
    mgr = sc.supabase_manager
    for i in range(4):
        assert asyncio.run(record_event(mgr, organization_id="o1", actor_user_id="u", action=f"a{i}", resource_type="t"))
    rows = rows_for(db, "o1")
    assert rows[0]["metadata"]["chain"]["prev"] == GENESIS
    assert verify_chain(rows)["ok"] and verify_chain(rows)["checked"] == 4
    edited = [dict(r) for r in rows]; edited[1]["outcome"] = "denied"
    assert verify_chain(edited)["ok"] is False
    assert verify_chain(rows[:1] + rows[2:])["ok"] is False  # deleted row
    assert verify_chain([rows[0], rows[2], rows[1], rows[3]])["ok"] is False  # reordered


def test_chains_are_per_organisation(client, db):
    import app.main as sc
    mgr = sc.supabase_manager
    asyncio.run(record_event(mgr, organization_id="o1", actor_user_id="u", action="x", resource_type="t"))
    asyncio.run(record_event(mgr, organization_id="o2", actor_user_id="u", action="y", resource_type="t"))
    assert rows_for(db, "o2")[0]["metadata"]["chain"]["prev"] == GENESIS


def test_verify_endpoint_roles_and_tamper_detection(client, db, world):
    from tests.conftest import make_key
    make_key(client, db, world["owner"], name="k")
    ok = client.get("/v1/audit/verify", headers=db.token(world["owner"]))
    assert ok.status_code == 200 and ok.json()["ok"] is True and ok.json()["checked"] >= 1
    for role in ("developer", "member"):
        assert client.get("/v1/audit/verify", headers=db.token(world[role])).status_code == 403
    db.rows("audit_events", organization_id=world["org_a"])[0]["outcome"] = "denied"
    assert client.get("/v1/audit/verify", headers=db.token(world["security"])).json()["ok"] is False


def test_scim_token_lifecycle_is_audited(client, db, world):
    r = client.post("/v1/enterprise/scim/tokens", json={}, headers=db.token(world["owner"]))
    assert r.status_code == 200, r.text
    client.delete(f"/v1/enterprise/scim/tokens/{r.json()['token_id']}", headers=db.token(world["owner"]))
    actions = {e["action"] for e in db.rows("audit_events", organization_id=world["org_a"])}
    assert {"scim_token.created", "scim_token.revoked"} <= actions

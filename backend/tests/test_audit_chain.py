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

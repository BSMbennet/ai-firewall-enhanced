"""Server-side authorization, role hierarchy and tenant isolation (application level)."""
import pytest

from conftest import make_key


def member_row(db, user_id):
    return db.rows("organization_members", user_id=user_id)[0]


# --- suspended / removed employees -------------------------------------------------

@pytest.mark.parametrize("status", ["suspended", "removed"])
def test_suspended_or_removed_member_is_denied_on_every_authenticated_route(client, db, world, status):
    token = db.token(world["developer"])
    assert client.get("/v1/organization/applications", headers=token).status_code == 200
    member_row(db, world["developer"])["status"] = status
    for path in ("/v1/organization/applications", "/v1/organization/stats", "/v1/api-keys"):
        assert client.get(path, headers=token).status_code == 403, path


def test_invited_member_can_still_sign_in(client, db, world):
    member_row(db, world["member"])["status"] = "invited"
    assert client.get("/v1/organization/applications", headers=db.token(world["member"])).status_code == 200


def test_suspension_is_effective_even_if_auth_ban_fails(client, db, world):
    db.fail_auth_admin = True
    target = member_row(db, world["developer"])
    response = client.patch(f"/v1/organization/members/{target['id']}", json={"status": "suspended"},
                            headers=db.token(world["admin"]))
    assert response.status_code == 200
    assert response.json()["member"]["auth_sync"] == "failed"
    assert client.get("/v1/organization/applications", headers=db.token(world["developer"])).status_code == 403


def test_reactivation_lifts_the_auth_ban(client, db, world):
    target = member_row(db, world["developer"])
    client.patch(f"/v1/organization/members/{target['id']}", json={"status": "suspended"}, headers=db.token(world["admin"]))
    assert db.users[world["developer"]]["banned"] is True
    client.patch(f"/v1/organization/members/{target['id']}", json={"status": "active"}, headers=db.token(world["admin"]))
    assert db.users[world["developer"]]["banned"] is False


def test_scim_deactivation_revokes_access(client, db, world):
    import hashlib
    token = "scim_testtoken"
    db.tables["scim_tokens"] = [{"id": "t1", "organization_id": world["org_a"], "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                                 "expires_at": None, "revoked_at": None}]
    target = member_row(db, world["developer"])
    slug = db.rows("organizations", id=world["org_a"])[0]["slug"]
    response = client.patch(f"/v1/enterprise/scim/{slug}/Users/{target['id']}", json={"active": False},
                            headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    # The Auth ban took effect, so the identity provider rejects the token (401). The independent database
    # status check (403) is proven by test_suspension_is_effective_even_if_auth_ban_fails.
    assert client.get("/v1/organization/applications", headers=db.token(world["developer"])).status_code == 401
    assert db.users[world["developer"]]["banned"] is True
    assert member_row(db, world["developer"])["status"] != "active"


# --- privilege escalation ------------------------------------------------------------

def test_admin_cannot_modify_suspend_or_remove_the_owner(client, db, world):
    owner = member_row(db, world["owner"])
    for body in ({"status": "suspended"}, {"status": "removed"}, {"role": "viewer"}):
        response = client.patch(f"/v1/organization/members/{owner['id']}", json=body, headers=db.token(world["admin"]))
        assert response.status_code == 403, body
    assert member_row(db, world["owner"])["status"] == "active"
    assert member_row(db, world["owner"])["role"] == "owner"
    assert client.get("/v1/organization/applications", headers=db.token(world["owner"])).status_code == 200


def test_nobody_can_change_their_own_role_or_status(client, db, world):
    for who in ("admin", "security", "owner"):
        me = member_row(db, world[who])
        for body in ({"role": "admin"}, {"status": "suspended"}):
            assert client.patch(f"/v1/organization/members/{me['id']}", json=body, headers=db.token(world[who])).status_code == 403


def test_actor_cannot_grant_a_role_at_or_above_their_own(client, db, world):
    target = member_row(db, world["member"])
    assert client.patch(f"/v1/organization/members/{target['id']}", json={"role": "admin"},
                        headers=db.token(world["admin"])).status_code == 403
    assert client.patch(f"/v1/organization/members/{target['id']}", json={"role": "admin"},
                        headers=db.token(world["security"])).status_code == 403
    assert member_row(db, world["member"])["role"] == "member"
    assert client.patch(f"/v1/organization/members/{target['id']}", json={"role": "developer"},
                        headers=db.token(world["admin"])).status_code == 200
    assert client.patch(f"/v1/organization/members/{target['id']}", json={"role": "admin"},
                        headers=db.token(world["owner"])).status_code == 200


def test_admin_cannot_manage_a_peer_admin(client, db, world):
    other = db.add_member(world["org_a"], "admin")
    response = client.patch(f"/v1/organization/members/{member_row(db, other)['id']}", json={"status": "suspended"},
                            headers=db.token(world["admin"]))
    assert response.status_code == 403


def test_invite_cannot_grant_role_above_actor(client, db, world):
    response = client.post("/v1/organization/members", json={"email": "new@example.test", "role": "admin"},
                           headers=db.token(world["security"]))
    assert response.status_code == 403


def test_invalid_invite_email_is_400_not_502(client, db, world):
    response = client.post("/v1/organization/members", json={"email": "not-an-email"}, headers=db.token(world["admin"]))
    assert response.status_code == 400


# --- RBAC on read/mutate endpoints -----------------------------------------------------

@pytest.mark.parametrize("role,expected", [("owner", 200), ("admin", 200), ("security", 200), ("viewer", 200),
                                           ("developer", 403), ("member", 403)])
def test_raw_audit_data_is_limited_to_audit_readers(client, db, world, role, expected):
    for path in ("/v1/enterprise/audit/export", "/v1/enterprise/audit/search", "/v1/enterprise/analytics",
                 "/v1/dashboard/recent-requests"):
        assert client.get(path, headers=db.token(world[role])).status_code == expected, path


def test_aggregate_stats_remain_available_to_every_role(client, db, world):
    for role in ("owner", "admin", "security", "developer", "member", "viewer"):
        assert client.get("/v1/dashboard/stats", headers=db.token(world[role])).status_code == 200


@pytest.mark.parametrize("role,expected", [("owner", 200), ("security", 200), ("admin", 200),
                                           ("developer", 403), ("member", 403), ("viewer", 403)])
def test_only_security_roles_can_change_alert_state(client, db, world, role, expected):
    db.tables["security_alerts"] = [{"id": "al-1", "organization_id": world["org_a"], "status": "open"}]
    response = client.patch("/v1/enterprise/alerts/al-1", json={"status": "acknowledged"}, headers=db.token(world[role]))
    assert response.status_code == expected


# --- cross-tenant negative tests ---------------------------------------------------------

def test_org_a_cannot_touch_org_b_records_even_with_known_ids(client, db, world):
    org_b_member = db.add_member(world["org_b"], "developer")
    b_member = member_row(db, org_b_member)
    b_key = make_key(client, db, world["owner_b"], name="b-key")
    b_app = client.post("/v1/organization/applications", json={"name": "b-app"}, headers=db.token(world["owner_b"])).json()["application"]
    db.tables["security_alerts"] = [{"id": "al-b", "organization_id": world["org_b"], "status": "open"}]
    a_owner = db.token(world["owner"])

    assert client.patch(f"/v1/organization/members/{b_member['id']}", json={"status": "suspended"}, headers=a_owner).status_code == 404
    assert member_row(db, org_b_member)["status"] == "active"
    assert client.delete(f"/v1/api-keys/{b_key['id']}", headers=a_owner).status_code == 404
    assert db.rows("api_keys", id=b_key["id"])[0]["is_active"] is True
    assert client.post(f"/v1/enterprise/api-keys/{b_key['id']}/rotate", json={}, headers=a_owner).status_code == 404
    assert client.patch(f"/v1/organization/applications/{b_app['id']}", json={"status": "disabled"}, headers=a_owner).status_code == 404
    assert client.patch("/v1/organization/policies/pol-b", json={"rate_limit_per_minute": 1}, headers=a_owner).status_code == 404
    assert client.patch("/v1/enterprise/alerts/al-b", json={"status": "resolved"}, headers=a_owner).status_code == 404
    assert client.get(f"/v1/enterprise/activity/applications/{b_app['id']}", headers=a_owner).status_code == 404
    assert client.get(f"/v1/enterprise/activity/employees/{b_member['id']}", headers=a_owner).status_code == 404


def test_listings_only_contain_own_organisation(client, db, world):
    make_key(client, db, world["owner_b"], name="b-key")
    make_key(client, db, world["owner"], name="a-key")
    keys = client.get("/v1/api-keys", headers=db.token(world["owner"])).json()["keys"]
    assert [k["name"] for k in keys] == ["a-key"]
    members = client.get("/v1/organization/members", headers=db.token(world["owner"])).json()["members"]
    assert {m["organization_id"] for m in members} == {world["org_a"]}


def test_client_supplied_organization_ids_are_ignored(client, db, world):
    response = client.post("/v1/api-keys", json={"name": "x", "organization_id": world["org_b"]}, headers=db.token(world["owner"]))
    assert response.status_code == 200
    assert db.rows("api_keys", id=response.json()["id"])[0]["organization_id"] == world["org_a"]


def test_invalid_jwt_is_401(client):
    assert client.get("/v1/organization", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert client.get("/v1/organization").status_code == 401

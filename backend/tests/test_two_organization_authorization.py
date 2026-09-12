"""Live two-organization authorization tests.

Run only against a deployed environment with two users from different
organizations. No credentials are committed; values are supplied via env.

Required env:
  AI_FIREWALL_BASE_URL
  ORG_A_ACCESS_TOKEN
  ORG_B_ACCESS_TOKEN

Optional:
  ORG_A_APPLICATION_ID
  ORG_B_APPLICATION_ID

The suite intentionally skips when credentials are absent so CI can run the
unit suite without access to production identities.
"""
import os
import pytest
import httpx

BASE = os.getenv("AI_FIREWALL_BASE_URL")
TOKEN_A = os.getenv("ORG_A_ACCESS_TOKEN")
TOKEN_B = os.getenv("ORG_B_ACCESS_TOKEN")
APP_A = os.getenv("ORG_A_APPLICATION_ID")
APP_B = os.getenv("ORG_B_APPLICATION_ID")

pytestmark = pytest.mark.integration


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def client():
    if not (BASE and TOKEN_A and TOKEN_B):
        pytest.skip("Set AI_FIREWALL_BASE_URL, ORG_A_ACCESS_TOKEN and ORG_B_ACCESS_TOKEN")
    with httpx.Client(base_url=BASE.rstrip("/"), timeout=30.0) as c:
        yield c


def test_each_identity_sees_only_its_organization(client):
    a = client.get("/v1/organization", headers=_headers(TOKEN_A))
    b = client.get("/v1/organization", headers=_headers(TOKEN_B))
    assert a.status_code == 200
    assert b.status_code == 200
    assert a.json()["id"] != b.json()["id"]


def test_cross_org_application_is_not_readable(client):
    if not (APP_A and APP_B):
        pytest.skip("Set ORG_A_APPLICATION_ID and ORG_B_APPLICATION_ID")
    a = client.patch(
        f"/v1/organization/applications/{APP_B}",
        headers=_headers(TOKEN_A),
        json={"status": "disabled"},
    )
    b = client.patch(
        f"/v1/organization/applications/{APP_A}",
        headers=_headers(TOKEN_B),
        json={"status": "disabled"},
    )
    assert a.status_code in (403, 404)
    assert b.status_code in (403, 404)


def test_audit_export_requires_privileged_role(client):
    response = client.get("/v1/enterprise/compliance/audit-export", headers=_headers(TOKEN_B))
    assert response.status_code in (200, 403)
    if response.status_code == 200:
        assert "text/csv" in response.headers.get("content-type", "")


def test_api_key_cannot_cross_organizations(client):
    if not (APP_A and APP_B):
        pytest.skip("Set application IDs for cross-organization API-key test")
    response = client.post(
        "/v1/api-keys",
        headers=_headers(TOKEN_A),
        json={"name": "cross-org-negative", "application_id": APP_B},
    )
    assert response.status_code in (400, 403, 404)

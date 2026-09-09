from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from typing import Any, Dict
import hashlib
import hmac
import os
import time
import httpx

from app.auth import AuthManager, get_current_user
from app.supabase_client import SupabaseManager

router = APIRouter(prefix="/v1/billing", tags=["billing"])
supabase = SupabaseManager()
auth = AuthManager()

PLANS = {
    "starter": {"name": "Starter", "price_cents": 2900, "included_seats": 5, "requests_month": 10000, "features": ["AI gateway", "PII protection", "Prompt injection protection", "Audit logs"]},
    "professional": {"name": "Professional", "price_cents": 7900, "included_seats": 25, "requests_month": 100000, "features": ["Everything in Starter", "Advanced policies", "SSO/SCIM", "Security operations"]},
    "enterprise": {"name": "Enterprise", "price_cents": None, "included_seats": 100, "requests_month": None, "features": ["Everything in Professional", "Government controls", "Custom retention", "Priority support"]},
}

def _stripe_base():
    return "https://api.stripe.com/v1"

def _stripe_headers():
    key = os.getenv("STRIPE_SECRET_KEY")
    if not key:
        raise HTTPException(503, "Billing is not configured")
    return {"Authorization": f"Bearer {key}"}

async def _org(user_id: str):
    if not supabase._initialized:
        await supabase.initialize()
    org = await supabase.get_organization_for_user(user_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    return org

async def _billing_row(org_id: str):
    r = supabase.client.table("billing_subscriptions").select("*").eq("organization_id", org_id).maybe_single().execute()
    return r.data

async def _customer_id(org: Dict, user_id: str):
    row = supabase.client.table("billing_customers").select("stripe_customer_id").eq("organization_id", org["id"]).maybe_single().execute().data
    if row:
        return row["stripe_customer_id"]
    profile = await supabase.get_profile(user_id) or {}
    email = profile.get("email") or ""
    data = {"name": org.get("name") or "AI Firewall customer", "metadata[organization_id]": org["id"]}
    if email:
        data["email"] = email
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(f"{_stripe_base()}/customers", data=data, headers=_stripe_headers())
    if response.status_code >= 400:
        raise HTTPException(502, "Unable to create billing customer")
    customer = response.json()
    supabase.client.table("billing_customers").insert({"organization_id": org["id"], "stripe_customer_id": customer["id"]}).execute()
    return customer["id"]

@router.get("/plans")
async def plans():
    return {"plans": PLANS}

@router.get("/subscription")
async def subscription(user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    row = await _billing_row(org["id"])
    return {"organization_id": org["id"], "subscription": row, "plan": PLANS.get((row or {}).get("plan_key", "starter"), PLANS["starter"])}

@router.post("/checkout")
async def checkout(payload: Dict[str, Any], user_id: str = Depends(auth.require_owner_or_admin)):
    plan_key = str(payload.get("plan") or "starter").lower()
    if plan_key not in PLANS or plan_key == "enterprise":
        raise HTTPException(400, "Select a self-service plan")
    price_id = os.getenv(f"STRIPE_PRICE_{plan_key.upper()}")
    if not price_id:
        raise HTTPException(503, f"Stripe price for {plan_key} is not configured")
    org = await _org(user_id)
    customer = await _customer_id(org, user_id)
    frontend = os.getenv("FRONTEND_URL", "http://localhost:5173").split(",")[0].rstrip("/")
    seats = max(1, int(payload.get("seats") or 1))
    data = {
        "mode": "subscription",
        "customer": customer,
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": str(seats),
        "success_url": f"{frontend}/settings?billing=success",
        "cancel_url": f"{frontend}/settings?billing=cancelled",
        "client_reference_id": org["id"],
        "metadata[organization_id]": org["id"],
        "metadata[plan_key]": plan_key,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(f"{_stripe_base()}/checkout/sessions", data=data, headers=_stripe_headers())
    if response.status_code >= 400:
        raise HTTPException(502, "Unable to create checkout session")
    return {"url": response.json().get("url"), "session_id": response.json().get("id")}

@router.post("/portal")
async def portal(user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    customer = await _customer_id(org, user_id)
    frontend = os.getenv("FRONTEND_URL", "http://localhost:5173").split(",")[0].rstrip("/")
    data = {"customer": customer, "return_url": f"{frontend}/settings"}
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(f"{_stripe_base()}/billing_portal/sessions", data=data, headers=_stripe_headers())
    if response.status_code >= 400:
        raise HTTPException(502, "Unable to create customer portal session")
    return {"url": response.json().get("url")}

@router.get("/usage")
async def usage(user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    start = datetime.now(timezone.utc).date().replace(day=1).isoformat()
    row = supabase.client.table("usage_counters").select("*").eq("organization_id", org["id"]).eq("period_start", start).maybe_single().execute().data or {"request_count": 0, "blocked_count": 0, "tokens_used": 0}
    sub = await _billing_row(org["id"])
    plan_key = (sub or {}).get("plan_key", "starter")
    return {"period_start": start, "usage": row, "limits": PLANS.get(plan_key, PLANS["starter"])}

@router.post("/webhook")
async def webhook(request: Request):
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    body = await request.body()
    signature = request.headers.get("stripe-signature", "")
    if not secret:
        raise HTTPException(503, "Webhook is not configured")
    try:
        parts = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in signature.split(",") if "=" in item}
        timestamp = int(parts.get("t", "0"))
        provided = parts.get("v1", "")
        signed = f"{timestamp}.{body.decode('utf-8')}".encode()
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        if abs(time.time() - timestamp) > 300 or not hmac.compare_digest(expected, provided):
            raise ValueError
    except Exception:
        raise HTTPException(400, "Invalid Stripe signature")
    event = await request.json()
    event_id = event.get("id")
    event_type = event.get("type") or "unknown"
    existing = supabase.client.table("billing_events").select("id").eq("stripe_event_id", event_id).maybe_single().execute().data if event_id else None
    if existing:
        return {"received": True, "duplicate": True}
    obj = (event.get("data") or {}).get("object") or {}
    metadata = obj.get("metadata") or {}
    org_id = metadata.get("organization_id") or ((obj.get("subscription_details") or {}).get("metadata") or {}).get("organization_id")
    if event_type in {"checkout.session.completed", "customer.subscription.created", "customer.subscription.updated"}:
        subscription_id = obj.get("subscription") if event_type == "checkout.session.completed" else obj.get("id")
        customer_id = obj.get("customer")
        if subscription_id and customer_id:
            items = (obj.get("items") or {}).get("data") or []
            quantity = int(((items[0].get("quantity") if items else None) or 1))
            price = ((items[0].get("price") if items else None) or {})
            price_id = price.get("id")
            plan_key = metadata.get("plan_key") or next((k for k in PLANS if os.getenv(f"STRIPE_PRICE_{k.upper()}") == price_id), "starter")
            if org_id:
                supabase.client.table("billing_subscriptions").upsert({"organization_id": org_id, "stripe_subscription_id": subscription_id, "stripe_customer_id": customer_id, "plan_key": plan_key, "status": obj.get("status", "active"), "seat_quantity": quantity, "current_period_end": datetime.fromtimestamp(obj["current_period_end"], tz=timezone.utc).isoformat() if obj.get("current_period_end") else None, "cancel_at_period_end": bool(obj.get("cancel_at_period_end", False)), "updated_at": datetime.now(timezone.utc).isoformat()}, on_conflict="organization_id").execute()
    elif event_type in {"customer.subscription.deleted", "invoice.payment_failed"}:
        customer_id = obj.get("customer")
        if customer_id:
            supabase.client.table("billing_subscriptions").update({"status": "canceled" if event_type.endswith("deleted") else "past_due", "updated_at": datetime.now(timezone.utc).isoformat()}).eq("stripe_customer_id", customer_id).execute()
    if event_id:
        supabase.client.table("billing_events").insert({"stripe_event_id": event_id, "event_type": event_type, "organization_id": org_id, "payload": {"id": event_id, "type": event_type}}).execute()
    return {"received": True}

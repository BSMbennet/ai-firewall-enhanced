import os
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class ResendEmailService:
    """Small Resend HTTP API client used for transactional platform emails."""

    def __init__(self) -> None:
        self.api_key = os.getenv("RESEND_API_KEY", "").strip()
        self.from_email = os.getenv("RESEND_FROM_EMAIL", "AI Firewall <onboarding@resend.dev>")
        self.enabled = bool(self.api_key)

    async def send(
        self,
        *,
        to: str | List[str],
        subject: str,
        html: str,
        text: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.enabled:
            logger.warning("Resend is not configured; email skipped")
            return {"sent": False, "skipped": True, "reason": "RESEND_API_KEY is not configured"}

        recipients = [to] if isinstance(to, str) else to
        payload: Dict[str, Any] = {
            "from": self.from_email,
            "to": recipients,
            "subject": subject,
            "html": html,
        }
        if text:
            payload["text"] = text
        if reply_to:
            payload["reply_to"] = reply_to

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return {"sent": True, "id": data.get("id"), "provider": "resend"}
        except httpx.HTTPStatusError as exc:
            logger.error("Resend rejected email: %s", exc.response.text)
            return {"sent": False, "error": "Email provider rejected the request"}
        except Exception as exc:
            logger.exception("Resend email failed: %s", exc)
            return {"sent": False, "error": "Unable to send email"}

    async def send_employee_invitation(
        self,
        *,
        email: str,
        full_name: str,
        organization_name: str = "your organization",
        role: str = "member",
        inviter_name: str = "AI Firewall administrator",
        invite_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        safe_name = full_name.strip() or "there"
        url = invite_url or os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/") + "/login"
        subject = f"You're invited to {organization_name} on AI Firewall"
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:24px;color:#0f172a">
          <h1 style="margin-bottom:12px">You're invited to AI Firewall</h1>
          <p>Hi {safe_name},</p>
          <p>{inviter_name} invited you to join <strong>{organization_name}</strong> as a <strong>{role}</strong>.</p>
          <p style="margin:28px 0">
            <a href="{url}" style="background:#2563eb;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none">Open AI Firewall</a>
          </p>
          <p style="color:#64748b;font-size:14px">If you were not expecting this invitation, you can ignore this email.</p>
        </div>
        """
        return await self.send(to=email, subject=subject, html=html)


email_service = ResendEmailService()

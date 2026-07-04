# app/webhook.py
import httpx
from typing import Dict, List
import json
from datetime import datetime

class WebhookNotifier:
    """Webhook notification system for alerts"""
    
    def __init__(self):
        self.webhooks = {}  # user_id -> {url: str, events: List[str]}
    
    async def configure(self, user_id: str, url: str, events: List[str]):
        """Configure webhook for user"""
        self.webhooks[user_id] = {
            "url": url,
            "events": events,
            "created_at": datetime.utcnow()
        }
    
    async def send_alert(self, user_id: str, alert_data: Dict):
        """Send alert via webhook"""
        if user_id not in self.webhooks:
            return
        
        webhook = self.webhooks[user_id]
        event_type = alert_data.get("type")
        
        if event_type not in webhook["events"]:
            return
        
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "event": event_type,
            "data": alert_data
        }
        
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    webhook["url"],
                    json=payload,
                    timeout=5.0
                )
        except Exception as e:
            print(f"Webhook delivery failed: {e}")
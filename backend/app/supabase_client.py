from supabase import create_client, Client
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import secrets
import json

class SupabaseManager:
    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_ANON_KEY")
        self.client: Optional[Client] = None
        self._initialized = False

    async def initialize(self):
        """Initialize Supabase client"""
        if not self.supabase_url or not self.supabase_key:
            raise ValueError("SUPABASE_URL and SUPABASE_ANON_KEY must be set")
        self.client = create_client(self.supabase_url, self.supabase_key)
        self._initialized = True
        await self.create_tables()

    async def create_tables(self):
        """Create necessary tables if they don't exist"""
        # Tables are created via migrations, but ensure they exist
        pass

    async def health_check(self) -> bool:
        """Check if Supabase is healthy"""
        try:
            if not self._initialized:
                await self.initialize()
            # Simple query to check connection
            result = self.client.table("users").select("count", count="exact").limit(1).execute()
            return True
        except Exception as e:
            print(f"Supabase health check failed: {e}")
            return False

    async def close(self):
        """Close connection"""
        self._initialized = False

    async def create_user(self, email: str, password_hash: str, company: str = None) -> Dict:
        """Create user in Supabase"""
        data = {
            "email": email,
            "password_hash": password_hash,
            "company": company
        }
        result = self.client.table("users").insert(data).execute()
        return result.data[0] if result.data else None

    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        result = self.client.table("users").select("*").eq("email", email).execute()
        return result.data[0] if result.data else None

    async def create_api_key(self, user_id: str, name: str = None, expires_days: int = 30) -> Dict:
        """Create API key"""
        api_key = f"aifw_{secrets.token_urlsafe(32)}"
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        data = {
            "user_id": user_id,
            "key": api_key,
            "name": name,
            "expires_at": expires_at.isoformat()
        }
        result = self.client.table("api_keys").insert(data).execute()
        return result.data[0] if result.data else None

    async def verify_api_key(self, api_key: str) -> Optional[Dict]:
        """Verify API key and return user_id"""
        result = self.client.table("api_keys").select("*").eq("key", api_key).execute()
        if not result.data:
            return None
        
        key_data = result.data[0]
        if not key_data['is_active']:
            return None
        
        expires_at = datetime.fromisoformat(key_data['expires_at'].replace('Z', '+00:00'))
        if expires_at < datetime.utcnow():
            return None
        
        return key_data

    async def revoke_key(self, key_id: str, user_id: str):
        """Revoke API key"""
        self.client.table("api_keys").update({
            "is_active": False,
            "revoked_at": datetime.utcnow().isoformat()
        }).eq("id", key_id).eq("user_id", user_id).execute()

    async def log_audit(self, log_data: Dict[str, Any]):
        """Log audit entry"""
        result = self.client.table("audit_logs").insert(log_data).execute()
        return result.data[0] if result.data else None

    async def log_security_event(self, event_data: Dict[str, Any]):
        """Log security event"""
        result = self.client.table("security_events").insert(event_data).execute()
        return result.data[0] if result.data else None

    async def get_user_stats(self, user_id: str) -> Dict:
        """Get user statistics"""
        # Total requests
        total_result = self.client.table("audit_logs")\
            .select("count", count="exact")\
            .eq("user_id", user_id)\
            .execute()
        
        # Blocked requests
        blocked_result = self.client.table("audit_logs")\
            .select("count", count="exact")\
            .eq("user_id", user_id)\
            .eq("action", "BLOCK")\
            .execute()
        
        # Average latency
        latency_result = self.client.table("audit_logs")\
            .select("latency_ms")\
            .eq("user_id", user_id)\
            .execute()
        
        avg_latency = 0
        if latency_result.data:
            latencies = [row['latency_ms'] for row in latency_result.data if row['latency_ms']]
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
        
        # Total cost
        cost_result = self.client.table("audit_logs")\
            .select("cost")\
            .eq("user_id", user_id)\
            .execute()
        
        total_cost = sum([row.get('cost', 0) for row in cost_result.data])
        
        total = total_result.count or 0
        blocked = blocked_result.count or 0
        
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "avg_latency_ms": avg_latency,
            "total_cost": total_cost,
            "threat_rate": (blocked / total * 100) if total > 0 else 0
        }

    async def get_user_requests(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get recent requests for user"""
        result = self.client.table("audit_logs")\
            .select("*")\
            .eq("user_id", user_id)\
            .order("timestamp", desc=True)\
            .limit(limit)\
            .execute()
        return result.data

    async def get_threat_timeline(self, user_id: str, days: int = 7) -> List[Dict]:
        """Get threat timeline for dashboard"""
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        result = self.client.table("security_events")\
            .select("*")\
            .eq("user_id", user_id)\
            .gte("timestamp", start_date)\
            .order("timestamp", desc=True)\
            .execute()
        return result.data

    async def get_logs(self, limit: int = 100, offset: int = 0, user_id: str = None) -> List[Dict]:
        """Retrieve audit logs"""
        query = self.client.table("audit_logs").select("*")
        if user_id:
            query = query.eq("user_id", user_id)
        
        result = query.order("timestamp", desc=True).limit(limit).offset(offset).execute()
        return result.data

    async def save_webhook_config(self, user_id: str, url: str, events: List[str]):
        """Save webhook configuration"""
        data = {
            "user_id": user_id,
            "url": url,
            "events": events,
            "created_at": datetime.utcnow().isoformat()
        }
        result = self.client.table("webhook_configs").upsert(data).execute()
        return result.data[0] if result.data else None
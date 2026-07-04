# app/database.py
import os
import asyncpg
import json
import uuid
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

# DATABASE URL CLEANUP
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


class DatabaseManager:
    pool = None
    _initialized = False

    @classmethod
    async def initialize(cls):
        """Initialize asyncpg connection pool"""
        if cls._initialized and cls.pool:
            return
        
        if not DATABASE_URL:
            print("⚠️ DATABASE_URL not set, using SQLite fallback")
            return
        
        try:
            ssl_mode = 'require' if 'railway' in DATABASE_URL or 'render' in DATABASE_URL else None
            
            cls.pool = await asyncpg.create_pool(
                DATABASE_URL,
                min_size=1,
                max_size=10,
                ssl=ssl_mode,
                command_timeout=30
            )
            await cls.create_tables()
            cls._initialized = True
            print("✅ Database initialized successfully")
        except Exception as e:
            print(f"⚠️ Database initialization failed: {e}")
            print("   Continuing without database...")

    @classmethod
    async def create_tables(cls):
        """Ensures core tables exist"""
        if not cls.pool:
            return
        
        async with cls.pool.acquire() as conn:
            # Users Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(50) PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    company VARCHAR(255),
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # API Keys Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    key VARCHAR(255) UNIQUE NOT NULL,
                    user_id VARCHAR(50) REFERENCES users(id),
                    permissions JSON DEFAULT '["query"]',
                    is_active BOOLEAN DEFAULT TRUE,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Audit Logs Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                    user_id VARCHAR(50),
                    request_id VARCHAR(100) NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    risk_score FLOAT,
                    reason TEXT,
                    tokens_used JSON,
                    latency_ms FLOAT,
                    model VARCHAR(50),
                    cost FLOAT DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key)")
            
            print("✅ Tables created/verified")

    @classmethod
    async def close(cls):
        if cls.pool:
            await cls.pool.close()
            cls.pool = None
            cls._initialized = False

    @classmethod
    async def health_check(cls) -> bool:
        if not cls.pool:
            return False
        try:
            async with cls.pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except:
            return False

    @classmethod
    @asynccontextmanager
    async def get_connection(cls):
        if cls.pool is None:
            await cls.initialize()
        async with cls.pool.acquire() as conn:
            yield conn


class AuditLogger:
    @staticmethod
    async def log_request(log_data: Dict[str, Any]):
        """Safe logging using the connection manager"""
        try:
            if DatabaseManager.pool:
                async with DatabaseManager.get_connection() as conn:
                    await conn.execute("""
                        INSERT INTO audit_logs (
                            id, user_id, request_id, action, risk_score, 
                            reason, tokens_used, latency_ms, model, cost, 
                            timestamp
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    """, 
                        str(uuid.uuid4()), 
                        log_data.get('user_id'), 
                        log_data.get('request_id'), 
                        log_data.get('action'), 
                        log_data.get('risk_score', 0), 
                        log_data.get('reason', ''), 
                        json.dumps(log_data.get('tokens_used', {})), 
                        log_data.get('latency_ms', 0), 
                        log_data.get('model'), 
                        log_data.get('cost', 0), 
                        log_data.get('timestamp', datetime.utcnow())
                    )
                    print(f"✅ Log saved for {log_data.get('request_id')}")
        except Exception as e:
            print(f"⚠️ Failed to save log: {e}")

    @staticmethod
    async def get_logs(limit: int = 100, offset: int = 0, user_id: str = None):
        """Get audit logs"""
        if not DatabaseManager.pool:
            return {"logs": [], "total": 0}
        
        try:
            async with DatabaseManager.get_connection() as conn:
                if user_id:
                    rows = await conn.fetch("""
                        SELECT id, user_id, request_id, action, risk_score,
                               reason, latency_ms, model, cost, timestamp
                        FROM audit_logs
                        WHERE user_id = $1
                        ORDER BY timestamp DESC
                        LIMIT $2 OFFSET $3
                    """, user_id, limit, offset)
                    count_row = await conn.fetchrow("SELECT COUNT(*) FROM audit_logs WHERE user_id = $1", user_id)
                else:
                    rows = await conn.fetch("""
                        SELECT id, user_id, request_id, action, risk_score,
                               reason, latency_ms, model, cost, timestamp
                        FROM audit_logs
                        ORDER BY timestamp DESC
                        LIMIT $1 OFFSET $2
                    """, limit, offset)
                    count_row = await conn.fetchrow("SELECT COUNT(*) FROM audit_logs")

                total = count_row[0] if count_row else 0

                logs = []
                for row in rows:
                    logs.append({
                        "id": str(row["id"]),
                        "user_id": row["user_id"],
                        "request_id": row["request_id"],
                        "action": row["action"],
                        "risk_score": row["risk_score"],
                        "reason": row["reason"],
                        "latency_ms": row["latency_ms"],
                        "model": row["model"],
                        "cost": row["cost"],
                        "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None
                    })

                return {"logs": logs, "total": total}
        except Exception as e:
            print(f"⚠️ Failed to get logs: {e}")
            return {"logs": [], "total": 0}
-- AI Firewall production schema
-- User identity is provided by Supabase Auth (auth.users).
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- API keys are stored as SHA-256 hashes. The plaintext key is returned only at creation time.
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    key_hash TEXT UNIQUE NOT NULL,
    name TEXT,
    permissions JSONB DEFAULT '["query"]'::jsonb,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    action TEXT NOT NULL,
    risk_score FLOAT,
    reason TEXT,
    tokens_used JSONB,
    latency_ms FLOAT,
    model TEXT,
    cost FLOAT DEFAULT 0,
    metadata JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score FLOAT,
    details JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhook_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    events JSONB NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_user ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp DESC);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_configs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can manage own API keys" ON api_keys;
CREATE POLICY "Users can manage own API keys" ON api_keys
    FOR ALL TO authenticated
    USING ((SELECT auth.uid()) = user_id)
    WITH CHECK ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users can view own logs" ON audit_logs;
CREATE POLICY "Users can view own logs" ON audit_logs
    FOR SELECT TO authenticated
    USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users can view own security events" ON security_events;
CREATE POLICY "Users can view own security events" ON security_events
    FOR SELECT TO authenticated
    USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users can manage own webhooks" ON webhook_configs;
CREATE POLICY "Users can manage own webhooks" ON webhook_configs
    FOR ALL TO authenticated
    USING ((SELECT auth.uid()) = user_id)
    WITH CHECK ((SELECT auth.uid()) = user_id);

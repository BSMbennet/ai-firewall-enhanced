"""Delete expired audit/security telemetry using the existing Supabase retention RPC.
Run from backend with SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY configured.
"""
import os
from supabase import create_client


def main():
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise SystemExit("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required")
    client = create_client(url, key)
    result = client.rpc("purge_expired_audit_logs").execute()
    print({"status": "completed", "result": result.data})


if __name__ == "__main__":
    main()

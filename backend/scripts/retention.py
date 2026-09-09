"""Run the database's locked retention RPC for every organization."""
import os
from supabase import create_client


def main():
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise SystemExit("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required")
    client = create_client(url, key)
    organizations = client.table("organizations").select("id").execute().data or []
    completed = 0
    for org in organizations:
        client.rpc("cleanup_expired_audit_logs", {"target_org": org["id"]}).execute()
        completed += 1
    print({"status": "completed", "organizations_processed": completed})


if __name__ == "__main__":
    main()

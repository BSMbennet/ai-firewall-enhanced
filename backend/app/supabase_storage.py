import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from supabase import create_client, Client


class SupabaseStorage:
    """Private Supabase Storage adapter for audit exports and files."""

    BUCKET = "ai-firewall"

    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.client: Optional[Client] = None
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        if not self.url or not self.key:
            raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required")
        self.client = create_client(self.url, self.key)
        try:
            self.client.storage.get_bucket(self.BUCKET)
        except Exception:
            self.client.storage.create_bucket(self.BUCKET, options={"public": False})
        self._initialized = True

    async def health_check(self) -> bool:
        return bool(self.client and self._initialized)

    def _safe_path(self, relative: str) -> str:
        cleaned = relative.replace("\\", "/").lstrip("/")
        if ".." in Path(cleaned).parts or not re.fullmatch(r"[A-Za-z0-9_./-]+", cleaned):
            raise ValueError("Invalid storage path")
        return cleaned

    async def upload_json(self, data: Dict, path: str | None = None) -> str | None:
        if not self.client:
            return None
        relative = path or f"data/{datetime.now(timezone.utc):%Y/%m/%d}/{datetime.now(timezone.utc).timestamp()}.json"
        relative = self._safe_path(relative)
        body = json.dumps(data).encode("utf-8")
        self.client.storage.from_(self.BUCKET).upload(relative, body, {"content-type": "application/json", "upsert": "true"})
        return relative

    async def download_json(self, path: str) -> Optional[Dict]:
        if not self.client:
            return None
        body = self.client.storage.from_(self.BUCKET).download(self._safe_path(path))
        return json.loads(body.decode("utf-8"))

    async def upload_file(self, file_data: bytes, filename: str, content_type: str = "application/octet-stream") -> str:
        if not self.client:
            raise RuntimeError("Storage is not initialized")
        safe_name = Path(filename).name
        relative = self._safe_path(f"files/{datetime.now(timezone.utc):%Y/%m/%d}/{safe_name}")
        self.client.storage.from_(self.BUCKET).upload(relative, file_data, {"content-type": content_type, "upsert": "false"})
        return relative

    async def delete_file(self, path: str) -> bool:
        if not self.client:
            return False
        self.client.storage.from_(self.BUCKET).remove([self._safe_path(path)])
        return True

    async def list_files(self, prefix: str = "", limit: int = 100) -> list:
        if not self.client:
            return []
        result = self.client.storage.from_(self.BUCKET).list(self._safe_path(prefix or "."), {"limit": min(max(limit, 1), 1000)})
        return result or []

    async def archive_audit_logs(self, older_than_days: int = 30):
        return None

import json
import os
import re
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime, timezone


class RenderStorage:
    """Durable file storage backed by a Render persistent disk."""

    def __init__(self):
        self.path = Path(os.getenv("RENDER_STORAGE_PATH", "/var/data/ai-firewall"))
        self._initialized = False

    async def initialize(self):
        production = os.getenv("ENVIRONMENT", "development").lower() == "production"
        if production and not self.path.exists():
            raise RuntimeError("RENDER_STORAGE_PATH is not mounted. Configure a Render persistent disk before production startup.")
        self.path.mkdir(parents=True, exist_ok=True)
        self._initialized = True

    async def health_check(self) -> bool:
        return self._initialized and self.path.exists() and os.access(self.path, os.W_OK)

    def _safe_path(self, relative: str) -> Path:
        cleaned = relative.replace("\\", "/").lstrip("/")
        if ".." in Path(cleaned).parts or not re.fullmatch(r"[A-Za-z0-9_./-]+", cleaned):
            raise ValueError("Invalid storage path")
        target = (self.path / cleaned).resolve()
        if self.path.resolve() not in target.parents and target != self.path.resolve():
            raise ValueError("Invalid storage path")
        return target

    async def upload_json(self, data: Dict, path: str | None = None) -> str | None:
        relative = path or f"data/{datetime.now(timezone.utc):%Y/%m/%d}/{datetime.now(timezone.utc).timestamp()}.json"
        target = self._safe_path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data), encoding="utf-8")
        return relative

    async def download_json(self, path: str) -> Optional[Dict]:
        target = self._safe_path(path)
        if not target.is_file():
            return None
        return json.loads(target.read_text(encoding="utf-8"))

    async def upload_file(self, file_data: bytes, filename: str, content_type: str = "application/octet-stream") -> str:
        safe_name = Path(filename).name
        relative = f"files/{datetime.now(timezone.utc):%Y/%m/%d}/{safe_name}"
        target = self._safe_path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_data)
        return relative

    async def delete_file(self, path: str) -> bool:
        target = self._safe_path(path)
        if not target.is_file():
            return False
        target.unlink()
        return True

    async def list_files(self, prefix: str = "", limit: int = 100) -> list:
        root = self._safe_path(prefix or ".")
        if not root.exists():
            return []
        result = []
        for file in root.rglob("*"):
            if file.is_file() and len(result) < min(max(limit, 1), 1000):
                result.append({"key": str(file.relative_to(self.path)), "size": file.stat().st_size, "last_modified": datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc).isoformat()})
        return result

    async def archive_audit_logs(self, older_than_days: int = 30):
        return None

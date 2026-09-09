import os
from pathlib import Path


class RenderStorage:
    """Local durable storage when a Render persistent disk is mounted.

    Render web services do not provide an S3-compatible object store. This adapter
    intentionally requires a mounted path in production rather than silently
    falling back to ephemeral container storage.
    """

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

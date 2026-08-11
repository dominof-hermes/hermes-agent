"""Uvicorn entrypoint; intentionally separate from the Hermes Gateway process."""

from .app import create_app
from .config import Settings
from .store import AsyncpgStore

settings = Settings.load()
store = AsyncpgStore(settings.database_url, query_timeout_seconds=settings.query_timeout_seconds)
app = create_app(settings=settings, store=store)

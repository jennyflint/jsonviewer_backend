from __future__ import annotations

from advanced_alchemy.repository import SQLAlchemyAsyncRepository

from app.db.models import HistoryEntry


class HistoryRepository(SQLAlchemyAsyncRepository[HistoryEntry]):
    model_type = HistoryEntry

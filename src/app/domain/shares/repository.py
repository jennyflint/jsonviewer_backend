from __future__ import annotations

from advanced_alchemy.repository import SQLAlchemyAsyncRepository

from app.db.models import Share


class ShareRepository(SQLAlchemyAsyncRepository[Share]):
    model_type = Share

from sqlalchemy import Column, DateTime, Integer, JSON, String, func

from backend.models.base import Base


class AnalyticsSnapshot(Base):
    __tablename__ = 'analytics'

    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String(128), nullable=False, index=True)
    metric_value = Column(Integer, nullable=False)
    dimensions = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

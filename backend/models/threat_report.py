from sqlalchemy import Column, DateTime, Integer, JSON, String, Text, func

from backend.models.base import Base


class ThreatReport(Base):
    __tablename__ = 'threat_reports'

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(64), nullable=False)
    target = Column(String(2048), nullable=False, index=True)
    status = Column(String(32), nullable=False)
    payload = Column(JSON, nullable=False)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

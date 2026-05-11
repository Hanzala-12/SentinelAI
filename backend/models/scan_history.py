from sqlalchemy import Boolean, Column, DateTime, Float, Integer, JSON, String, Text, func

from backend.models.base import Base


class ScanHistory(Base):
    __tablename__ = 'scan_history'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    url = Column(String(2048), nullable=True, index=True)
    scan_type = Column(String(32), nullable=False)
    risk_score = Column(Integer, nullable=False)
    classification = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False)
    explanation = Column(Text, nullable=False)
    llm_used = Column(Boolean, default=False, nullable=False)
    detected_issues = Column(JSON, nullable=False)
    source_breakdown = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

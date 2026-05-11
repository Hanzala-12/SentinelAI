from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models.scan_history import ScanHistory


class ScanHistoryRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, **values) -> ScanHistory:
        values.setdefault("llm_used", False)
        record = ScanHistory(**values)
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def list_recent(self, user_id: int, limit: int = 20, offset: int = 0) -> list[ScanHistory]:
        return (
            self.db.query(ScanHistory)
            .filter(ScanHistory.user_id == user_id)
            .order_by(ScanHistory.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def count_for_user(self, user_id: int) -> int:
        return int(
            self.db.query(func.count(ScanHistory.id))
            .filter(ScanHistory.user_id == user_id)
            .scalar()
            or 0
        )

    def stats_for_user(self, user_id: int) -> dict[str, object]:
        rows = (
            self.db.query(
                ScanHistory.classification,
                func.count(ScanHistory.id),
                func.avg(ScanHistory.risk_score),
            )
            .filter(ScanHistory.user_id == user_id)
            .group_by(ScanHistory.classification)
            .all()
        )
        recent = self.list_recent(user_id=user_id, limit=5)
        return {
            "classification_breakdown": [
                {
                    "classification": row[0],
                    "count": int(row[1]),
                    "avg_risk_score": round(float(row[2] or 0), 2),
                }
                for row in rows
            ],
            "recent_scans": [
                {
                    "id": item.id,
                    "url": item.url,
                    "scan_type": item.scan_type,
                    "risk_score": item.risk_score,
                    "classification": item.classification,
                    "confidence": item.confidence,
                    "explanation": item.explanation,
                    "created_at": item.created_at.isoformat() if item.created_at else None,
                }
                for item in recent
            ],
            "total_scans": self.count_for_user(user_id),
        }

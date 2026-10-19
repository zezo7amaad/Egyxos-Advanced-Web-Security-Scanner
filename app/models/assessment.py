from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanMode(str, Enum):
    passive_recon = "passive_recon"
    full_reconnaissance = "full_reconnaissance"
    active_vuln = "active_vuln"


class ApprovalStatus(str, Enum):
    not_required = "NOT_REQUIRED"
    pending = "PENDING_APPROVAL"
    approved = "APPROVED"
    rejected = "REJECTED"


class ScanStatus(str, Enum):
    queued = "QUEUED"
    paused = "PAUSED_AT_APPROVAL_GATE"
    running = "RUNNING"
    completed = "COMPLETED"
    blocked = "BLOCKED"


class AssessmentScope(Base):
    __tablename__ = "assessment_scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    allowed_targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scans: Mapped[list["ScanSession"]] = relationship(back_populates="scope")


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[int] = mapped_column(ForeignKey("assessment_scopes.id"))
    target: Mapped[str] = mapped_column(String(255))
    scan_mode: Mapped[ScanMode] = mapped_column(SqlEnum(ScanMode))
    selected_tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    approval_status: Mapped[ApprovalStatus] = mapped_column(SqlEnum(ApprovalStatus))
    status: Mapped[ScanStatus] = mapped_column(SqlEnum(ScanStatus))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope: Mapped[AssessmentScope] = relationship(back_populates="scans")
    findings: Mapped[list["NormalizedFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class NormalizedFinding(Base):
    __tablename__ = "normalized_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    source_tool: Mapped[str] = mapped_column(String(30))
    asset: Mapped[str] = mapped_column(String(255))
    technology: Mapped[str | None] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    raw_severity: Mapped[str] = mapped_column(String(30), default="Info")
    ai_severity: Mapped[str] = mapped_column(String(30), default="Info")
    ai_classification: Mapped[str] = mapped_column(String(80), default="observation")
    is_likely_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_remediation: Mapped[str] = mapped_column(Text, default="")
    raw_evidence: Mapped[str] = mapped_column(Text, default="")
    scan: Mapped[ScanSession] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(120), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

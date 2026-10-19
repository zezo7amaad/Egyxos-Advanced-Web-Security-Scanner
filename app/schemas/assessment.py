from datetime import datetime

from pydantic import BaseModel, Field

from app.models.assessment import ApprovalStatus, ScanMode, ScanStatus


class ScopeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    allowed_targets: list[str] = Field(min_length=1)


class ScopeResponse(ScopeCreate):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanCreate(BaseModel):
    scope_id: int
    target: str = Field(min_length=1, max_length=255)
    scan_mode: ScanMode = ScanMode.passive_recon
    selected_tools: list[str] = Field(default_factory=lambda: ["subfinder", "httpx"])


class ApprovalDecision(BaseModel):
    approved: bool


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    source_tool: str
    asset: str
    technology: str | None
    title: str
    raw_severity: str
    ai_severity: str
    ai_classification: str
    is_likely_false_positive: bool
    ai_remediation: str
    raw_evidence: str

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: int
    scope_id: int
    target: str
    scan_mode: ScanMode
    selected_tools: list[str]
    approval_status: ApprovalStatus
    status: ScanStatus
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class AIAnalysis(BaseModel):
    ai_classification: str
    ai_severity: str
    is_likely_false_positive: bool
    ai_remediation: str

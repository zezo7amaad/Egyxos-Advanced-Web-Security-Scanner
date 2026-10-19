import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db, init_db
from app.core.governance import is_target_in_scope, requires_approval_gate
from app.models.assessment import (
    ApprovalStatus,
    AssessmentScope,
    AuditLog,
    NormalizedFinding,
    ScanSession,
    ScanStatus,
    utcnow,
)
from app.schemas.assessment import ApprovalDecision, FindingResponse, ScanCreate, ScanResponse, ScopeCreate, ScopeResponse
from app.services.ai_analyzer import analyze_finding
from app.services.orchestrator import execute_pipeline
from app.services.reporter import build_report, render_report, save_report

app = FastAPI(title="Egyxos Advanced Web Security Scanner", version="1.0.0")


@app.on_event("startup")
def startup() -> None:
    init_db()


def audit(db: Session, action: str, target: str = "", details: str = "", actor: str = "operator") -> None:
    db.add(AuditLog(actor=actor, action=action, target=target, details=details))
    db.commit()


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    template = Path(__file__).parent / "dashboard" / "templates" / "index.html"
    return template.read_text(encoding="utf-8")


@app.get("/assets/logo.svg")
def logo() -> FileResponse:
    return FileResponse(Path(__file__).parent.parent / "assets" / "logo.svg", media_type="image/svg+xml")


@app.post("/api/v1/scopes", response_model=ScopeResponse)
def create_scope(payload: ScopeCreate, db: Session = Depends(get_db)) -> AssessmentScope:
    scope = AssessmentScope(name=payload.name, allowed_targets=payload.allowed_targets)
    db.add(scope)
    db.commit()
    db.refresh(scope)
    audit(db, "SCOPE_CREATED", scope.name, json.dumps(scope.allowed_targets))
    return scope


@app.get("/api/v1/scopes", response_model=list[ScopeResponse])
def list_scopes(db: Session = Depends(get_db)) -> list[AssessmentScope]:
    return list(db.scalars(select(AssessmentScope).order_by(AssessmentScope.created_at.desc())))


@app.post("/api/v1/scans", response_model=ScanResponse, status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> ScanSession:
    scope = db.get(AssessmentScope, payload.scope_id)
    if not scope:
        raise HTTPException(404, "Assessment scope not found.")
    if not is_target_in_scope(payload.target, scope.allowed_targets, db):
        raise HTTPException(403, "Target is outside the authorized scope.")
    gated = requires_approval_gate(payload.selected_tools, payload.scan_mode.value)
    scan = ScanSession(
        scope_id=scope.id,
        target=payload.target,
        scan_mode=payload.scan_mode,
        selected_tools=payload.selected_tools,
        approval_status=ApprovalStatus.pending if gated else ApprovalStatus.not_required,
        status=ScanStatus.paused if gated else ScanStatus.queued,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    audit(db, "SCAN_CREATED", payload.target, f"scan_id={scan.id}; approval_required={gated}")
    return scan


@app.get("/api/v1/scans", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)) -> list[ScanSession]:
    return list(db.scalars(select(ScanSession).order_by(ScanSession.created_at.desc())))


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanSession:
    scan = db.get(ScanSession, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


def execute_scan(scan: ScanSession, db: Session) -> None:
    scan.status = ScanStatus.running
    db.commit()
    audit(db, "SCAN_STARTED", scan.target, f"scan_id={scan.id}")
    for finding in execute_pipeline(scan.target, scan.selected_tools):
        finding.update(analyze_finding(finding))
        db.add(NormalizedFinding(scan_id=scan.id, **finding))
    scan.status = ScanStatus.completed
    scan.approval_status = ApprovalStatus.approved if scan.approval_status == ApprovalStatus.pending else scan.approval_status
    scan.completed_at = utcnow()
    db.commit()
    audit(db, "SCAN_COMPLETED", scan.target, f"scan_id={scan.id}")


@app.post("/api/v1/scans/{scan_id}/approval", response_model=ScanResponse)
def decide_scan(scan_id: int, decision: ApprovalDecision, db: Session = Depends(get_db)) -> ScanSession:
    scan = db.get(ScanSession, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    if scan.approval_status != ApprovalStatus.pending:
        raise HTTPException(409, "This scan has no pending approval gate.")
    if not decision.approved:
        scan.approval_status = ApprovalStatus.rejected
        scan.status = ScanStatus.blocked
        db.commit()
        audit(db, "SCAN_REJECTED", scan.target, f"scan_id={scan.id}")
        return scan
    scan.approval_status = ApprovalStatus.approved
    db.commit()
    execute_scan(scan, db)
    return scan


@app.get("/api/v1/findings", response_model=list[FindingResponse])
def list_findings(scan_id: int | None = Query(default=None), db: Session = Depends(get_db)) -> list[NormalizedFinding]:
    statement = select(NormalizedFinding).order_by(NormalizedFinding.id.desc())
    if scan_id is not None:
        statement = statement.where(NormalizedFinding.scan_id == scan_id)
    return list(db.scalars(statement))


@app.get("/api/v1/findings/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> NormalizedFinding:
    finding = db.get(NormalizedFinding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    return finding


@app.get("/api/v1/audit", response_model=list[dict])
def list_audit(db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": event.id, "actor": event.actor, "action": event.action, "target": event.target, "details": event.details, "timestamp": event.timestamp.isoformat()} for event in db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()))]


@app.get("/api/v1/reports/{scan_id}")
def get_report(scan_id: int, format: str = Query(default="json", pattern="^(json|markdown|html)$"), db: Session = Depends(get_db)) -> Response:
    scan = db.get(ScanSession, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    audit_rows = list(db.scalars(select(AuditLog).order_by(AuditLog.timestamp.asc())))
    report = build_report(scan, list(scan.findings), audit_rows)
    content, media_type = render_report(report, format)
    save_report(report, scan_id, format, get_settings().reports_dir)
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.{ "md" if format == "markdown" else format}"'})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "lab" if get_settings().lab_mode else "production"}

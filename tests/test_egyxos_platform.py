import os

os.environ["DATABASE_URL"] = "sqlite:///./test-egyxos.db"
os.environ["DEMO_MODE"] = "true"

from fastapi.testclient import TestClient

from app.core.database import Base, engine
from app.main import app
from app.models.assessment import AuditLog, NormalizedFinding, ScanStatus


client = TestClient(app)


def setup_function() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_scope_blocks_target_and_audits() -> None:
    scope = client.post("/api/v1/scopes", json={"name": "local", "allowed_targets": ["localhost"]}).json()
    response = client.post("/api/v1/scans", json={"scope_id": scope["id"], "target": "example.com", "selected_tools": ["httpx"]})
    assert response.status_code == 403
    from app.core.database import SessionLocal
    with SessionLocal() as db:
        assert db.query(AuditLog).filter_by(action="SCOPE_VIOLATION_BLOCKED").count() == 1


def test_nuclei_pauses_at_approval_gate() -> None:
    scope = client.post("/api/v1/scopes", json={"name": "local", "allowed_targets": ["localhost"]}).json()
    response = client.post("/api/v1/scans", json={"scope_id": scope["id"], "target": "localhost", "selected_tools": ["subfinder", "nuclei"]})
    assert response.status_code == 201
    assert response.json()["status"] == ScanStatus.paused.value
    assert response.json()["approval_status"] == "PENDING_APPROVAL"


def test_approval_executes_demo_pipeline_and_ai_triage() -> None:
    scope = client.post("/api/v1/scopes", json={"name": "local", "allowed_targets": ["localhost"]}).json()
    scan = client.post("/api/v1/scans", json={"scope_id": scope["id"], "target": "localhost", "selected_tools": ["nuclei"]}).json()
    approved = client.post(f"/api/v1/scans/{scan['id']}/approval", json={"approved": True})
    assert approved.status_code == 200
    assert approved.json()["status"] == ScanStatus.completed.value
    findings = client.get("/api/v1/findings", params={"scan_id": scan["id"]})
    assert findings.status_code == 200
    assert findings.json()
    assert "ai_severity" in findings.json()[0]


def test_reports_support_all_formats() -> None:
    scope = client.post("/api/v1/scopes", json={"name": "local", "allowed_targets": ["localhost"]}).json()
    scan = client.post("/api/v1/scans", json={"scope_id": scope["id"], "target": "localhost", "selected_tools": ["httpx"]}).json()
    for output_format, content_type in [("json", "application/json"), ("markdown", "text/markdown"), ("html", "text/html")]:
        response = client.get(f"/api/v1/reports/{scan['id']}", params={"format": output_format})
        assert response.status_code == 200
        assert content_type in response.headers["content-type"]

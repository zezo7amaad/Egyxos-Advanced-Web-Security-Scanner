import json
from html import escape
from pathlib import Path

from app.models.assessment import AuditLog, NormalizedFinding, ScanSession


def build_report(scan: ScanSession, findings: list[NormalizedFinding], audit: list[AuditLog]) -> dict:
    return {
        "scan": {
            "id": scan.id,
            "target": scan.target,
            "mode": scan.scan_mode.value,
            "status": scan.status.value,
            "scope": scan.scope.allowed_targets,
            "selected_tools": scan.selected_tools,
        },
        "executive_summary": f"{len(findings)} normalized observations were collected. AI labels are triage guidance, not proof of exploitability.",
        "findings": [
            {
                "id": item.id,
                "source_tool": item.source_tool,
                "asset": item.asset,
                "technology": item.technology,
                "title": item.title,
                "raw_severity": item.raw_severity,
                "ai_severity": item.ai_severity,
                "ai_classification": item.ai_classification,
                "is_likely_false_positive": item.is_likely_false_positive,
                "remediation": item.ai_remediation,
                "evidence": item.raw_evidence,
            }
            for item in findings
        ],
        "audit_trail": [{"actor": event.actor, "action": event.action, "target": event.target, "timestamp": event.timestamp.isoformat()} for event in audit],
    }


def render_report(report: dict, output_format: str) -> tuple[str, str]:
    if output_format == "json":
        return json.dumps(report, indent=2), "application/json"
    if output_format == "html":
        rows = "".join(
            "<tr>"
            f"<td>{escape(str(item['title']))}</td>"
            f"<td>{escape(str(item['asset']))}</td>"
            f"<td>{escape(str(item['ai_severity']))}</td>"
            f"<td>{escape(str(item['ai_classification']))}</td>"
            "</tr>"
            for item in report["findings"]
        )
        summary = escape(str(report["executive_summary"]))
        return f"<html><body><h1>Egyxos assessment report</h1><p>{summary}</p><table><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>Classification</th></tr>{rows}</table></body></html>", "text/html"
    lines = [f"# Egyxos assessment {report['scan']['id']}", "", report["executive_summary"], "", "## Findings"]
    for item in report["findings"]:
        lines.extend([f"### {item['title']}", f"- Asset: {item['asset']}", f"- AI severity: {item['ai_severity']}", f"- Classification: {item['ai_classification']}", f"- Remediation: {item['remediation']}", f"- Evidence: {item['evidence']}", ""])
    return "\n".join(lines), "text/markdown"


def save_report(report: dict, scan_id: int, output_format: str, directory: str) -> Path:
    content, _ = render_report(report, output_format)
    suffix = "md" if output_format == "markdown" else output_format
    path = Path(directory) / f"scan-{scan_id}.{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path

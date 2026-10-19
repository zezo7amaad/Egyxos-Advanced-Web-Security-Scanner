from fnmatch import fnmatch
from ipaddress import ip_address
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.assessment import AuditLog


def _host(target: str) -> str | None:
    candidate = target if "://" in target else f"https://{target}"
    parsed = urlparse(candidate)
    host = parsed.hostname
    if not host:
        return None
    try:
        return str(ip_address(host))
    except ValueError:
        return host.rstrip(".").lower()


def is_target_in_scope(target: str, allowed_patterns: list[str], db: Session | None = None, actor: str = "system") -> bool:
    host = _host(target)
    allowed = False
    if host:
        for pattern in allowed_patterns:
            normalized = pattern.strip().lower().rstrip(".")
            if host == normalized or fnmatch(host, normalized):
                allowed = True
                break
    if not allowed and db is not None:
        db.add(AuditLog(actor=actor, action="SCOPE_VIOLATION_BLOCKED", target=target, details=f"Allowed patterns: {allowed_patterns}"))
        db.commit()
    return allowed


def requires_approval_gate(selected_tools: list[str], scan_mode: str) -> bool:
    return "nuclei" in selected_tools or scan_mode == "active_vuln"

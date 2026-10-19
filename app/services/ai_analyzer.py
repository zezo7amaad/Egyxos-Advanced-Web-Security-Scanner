import json
from urllib.request import Request, urlopen

from app.core.config import get_settings


def _fallback(finding: dict[str, str]) -> dict[str, object]:
    title = finding.get("title", "").lower()
    raw = finding.get("raw_evidence", "")
    false_positive = not raw.strip() or "informational" in title or "banner" in title
    severity = "Low"
    if any(term in title for term in ("rce", "remote code", "sql injection")):
        severity = "Critical"
    elif any(term in title for term in ("auth", "authorization", "xss", "exposure")):
        severity = "High"
    elif "header" in title or "tls" in title:
        severity = "Medium"
    return {
        "ai_classification": "likely_false_positive" if false_positive else "validated_observation",
        "ai_severity": severity,
        "is_likely_false_positive": false_positive,
        "ai_remediation": "Validate with authorized test accounts and retain redacted evidence before treating this observation as confirmed.",
    }


def analyze_finding(finding: dict[str, str]) -> dict[str, object]:
    settings = get_settings()
    if not settings.gemini_api_key and not settings.ollama_url:
        return _fallback(finding)
    prompt = (
        "Return JSON only with keys ai_classification, ai_severity, "
        "is_likely_false_positive, ai_remediation. Do not claim exploitation. "
        f"Finding: {json.dumps(finding)}"
    )
    try:
        if settings.ollama_url:
            request = Request(
                f"{settings.ollama_url.rstrip('/')}/api/generate",
                data=json.dumps({"model": settings.ollama_model, "prompt": prompt, "stream": False}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode())
                return {**_fallback(finding), **json.loads(payload["response"])}
        request = Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent?key={settings.gemini_api_key}",
            data=json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode())
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
            return {**_fallback(finding), **json.loads(text)}
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _fallback(finding)

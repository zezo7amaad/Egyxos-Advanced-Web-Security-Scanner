import json
import shutil
import subprocess
from collections.abc import Iterable

from app.core.config import get_settings


def _run(binary: str, args: list[str]) -> str:
    if not shutil.which(binary):
        return ""
    try:
        result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout[:1_000_000] if result.returncode == 0 else ""


def run_tool(tool: str, target: str) -> list[dict[str, str]]:
    settings = get_settings()
    if tool == "subfinder":
        output = _run("subfinder", ["-d", target, "-silent"])
        if not output and settings.demo_mode and target in {"localhost", "127.0.0.1", "juice-shop", "dvwa"}:
            output = f"{target}\n"
        return [{"source_tool": "subfinder", "asset": line.strip(), "technology": "", "title": "Discovered subdomain", "raw_severity": "Info", "raw_evidence": line.strip()} for line in output.splitlines() if line.strip()]
    if tool == "httpx":
        output = _run("httpx", ["-u", target, "-silent", "-title"])
        if not output and settings.demo_mode:
            output = target
        return [{"source_tool": "httpx", "asset": line.strip(), "technology": "HTTP service", "title": "Live HTTP host", "raw_severity": "Info", "raw_evidence": line.strip()} for line in output.splitlines() if line.strip()]
    if tool == "nuclei":
        output = _run("nuclei", ["-u", target, "-jsonl"])
        rows: list[dict[str, str]] = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            rows.append({
                "source_tool": "nuclei",
                "asset": str(item.get("matched-at") or target),
                "technology": str(info.get("name") or ""),
                "title": str(info.get("name") or "Nuclei observation"),
                "raw_severity": str(info.get("severity") or "Info").title(),
                "raw_evidence": line,
            })
        if not rows and settings.demo_mode:
            rows.append({"source_tool": "nuclei", "asset": target, "technology": "Demo mode", "title": "No verified vulnerability output", "raw_severity": "Info", "raw_evidence": "No Nuclei binary or findings were available; this is not a vulnerability claim."})
        return rows
    return []


def execute_pipeline(target: str, selected_tools: Iterable[str]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for tool in selected_tools:
        normalized.extend(run_tool(tool, target))
    return normalized

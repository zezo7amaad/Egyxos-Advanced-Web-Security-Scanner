import type { Finding } from "./types.js";

export function renderMarkdownReport(findings: Finding[]): string {
  const lines: string[] = [
    "# Egyxos Advanced Web Security Scanner Report",
    "",
    "## Executive Summary",
    "",
    `Total findings: ${findings.length}`,
    "",
    "## Findings",
    "",
  ];

  if (!findings.length) {
    lines.push("No findings recorded.");
    return lines.join("\n");
  }

  for (const finding of findings) {
    lines.push(`### ${finding.title}`);
    lines.push("");
    lines.push(`- ID: ${finding.id}`);
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- Confidence: ${finding.confidence}`);
    lines.push(`- Target: ${finding.target}`);
    lines.push(`- Endpoint: ${finding.endpoint}`);
    lines.push(`- Status: ${finding.status}`);
    lines.push("");
    lines.push(finding.description);
    lines.push("");
    lines.push("**Impact**");
    lines.push(finding.impact);
    lines.push("");
    lines.push("**Remediation**");
    lines.push(finding.remediation);
    lines.push("");
  }

  return lines.join("\n");
}

export function renderJsonReport(findings: Finding[]): string {
  return JSON.stringify({ report: "Egyxos Advanced Web Security Scanner", findings }, null, 2);
}

export function renderHtmlReport(findings: Finding[]): string {
  const items = findings
    .map(
      (finding) => `
        <article>
          <h2>${finding.title}</h2>
          <ul>
            <li><strong>ID:</strong> ${finding.id}</li>
            <li><strong>Severity:</strong> ${finding.severity}</li>
            <li><strong>Confidence:</strong> ${finding.confidence}</li>
            <li><strong>Target:</strong> ${finding.target}</li>
          </ul>
          <p>${finding.description}</p>
        </article>
      `,
    )
    .join("\n");

  return `<!doctype html><html><head><meta charset="UTF-8"><title>Egyxos Advanced Web Security Scanner Report</title></head><body><h1>Egyxos Advanced Web Security Scanner</h1>${items}</body></html>`;
}

export function generateReport(findings: Finding[], format: "markdown" | "html" | "json" = "markdown"): string {
  switch (format) {
    case "json":
      return renderJsonReport(findings);
    case "html":
      return renderHtmlReport(findings);
    default:
      return renderMarkdownReport(findings);
  }
}

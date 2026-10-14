#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { stdin, stdout } from "node:process";
import { createProject, listProjects, openProject, showScope, addScope } from "./project.js";
import { startSession, listSessions, resumeSession } from "./session.js";
import { getToolRegistry, previewAction } from "./tooling.js";
import { FindingStore } from "./findings.js";
import { generateReport } from "./reporting.js";
import { runDoctor } from "./doctor.js";
import { validateTarget } from "./scope.js";
import { loadConfig, resolveStoragePath } from "./config.js";
import { askGemini } from "./ai.js";
import { buildSkillPrompt, getSecuritySkills } from "./skills.js";
import { renderSecurityCurriculum } from "./training.js";
import { runAuthorizedScan } from "./scanner.js";
import { GeminiProvider } from "./ai.js";

function printHeader(): void {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║   Egyxos Advanced Web Security Scanner     ║");
  console.log("║       AI Security Assessment Platform      ║");
  console.log("╚══════════════════════════════════════════════╝");
}

function printHelp(): void {
  console.log("Usage: egyxos-redteam <command> [options]");
  console.log("");
  console.log("Commands:");
  console.log("  project create <name>");
  console.log("  project list");
  console.log("  project open <name>");
  console.log("  config show");
  console.log("  scope add <domain>");
  console.log("  scope show");
  console.log("  session start [objective]");
  console.log("  session list");
  console.log("  session resume <id>");
  console.log("  recon start");
  console.log("  findings list");
  console.log("  report generate [markdown|html|json]");
  console.log("  tools list");
  console.log("  skills list");
  console.log("  skills curriculum");
  console.log("  ai ask <skill> <request>");
  console.log("  ai scan <skill> <target> --approve");
  console.log("  doctor");
  console.log("  --help");
  console.log("  --dry-run");
}

function handleProject(args: string[]): void {
  const [action, name] = args;
  if (action === "create") {
    const project = createProject(name ?? "demo");
    console.log(`Project created: ${project.name}`);
    return;
  }

  if (action === "list") {
    const projects = listProjects();
    console.log(projects.length ? projects.map((project) => project.name).join("\n") : "No projects found.");
    return;
  }

  if (action === "open") {
    const project = openProject(name ?? "default");
    console.log(`Project opened: ${project.name}`);
    return;
  }

  printHelp();
}

function handleConfig(args: string[]): void {
  const [action] = args;
  if (action === "show") {
    const config = loadConfig();
    console.log(JSON.stringify({ ...config, storagePath: resolveStoragePath() }, null, 2));
    return;
  }

  printHelp();
}

function handleScope(args: string[]): void {
  const [action, value] = args;
  if (action === "add") {
    const scope = addScope(value ?? "example.com");
    console.log(`Scope updated: ${scope.join(", ")}`);
    return;
  }

  if (action === "show") {
    const scope = showScope();
    console.log(scope.length ? scope.join("\n") : "No scope configured.");
    return;
  }

  printHelp();
}

function handleSession(args: string[]): void {
  const [action, objective, target] = args;
  if (action === "start") {
    const session = startSession(undefined, objective ?? "Initial assessment", target ?? "https://example.com");
    console.log(`Session started: ${session.id}`);
    return;
  }

  if (action === "list") {
    const sessions = listSessions();
    console.log(sessions.length ? sessions.map((entry) => `${entry.id} :: ${entry.objective}`).join("\n") : "No sessions found.");
    return;
  }

  if (action === "resume") {
    const session = resumeSession(objective ?? "default");
    console.log(`Session resumed: ${session.id}`);
    return;
  }

  printHelp();
}

function handleRecon(): void {
  const config = loadConfig();
  const project = showScope();
  const target = "https://example.com";
  const validation = validateTarget(target, project);

  if (!validation.ok) {
    console.log(`Scope validation failed: ${validation.reason}`);
    return;
  }

  const action = previewAction("httpx", target, project, true);
  console.log("Planned Action");
  console.log(`Tool: ${action.tool}`);
  console.log(`Target: ${target}`);
  console.log(`Scope: ${project.join(", ") || "default"}`);
  console.log(`Command Preview: ${action.preview}`);

  if (config.requireApproval) {
    console.log("Approval required before execution.");
  }
}

function handleFindings(): void {
  const store = new FindingStore();
  const findings = store.listFindings();
  console.log(findings.length ? findings.map((entry) => `${entry.id} :: ${entry.title} [${entry.severity}]`).join("\n") : "No findings recorded.");
}

function handleReport(args: string[]): void {
  const format = (args[1] ?? "markdown").toLowerCase() as "markdown" | "html" | "json";
  const store = new FindingStore();
  const report = generateReport(store.listFindings(), format);
  const reportPath = path.join(resolveStoragePath(), "reports", `egyxos-report.${format === "html" ? "html" : format === "json" ? "json" : "md"}`);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, report);
  console.log(`Report written to ${reportPath}`);
}

function handleTools(): void {
  for (const tool of getToolRegistry()) {
    console.log(`${tool.name} :: ${tool.description} :: ${tool.requiresApproval ? "approval required" : "safe"}`);
  }
}

function handleSkills(args: string[] = []): void {
  if (args[0] === "curriculum") {
    console.log(renderSecurityCurriculum());
    return;
  }

  for (const skill of getSecuritySkills()) {
    console.log(`${skill.name} :: ${skill.description} :: ${skill.permissions.join(", ")}`);
  }
}

async function handleAI(args: string[]): Promise<void> {
  const [action, skill, ...requestParts] = args;
  if (action === "scan") {
    await handleAIScan(skill, requestParts);
    return;
  }

  if (action !== "ask" || !skill || requestParts.length === 0) {
    printHelp();
    return;
  }

  try {
    const response = await askGemini(skill, requestParts.join(" "));
    console.log(response.text);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "AI request failed.");
    process.exitCode = 1;
  }
}

async function handleAIScan(skill: string | undefined, args: string[]): Promise<void> {
  const target = args.find((arg) => !arg.startsWith("--"));
  const approved = args.includes("--approve");
  if (!skill || !target) {
    printHelp();
    return;
  }

  try {
    console.log("Running authorized scan. Passive discovery and approved Nuclei checks only.");
    const output = runAuthorizedScan(target, { approveActive: approved });
    const prompt = buildSkillPrompt(
      skill,
      [
        `Target: ${output.target}`,
        "Authorization attestation: the operator has written authorization for this target, and the local scope validator allowed the scan.",
        "You are not being asked to access, probe, exploit, or provide instructions for this target. The tool execution is complete.",
        "Analyze only the supplied, already-collected tool output as a defensive triage and report-writing task.",
        "Do not refuse solely because the target is a public or real-world domain. Instead, state when the supplied evidence is insufficient.",
        "Identify only evidence-backed vulnerabilities and label unconfirmed observations as potential.",
        "Do not invent endpoints, requests, responses, impact, or successful exploitation.",
        `Subfinder output:\n${output.subdomains.slice(0, 20_000)}`,
        `HTTPX output:\n${output.httpx.slice(0, 20_000)}`,
        `Nuclei JSONL output:\n${output.nuclei.slice(0, 50_000)}`,
        "Produce a concise report with summary, findings, confidence, evidence, impact, remediation, and an explicit no-findings statement when appropriate.",
      ].join("\n\n"),
    );
    const response = await new GeminiProvider().generate({ prompt });
    const reportDir = path.join(resolveStoragePath(), "reports");
    fs.mkdirSync(reportDir, { recursive: true });
    const reportPath = path.join(reportDir, `ai-scan-${Date.now()}.md`);
    fs.writeFileSync(reportPath, `# Egyxos Advanced Web Security Scanner AI Security Assessment\n\nTarget: ${output.target}\n\n${response.text}\n`);
    console.log(`AI assessment written to ${reportPath}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Authorized scan failed.");
    process.exitCode = 1;
  }
}

function handleDoctor(): void {
  const result = runDoctor();
  console.log("Egyxos Advanced Web Security Scanner Doctor");
  for (const check of result.checks) {
    console.log(`${check.ok ? "✓" : "!"} ${check.name}: ${check.details}`);
  }
  console.log(`Status: ${result.status}`);
}

async function interactiveShell(): Promise<void> {
  printHeader();
  console.log("Project: default");
  console.log("Target: https://example.com");
  console.log("Status: Ready");
  console.log("");

  const rl = readline.createInterface({ input: stdin, output: stdout });
  rl.setPrompt("egyxos > ");
  rl.prompt();

  rl.on("line", (line) => {
    const raw = line.trim();
    if (!raw || raw === "exit") {
      rl.close();
      return;
    }

    if (raw.toLowerCase() === "initialize assessment") {
      console.log("Egyxos Advanced Web Security Scanner: Target identified.");
      console.log("Scope: example.com");
      console.log("Proposed plan:");
      console.log("[1] Passive reconnaissance");
      console.log("[2] HTTP service discovery");
      console.log("[3] Technology fingerprinting");
      console.log("[4] Endpoint discovery");
      console.log("Execute plan? [y/N]");
      rl.prompt();
      return;
    }

    console.log("Command queued: ", raw);
    rl.prompt();
  });

  rl.on("close", () => {
    process.exit(0);
  });
}

function main(): void {
  const args = process.argv.slice(2).filter((arg) => arg !== "--dry-run");
  if (args.length === 0 || args[0] === "--help" || args[0] === "help") {
    printHeader();
    printHelp();
    return;
  }

  const [command, ...rest] = args;

  switch (command) {
    case "project":
      handleProject(rest);
      break;
    case "config":
      handleConfig(rest);
      break;
    case "scope":
      handleScope(rest);
      break;
    case "session":
      handleSession(rest);
      break;
    case "recon":
      handleRecon();
      break;
    case "findings":
      handleFindings();
      break;
    case "report":
      handleReport(rest);
      break;
    case "tools":
      handleTools();
      break;
    case "skills":
      handleSkills(rest);
      break;
    case "ai":
      void handleAI(rest);
      break;
    case "doctor":
      handleDoctor();
      break;
    default:
      if (command === "interactive") {
        void interactiveShell();
        return;
      }
      printHeader();
      printHelp();
  }
}

main();

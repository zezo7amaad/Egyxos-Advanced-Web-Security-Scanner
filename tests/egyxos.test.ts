import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeEach } from "vitest";
import { AgentController } from "../src/agent.js";
import { addScope, createProject, listProjects, openProject } from "../src/project.js";
import { renderJsonReport } from "../src/reporting.js";
import { validateTarget } from "../src/scope.js";
import { runDoctor } from "../src/doctor.js";
import { buildToolCommand, getToolRegistry } from "../src/tooling.js";
import { buildSkillPrompt, getSecuritySkills } from "../src/skills.js";
import { renderSecurityCurriculum } from "../src/training.js";
import { runAuthorizedScan } from "../src/scanner.js";
import { startSession, listSessions, resumeSession, getSessionCount } from "../src/session.js";

const originalStorage = process.env.EGYXOS_STORAGE;

beforeEach(() => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "egyxos-test-"));
  process.env.EGYXOS_STORAGE = temp;
});

describe("Egyxos Advanced Web Security Scanner core behaviors", () => {
  it("creates a project and enforces scope", () => {
    const project = createProject("demo");
    addScope("example.com", "demo");
    const allowed = validateTarget("https://api.example.com", ["example.com"]);
    const blocked = validateTarget("https://evil.example.net", ["example.com"]);

    expect(project.name).toBe("demo");
    expect(listProjects().some((entry) => entry.name === "demo")).toBe(true);
    expect(allowed.ok).toBe(true);
    expect(blocked.ok).toBe(false);
  });

  it("requires approval for dangerous actions", () => {
    const controller = new AgentController("Map API attack surface", "https://example.com");
    const approval = controller.requestApproval("ffuf", "https://example.com", ["example.com"], "Fuzz API endpoints");

    expect(approval.status).toBe("pending");
    expect(controller.approveRequest(true)).toBe(true);
    expect(controller.phase).toBe("execute");
  });

  it("lists available tools and renders JSON reports", () => {
    const tools = getToolRegistry();
    const report = renderJsonReport([
      {
        id: "EGYXOS-001",
        title: "Example Finding",
        severity: "high",
        confidence: "confirmed",
        target: "https://example.com",
        endpoint: "/api/example",
        description: "Sample finding for validation.",
        impact: "Unauthorized access could be possible.",
        evidence: ["HTTP response 200"],
        reproduction: ["Issue reproduced against the endpoint"],
        remediation: "Fix request validation.",
        references: ["https://example.com/docs"],
        status: "confirmed",
      },
    ]);

    expect(tools.some((tool) => tool.name === "httpx")).toBe(true);
    expect(tools.some((tool) => tool.name === "nuclei")).toBe(true);
    expect(tools.some((tool) => tool.name === "subfinder")).toBe(true);
    expect(buildToolCommand("subfinder", "example.com")).toContain("subfinder -d");
    expect(buildToolCommand("nuclei", "https://example.com")).toContain("nuclei -u");
    expect(buildToolCommand("nuclei", "https://example.com")).toContain(" -v ");
    expect(buildToolCommand("katana", "https://example.com")).toContain("katana -u");
    expect(buildToolCommand("ffuf", "https://example.com")).toContain("ffuf -u");
    expect(buildToolCommand("curl", "https://example.com")).toContain("curl -sSIL");
    expect(report).toContain("EGYXOS-001");
  });

  it("runs a doctor check suite", () => {
    const result = runDoctor();
    expect(result.checks.length).toBeGreaterThan(0);
    expect(result.status).toBeDefined();
  });

  it("provides safe bug bounty skills and scoped prompts", () => {
    const skills = getSecuritySkills();
    const prompt = buildSkillPrompt("bug-bounty-triage", "Review these authorized observations.");
    expect(skills.some((skill) => skill.name === "bug-bounty-triage")).toBe(true);
    expect(skills.some((skill) => skill.name === "xss-review")).toBe(true);
    expect(skills.some((skill) => skill.name === "sqli-review")).toBe(true);
    expect(skills.some((skill) => skill.name === "subdomain-takeover-review")).toBe(true);
    expect(prompt).toContain("configured scope");
    expect(prompt).toContain("Do not perform or recommend destructive actions");
    expect(prompt).toContain("authorization-and-scope");
    expect(renderSecurityCurriculum()).toContain("validation-and-evidence");
  });

  it("rejects an out-of-scope scan before launching tools", () => {
    expect(() => runAuthorizedScan("outside.example.net", { approveActive: true })).toThrow(/outside the (active|configured) scope/i);
  });

  it("rejects path traversal in project names", () => {
    expect(() => createProject("../outside")).toThrow(/invalid path characters/i);
    expect(() => createProject("nested/project")).toThrow(/invalid path characters/i);
  });
});

describe("Session security - file inclusion vulnerability mitigation", () => {
  it("prevents path traversal in resumeSession with relative paths", () => {
    createProject("secure-project");
    const session = startSession("secure-project", "Test Objective", "https://example.com");
    
    // Attempt path traversal using ../ in session ID
    expect(() => resumeSession("../../../etc/passwd", "secure-project")).toThrow("Invalid file path");
    expect(() => resumeSession("../../config", "secure-project")).toThrow("Invalid file path");
  });

  it("prevents path traversal in resumeSession with absolute paths", () => {
    createProject("secure-project2");
    const session = startSession("secure-project2", "Test Objective", "https://example.com");
    
    // Attempt path traversal using absolute paths
    expect(() => resumeSession("/etc/passwd", "secure-project2")).toThrow("Invalid file path");
    expect(() => resumeSession("/tmp/malicious", "secure-project2")).toThrow("Invalid file path");
  });

  it("allows legitimate session resumption", () => {
    createProject("legit-project");
    const session = startSession("legit-project", "Legitimate Test", "https://example.com");
    
    // Should work with valid session ID
    const resumed = resumeSession(session.id, "legit-project");
    expect(resumed.id).toBe(session.id);
    expect(resumed.status).toBe("active");
  });

  it("validates project paths in session operations", () => {
    // Create a legitimate project
    createProject("valid-project");
    
    // These should work normally
    const session = startSession("valid-project");
    expect(session.id).toBeDefined();
    
    const sessions = listSessions("valid-project");
    expect(sessions.length).toBeGreaterThan(0);
    
    const count = getSessionCount();
    expect(count).toBeGreaterThan(0);
  });
});

describe("Project security - file inclusion vulnerability mitigation", () => {
  it("prevents path traversal in createProject with relative paths", () => {
    // Attempt to create project outside the projects directory using ../
    expect(() => createProject("../../../etc/passwd")).toThrow("Invalid file path");
    expect(() => createProject("../../config")).toThrow("Invalid file path");
    expect(() => createProject("../malicious")).toThrow("Invalid file path");
  });

  it("prevents path traversal in createProject with absolute paths", () => {
    // Attempt to create project using absolute paths
    expect(() => createProject("/etc/passwd")).toThrow("Invalid file path");
    expect(() => createProject("/tmp/malicious")).toThrow("Invalid file path");
  });

  it("prevents path traversal in openProject with relative paths", () => {
    // First create a legitimate project
    createProject("test-open-project");
    
    // Attempt to open project outside the projects directory
    expect(() => openProject("../../../etc/passwd")).toThrow("Invalid file path");
    expect(() => openProject("../../config")).toThrow("Invalid file path");
  });

  it("prevents path traversal in openProject with absolute paths", () => {
    // Attempt to open project using absolute paths
    expect(() => openProject("/etc/passwd")).toThrow("Invalid file path");
    expect(() => openProject("/tmp/malicious")).toThrow("Invalid file path");
  });

  it("allows legitimate project creation and opening", () => {
    // Should work with valid project names
    const project = createProject("legitimate-project");
    expect(project.name).toBe("legitimate-project");
    expect(project.path).toContain("projects");
    expect(project.path).toContain("legitimate-project");
    
    // Should be able to open the legitimate project
    const opened = openProject("legitimate-project");
    expect(opened.name).toBe("legitimate-project");
  });
});

process.env.EGYXOS_STORAGE = originalStorage ?? "";

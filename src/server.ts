import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { URL } from "node:url";
import { ensureProject, listProjects, openProject, showScope } from "./project.js";
import { FindingStore } from "./findings.js";
import { listSessions, startSession } from "./session.js";
import { validateTarget } from "./scope.js";
import { assertSafeName, safeChildPath } from "./config.js";
import { getToolRegistry } from "./tooling.js";
import { DatabaseService } from "./database.js";
import { can, createSession, deleteSession, findUser, getSession, getUser } from "./auth.js";
import type { DashboardUser } from "./auth.js";
import type { ApprovalRequest, Finding, ProjectRecord, SessionRecord } from "./types.js";

const port = Number(process.env.PORT || 4173);
const dashboardRoot = path.resolve(process.cwd(), "dashboard");
const assetRoot = path.resolve(process.cwd(), "assets");
const cookieName = "egyxos_dashboard";
const csrfCookieName = "egyxos_csrf";

interface RequestContext {
  session: ReturnType<typeof getSession>;
  user?: DashboardUser;
}

function json(response: http.ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}): void {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  response.end(JSON.stringify(body));
}

function error(response: http.ServerResponse, status: number, message: string, code: string): void {
  json(response, status, { error: { code, message } });
}

function parseCookies(request: http.IncomingMessage): Record<string, string> {
  return Object.fromEntries((request.headers.cookie ?? "").split(";").map((part) => {
    const index = part.indexOf("=");
    return index === -1 ? ["", ""] : [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

function requestContext(request: http.IncomingMessage): RequestContext {
  const session = getSession(parseCookies(request)[cookieName]);
  return { session, user: session ? getUser(session.userId) : undefined };
}

function requireAuth(request: http.IncomingMessage, response: http.ServerResponse): RequestContext | undefined {
  const context = requestContext(request);
  if (!context.session || !context.user) {
    error(response, 401, "Sign in is required.", "AUTHENTICATION_REQUIRED");
    return undefined;
  }
  return context;
}

function requireRole(request: http.IncomingMessage, response: http.ServerResponse, action: "view" | "manage_findings" | "approve"): RequestContext | undefined {
  const context = requireAuth(request, response);
  if (!context || !can(context.user!.role, action)) {
    if (context) error(response, 403, "Your role cannot perform this action.", "PERMISSION_REQUIRED");
    return undefined;
  }
  return context;
}

function requireCsrf(request: http.IncomingMessage, response: http.ServerResponse, context: RequestContext): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method ?? "GET")) return true;
  if (request.headers["x-csrf-token"] !== context.session?.csrfToken) {
    error(response, 403, "A valid CSRF token is required.", "CSRF_REQUIRED");
    return false;
  }
  return true;
}

async function readBody(request: http.IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  if (!Buffer.concat(chunks).length) return {};
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Request body must be a JSON object.");
  return parsed as Record<string, unknown>;
}

function safePublicProject(project: ProjectRecord): Omit<ProjectRecord, "path"> {
  const { path: _path, ...publicProject } = project;
  return publicProject;
}

function safeFinding(finding: Finding): Finding {
  return { ...finding, references: finding.references ?? [] };
}

function reportRecords(projectName?: string): Array<{ id: string; project: string; format: string; path: string; updatedAt: string }> {
  const projects = projectName ? [openProject(projectName)] : listProjects();
  return projects.flatMap((project) => {
    const reportsDir = path.join(project.path, "reports");
    if (!fs.existsSync(reportsDir)) return [];
    return fs.readdirSync(reportsDir).filter((file) => /\.(md|html|json)$/i.test(file)).map((file) => ({
      id: `${project.name}:${file}`,
      project: project.name,
      format: path.extname(file).slice(1).toLowerCase(),
      path: file,
      updatedAt: fs.statSync(path.join(reportsDir, file)).mtime.toISOString(),
    }));
  });
}

async function api(request: http.IncomingMessage, response: http.ServerResponse, url: URL): Promise<void> {
  const context = requestContext(request);
  const route = url.pathname;

  if (route === "/api/auth/login" && request.method === "POST") {
    try {
      const body = await readBody(request);
      if (typeof body.username !== "string" || typeof body.password !== "string" || !body.username || !body.password) {
        error(response, 400, "Username and password are required.", "VALIDATION_ERROR");
        return;
      }
      const user = findUser(body.username, body.password);
      if (!user) {
        error(response, 401, "Invalid credentials.", "INVALID_CREDENTIALS");
        return;
      }
      const session = createSession(user.id);
      const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
      json(response, 200, { user: { id: user.id, username: user.username, role: user.role, displayName: user.displayName }, csrfToken: session.csrfToken }, {
        "Set-Cookie": [
          `${cookieName}=${session.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`,
          `${csrfCookieName}=${session.csrfToken}; SameSite=Strict; Path=/; Max-Age=28800${secure}`,
        ],
      });
    } catch (caught) {
      error(response, 503, caught instanceof Error ? caught.message : "Dashboard authentication is not configured.", "AUTHENTICATION_UNAVAILABLE");
    }
    return;
  }

  if (route === "/api/auth/logout" && request.method === "POST") {
    if (context.session && requireCsrf(request, response, context)) deleteSession(context.session.id);
    response.writeHead(204, { "Set-Cookie": [
      `${cookieName}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
      `${csrfCookieName}=; SameSite=Strict; Path=/; Max-Age=0`,
    ] });
    response.end();
    return;
  }

  if (route === "/api/auth/me" && request.method === "GET") {
    const authenticated = requireAuth(request, response);
    if (authenticated) json(response, 200, { user: authenticated.user, csrfToken: authenticated.session!.csrfToken });
    return;
  }

  const authenticated = requireRole(request, response, "view");
  if (!authenticated) return;
  if (!requireCsrf(request, response, authenticated)) return;

  if (route === "/api/projects" && request.method === "GET") {
    json(response, 200, { data: listProjects().map(safePublicProject) });
    return;
  }

  const projectMatch = route.match(/^\/api\/projects\/([^/]+)(?:\/(scope|sessions|findings|reports))?$/);
  if (projectMatch && request.method === "GET") {
    const projectName = decodeURIComponent(projectMatch[1]);
    const project = openProject(projectName);
    const resource = projectMatch[2];
    if (resource === "scope") json(response, 200, { data: showScope(projectName) });
    else if (resource === "sessions") json(response, 200, { data: listSessions(projectName) });
    else if (resource === "findings") json(response, 200, { data: new FindingStore(projectName).listFindings().map(safeFinding) });
    else if (resource === "reports") json(response, 200, { data: reportRecords(projectName) });
    else json(response, 200, { data: safePublicProject(project) });
    return;
  }

  if (route === "/api/scans" && request.method === "GET") {
    const scans = listProjects().flatMap((project) => listSessions(project.name).map((scan) => ({ ...scan, project: project.name })));
    json(response, 200, { data: scans });
    return;
  }

  if (route === "/api/scans" && request.method === "POST") {
    const body = await readBody(request);
    if (typeof body.project !== "string" || typeof body.target !== "string") {
      error(response, 400, "project and target are required.", "VALIDATION_ERROR");
      return;
    }

    if (route === "/api/approvals" && request.method === "GET") {
      const approvals = listProjects().flatMap((project) => listSessions(project.name).flatMap((session) =>
        session.approvals.map((approval) => ({ ...approval, project: project.name, sessionId: session.id })),
      ));
      json(response, 200, { data: approvals });
      return;
    }

    if (route === "/api/approvals" && request.method === "POST") {
      const approver = requireRole(request, response, "approve");
      if (!approver) return;
      const body = await readBody(request);
      if (typeof body.project !== "string" || typeof body.sessionId !== "string"
        || typeof body.tool !== "string" || typeof body.target !== "string" || typeof body.reason !== "string") {
        error(response, 400, "project, sessionId, tool, target, and reason are required.", "VALIDATION_ERROR");
        return;
      }
      const tool = getToolRegistry().find((entry) => entry.name === body.tool);
      if (!tool) return error(response, 404, "Requested tool is not registered.", "TOOL_NOT_FOUND");
      if (!tool.requiresApproval) return error(response, 422, "This tool does not require an approval record.", "APPROVAL_NOT_REQUIRED");
      const project = ensureProject(body.project);
      const sessionId = assertSafeName(body.sessionId, "Session ID");
      const sessionFile = safeChildPath(path.join(project.path, "sessions"), `${sessionId}.json`, "Session ID");
      if (!fs.existsSync(sessionFile)) return error(response, 404, "Assessment session not found.", "NOT_FOUND");
      const session = JSON.parse(fs.readFileSync(sessionFile, "utf8")) as SessionRecord;
      const validation = validateTarget(body.target, project.scope);
      if (!validation.ok) return error(response, 422, validation.reason ?? "Target is outside the authorized scope.", "OUT_OF_SCOPE");
      const approval: ApprovalRequest = {
        id: `approval-${Date.now().toString(36)}`,
        tool: body.tool,
        target: body.target,
        scope: project.scope,
        reason: body.reason,
        status: "pending",
      };
      session.approvals = [...session.approvals, approval];
      session.updatedAt = new Date().toISOString();
      fs.writeFileSync(sessionFile, JSON.stringify(session, null, 2));
      const db = new DatabaseService();
      await db.logEvent("approval_requested", { project: project.name, sessionId, approvalId: approval.id, actor: approver.user!.username });
      await db.close();
      json(response, 201, { data: { ...approval, project: project.name, sessionId } });
      return;
    }

    const approvalMatch = route.match(/^\/api\/approvals\/([^/]+)$/);
    if (approvalMatch && request.method === "PATCH") {
      const approver = requireRole(request, response, "approve");
      if (!approver) return;
      const body = await readBody(request);
      if (body.status !== "approved" && body.status !== "denied") return error(response, 400, "status must be approved or denied.", "VALIDATION_ERROR");
      const approvalId = decodeURIComponent(approvalMatch[1]);
      const projectName = typeof body.project === "string" ? body.project : undefined;
      const projects = projectName ? [openProject(projectName)] : listProjects();
      for (const project of projects) {
        const sessionFiles = fs.existsSync(path.join(project.path, "sessions")) ? fs.readdirSync(path.join(project.path, "sessions")).filter((file) => file.endsWith(".json")) : [];
        for (const sessionFileName of sessionFiles) {
          const sessionFile = path.join(project.path, "sessions", sessionFileName);
          const session = JSON.parse(fs.readFileSync(sessionFile, "utf8")) as SessionRecord;
          const approval = session.approvals.find((entry) => entry.id === approvalId);
          if (approval) {
            approval.status = body.status;
            session.updatedAt = new Date().toISOString();
            fs.writeFileSync(sessionFile, JSON.stringify(session, null, 2));
            const db = new DatabaseService();
            await db.logEvent("approval_updated", { project: project.name, approvalId, status: approval.status, actor: approver.user!.username });
            await db.close();
            json(response, 200, { data: { ...approval, project: project.name, sessionId: session.id } });
            return;
          }
        }
      }
      error(response, 404, "Approval request not found.", "NOT_FOUND");
      return;
    }
    const project = ensureProject(body.project);
    const validation = validateTarget(body.target, project.scope);
    if (!validation.ok) {
      error(response, 422, validation.reason ?? "Target is outside the authorized scope.", "OUT_OF_SCOPE");
      return;
    }
    if (!can(authenticated.user!.role, "approve")) {
      error(response, 403, "An approver role is required to request an active assessment.", "APPROVAL_REQUIRED");
      return;
    }
    const session = startSession(project.name, typeof body.objective === "string" ? body.objective : "Dashboard assessment request", body.target);
    const db = new DatabaseService();
    await db.logEvent("scan_requested", { project: project.name, target: body.target, sessionId: session.id, actor: authenticated.user!.username });
    await db.close();
    json(response, 202, { data: { ...session, execution: "planned", message: "Assessment is planned but not executed by the dashboard API. Use the scanner CLI with explicit approval to run tools." } });
    return;
  }

  if (route === "/api/findings" && request.method === "GET") {
    const project = url.searchParams.get("project") ?? undefined;
    const findings = project ? new FindingStore(project).listFindings() : listProjects().flatMap((entry) => new FindingStore(entry.name).listFindings().map((finding) => ({ ...finding, project: entry.name })));
    json(response, 200, { data: findings.map(safeFinding) });
    return;
  }

  const findingMatch = route.match(/^\/api\/findings\/([^/]+)$/);
  if (findingMatch) {
    const id = decodeURIComponent(findingMatch[1]);
    const project = url.searchParams.get("project") ?? undefined;
    const store = new FindingStore(project);
    if (request.method === "GET") {
      const finding = store.getFinding(id);
      if (!finding) return error(response, 404, "Finding not found.", "NOT_FOUND");
      json(response, 200, { data: safeFinding(finding) });
      return;
    }
    if (request.method === "PATCH") {
      const editor = requireRole(request, response, "manage_findings");
      if (!editor) return;
      const body = await readBody(request);
      const changes: Partial<Pick<Finding, "status" | "remediation">> = {};
      if (typeof body.status === "string" && ["potential", "suspected", "confirmed", "false_positive"].includes(body.status)) changes.status = body.status as Finding["status"];
      if (typeof body.remediation === "string") changes.remediation = body.remediation;
      if (!Object.keys(changes).length) return error(response, 400, "No supported finding changes were supplied.", "VALIDATION_ERROR");
      const updated = store.updateFinding(id, changes);
      const db = new DatabaseService();
      await db.logEvent("finding_updated", { findingId: id, status: updated.status, actor: editor.user!.username });
      await db.close();
      json(response, 200, { data: safeFinding(updated) });
      return;
    }
  }

  if (route === "/api/reports" && request.method === "GET") {
    json(response, 200, { data: reportRecords(url.searchParams.get("project") ?? undefined) });
    return;
  }

  if (route === "/api/activity" && request.method === "GET") {
    const db = new DatabaseService();
    const events = await db.getEventLog(Number(url.searchParams.get("limit") ?? 25));
    await db.close();
    json(response, 200, { data: events.map((event) => ({ ...event, payload: JSON.parse(event.payload) })) });
    return;
  }

  if (route === "/api/tools" && request.method === "GET") {
    json(response, 200, { data: getToolRegistry() });
    return;
  }

  error(response, 404, "API route not found.", "NOT_FOUND");
}

function serveStatic(request: http.IncomingMessage, response: http.ServerResponse, url: URL): void {
  const rawPath = url.pathname === "/" || url.pathname === "/login" ? "index.html" : url.pathname.replace(/^\/+/, "");
  const assetRequest = rawPath.startsWith("assets/");
  const requested = assetRequest ? rawPath.slice("assets/".length) : rawPath;
  const base = assetRequest ? assetRoot : dashboardRoot;
  const file = path.resolve(base, requested);
  if (!file.startsWith(`${base}${path.sep}`) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    response.writeHead(404);
    response.end("Not found");
    return;
  }
  const contentType = file.endsWith(".html") ? "text/html; charset=utf-8" : file.endsWith(".css") ? "text/css; charset=utf-8" : file.endsWith(".js") ? "text/javascript; charset=utf-8" : "image/svg+xml";
  response.writeHead(200, { "Content-Type": contentType });
  response.end(fs.readFileSync(file));
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    void api(request, response, url).catch((caught) => error(response, 500, caught instanceof Error ? caught.message : "Unexpected server error.", "INTERNAL_ERROR"));
    return;
  }
  serveStatic(request, response, url);
});

server.listen(port, () => {
  console.log(`Egyxos dashboard listening on http://localhost:${port}`);
});

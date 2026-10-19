import crypto from "node:crypto";

export type DashboardRole = "viewer" | "analyst" | "approver" | "admin";

export interface DashboardUser {
  id: string;
  username: string;
  passwordHash: string;
  role: DashboardRole;
  displayName?: string;
}

export interface DashboardSession {
  id: string;
  userId: string;
  csrfToken: string;
  createdAt: string;
  expiresAt: number;
}

const sessions = new Map<string, DashboardSession>();
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function parseUsers(): DashboardUser[] {
  const raw = process.env.EGYXOS_DASHBOARD_USERS_JSON;
  if (!raw) {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("EGYXOS_DASHBOARD_USERS_JSON must contain valid JSON.");
  }

  if (!Array.isArray(parsed)) {
    throw new Error("EGYXOS_DASHBOARD_USERS_JSON must be a JSON array.");
  }

  return parsed.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Dashboard user ${index + 1} is invalid.`);
    }
    const candidate = entry as Record<string, unknown>;
    if (typeof candidate.id !== "string" || typeof candidate.username !== "string"
      || typeof candidate.passwordHash !== "string" || !["viewer", "analyst", "approver", "admin"].includes(String(candidate.role))) {
      throw new Error(`Dashboard user ${index + 1} must include id, username, passwordHash, and a valid role.`);
    }
    return {
      id: candidate.id,
      username: candidate.username,
      passwordHash: candidate.passwordHash,
      role: candidate.role as DashboardRole,
      displayName: typeof candidate.displayName === "string" ? candidate.displayName : undefined,
    };
  });
}

export function hashPassword(password: string, salt = crypto.randomBytes(16).toString("hex")): string {
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password: string, encoded: string): boolean {
  const [algorithm, salt, expected] = encoded.split("$");
  if (algorithm !== "scrypt" || !salt || !expected) {
    return false;
  }
  const actual = crypto.scryptSync(password, salt, 64).toString("hex");
  return actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

export function findUser(username: string, password: string): DashboardUser | undefined {
  const users = parseUsers();
  return users.find((user) => user.username.toLowerCase() === username.trim().toLowerCase() && verifyPassword(password, user.passwordHash));
}

export function getUser(userId: string): DashboardUser | undefined {
  return parseUsers().find((user) => user.id === userId);
}

export function createSession(userId: string): DashboardSession {
  const now = Date.now();
  const session: DashboardSession = {
    id: crypto.randomBytes(32).toString("hex"),
    userId,
    csrfToken: crypto.randomBytes(24).toString("hex"),
    createdAt: new Date(now).toISOString(),
    expiresAt: now + SESSION_TTL_MS,
  };
  sessions.set(session.id, session);
  return session;
}

export function getSession(id: string | undefined): DashboardSession | undefined {
  if (!id) {
    return undefined;
  }
  const session = sessions.get(id);
  if (!session || session.expiresAt <= Date.now()) {
    if (session) {
      sessions.delete(id);
    }
    return undefined;
  }
  return session;
}

export function deleteSession(id: string | undefined): void {
  if (id) {
    sessions.delete(id);
  }
}

export function can(role: DashboardRole, action: "view" | "manage_findings" | "approve"): boolean {
  if (action === "view") return true;
  if (action === "manage_findings") return ["analyst", "approver", "admin"].includes(role);
  return ["approver", "admin"].includes(role);
}

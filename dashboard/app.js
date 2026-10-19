const loginScreen = document.querySelector("#login-screen");
const appShell = document.querySelector("#app-shell");
const loginForm = document.querySelector("#login-form");
const loginError = document.querySelector("#login-error");
const togglePassword = document.querySelector("#toggle-password");
const passwordInput = document.querySelector("#login-password");
const userAvatar = document.querySelector("#user-avatar");
let csrfToken = "";

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const body = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new Error(body?.error?.message || "The dashboard service is unavailable.");
  return body;
}

function showDashboard(user) {
  loginScreen.hidden = true;
  appShell.hidden = false;
  if (userAvatar) {
    userAvatar.textContent = (user.displayName || user.username).slice(0, 2).toUpperCase();
    userAvatar.title = `${user.displayName || user.username} · ${user.role}`;
  }
}

function showLogin(message = "") {
  appShell.hidden = true;
  loginScreen.hidden = false;
  if (message) {
    loginError.textContent = message;
    loginError.hidden = false;
  }
}

function renderEmptyTable(tableId, message, colspan) {
  const table = document.querySelector(tableId);
  if (table) table.innerHTML = `<tr><td colspan="${colspan}" class="empty-cell">${message}</td></tr>`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[character]));
}

function renderLiveTables(scans, findings) {
  const scansTable = document.querySelector("section#assessments tbody");
  if (scansTable) {
    scansTable.innerHTML = scans.length ? scans.slice(0, 8).map((scan) => {
      const status = scan.status === "active" ? "Running" : scan.status === "completed" ? "Completed" : escapeHtml(scan.status);
      const statusClass = scan.status === "active" ? "running" : scan.status === "completed" ? "complete" : "approval";
      return `<tr><td><strong>${escapeHtml(scan.project || "Project")}</strong><span class="table-subtext">${escapeHtml(scan.target)}</span></td><td>${escapeHtml(new Date(scan.createdAt).toLocaleDateString())}<span class="table-subtext">${escapeHtml(new Date(scan.createdAt).toLocaleTimeString())}</span></td><td><span class="status-pill ${statusClass}"><span class="status-dot"></span>${status}</span></td><td><strong>${findings.filter((finding) => finding.target === scan.target).length}</strong><span class="table-subtext">recorded</span></td><td><button class="report-button muted" type="button" disabled>Use Reports</button></td></tr>`;
    }).join("") : `<tr><td colspan="5" class="empty-cell">No assessment runs have been recorded yet.</td></tr>`;
  }

  const findingsTable = document.querySelector("#findings-table");
  if (findingsTable) {
    findingsTable.innerHTML = findings.length ? findings.slice(0, 20).map((finding) => {
      const severity = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);
      const confidence = finding.confidence.charAt(0).toUpperCase() + finding.confidence.slice(1);
      return `<tr data-search="${escapeHtml(`${finding.title} ${finding.target} ${finding.endpoint}`.toLowerCase())}" data-severity="${escapeHtml(severity)}" data-confidence="${escapeHtml(confidence)}" data-status="${escapeHtml(finding.status)}"><td><strong>${escapeHtml(finding.title)}</strong><span class="table-subtext">${escapeHtml(finding.target)} ${escapeHtml(finding.endpoint)}</span></td><td><span class="severity-badge ${escapeHtml(finding.severity)}">${escapeHtml(severity)}</span></td><td><span class="confidence-tag ${escapeHtml(finding.confidence)}">${escapeHtml(confidence)}</span></td><td><span class="status-pill ${finding.status === "confirmed" ? "complete" : "approval"}">${escapeHtml(finding.status)}</span></td><td><span class="evidence-state ${finding.evidence?.length ? "available" : "partial"}">● ${finding.evidence?.length || 0} items</span></td><td>${escapeHtml(finding.updatedAt || "Recorded")}</td><td><span class="owner-cell unassigned">--</span></td></tr>`;
    }).join("") : `<tr><td colspan="7" class="empty-cell">No findings have been recorded yet.</td></tr>`;
  }
}

async function loadLiveData() {
  const [projectsResponse, scansResponse, findingsResponse, activityResponse] = await Promise.all([
    apiRequest("/api/projects"),
    apiRequest("/api/scans"),
    apiRequest("/api/findings"),
    apiRequest("/api/activity"),
  ]);
  const projects = projectsResponse.data || [];
  const scans = scansResponse.data || [];
  const findings = findingsResponse.data || [];
  const activity = activityResponse.data || [];
  const metricValues = document.querySelectorAll(".metric-card strong");
  if (metricValues[0]) metricValues[0].textContent = String(projects.length).padStart(2, "0");
  if (metricValues[1]) metricValues[1].textContent = String(scans.length).padStart(2, "0");
  if (metricValues[2]) metricValues[2].textContent = String(findings.filter((finding) => finding.status !== "false_positive").length).padStart(2, "0");
  if (metricValues[3]) metricValues[3].textContent = String(findings.filter((finding) => finding.confidence !== "confirmed").length).padStart(2, "0");
  const chip = document.querySelector(".sample-chip");
  if (chip) chip.innerHTML = `<span class="status-dot good"></span>${projects.length || scans.length || findings.length ? "Live API data" : "No records yet"}`;
  const findingCount = document.querySelector("#finding-count");
  if (findingCount) findingCount.textContent = `Showing ${findings.length} recorded finding${findings.length === 1 ? "" : "s"}`;
  renderLiveTables(scans, findings);
  return { projects, scans, findings, activity };
}

togglePassword?.addEventListener("click", () => {
  const visible = passwordInput.type === "text";
  passwordInput.type = visible ? "password" : "text";
  togglePassword.textContent = visible ? "Show" : "Hide";
  togglePassword.setAttribute("aria-label", visible ? "Show password" : "Hide password");
});

loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.hidden = true;
  if (!loginForm.reportValidity()) return;
  const button = loginForm.querySelector("button[type=submit]");
  button.disabled = true;
  button.querySelector("span:first-child").hidden = true;
  button.querySelector(".login-spinner").hidden = false;
  try {
    const body = await apiRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: loginForm.username.value, password: loginForm.password.value }),
    });
    csrfToken = body.csrfToken;
    showDashboard(body.user);
    await loadLiveData();
  } catch (error) {
    loginError.textContent = error.message;
    loginError.hidden = false;
  } finally {
    button.disabled = false;
    button.querySelector("span:first-child").hidden = false;
    button.querySelector(".login-spinner").hidden = true;
  }
});

document.querySelector("#sign-out")?.addEventListener("click", async () => {
  try {
    await apiRequest("/api/auth/logout", { method: "POST", headers: { "X-CSRF-Token": csrfToken } });
  } finally {
    csrfToken = "";
    showLogin();
  }
});

void apiRequest("/api/auth/me").then(async (body) => {
  csrfToken = body.csrfToken;
  showDashboard(body.user);
  await loadLiveData();
}).catch(() => showLogin());

const modal = document.querySelector("#finding-modal");
const closeButton = modal?.querySelector(".close-button");
const scanModal = document.querySelector("#scan-modal");
const scanCloseButton = scanModal?.querySelector(".close-button");

function openFinding() {
  modal?.classList.add("open");
  modal?.setAttribute("aria-hidden", "false");
  closeButton?.focus();
}

function closeFinding() {
  modal?.classList.remove("open");
  modal?.setAttribute("aria-hidden", "true");
}

document.querySelectorAll("[data-finding]").forEach((button) => button.addEventListener("click", openFinding));
closeButton?.addEventListener("click", closeFinding);
modal?.addEventListener("click", (event) => { if (event.target === modal) closeFinding(); });

function openScan() {
  scanModal?.classList.add("open");
  scanModal?.setAttribute("aria-hidden", "false");
  scanCloseButton?.focus();
}

function closeScan() {
  scanModal?.classList.remove("open");
  scanModal?.setAttribute("aria-hidden", "true");
}

scanCloseButton?.addEventListener("click", closeScan);
scanModal?.addEventListener("click", (event) => { if (event.target === scanModal) closeScan(); });
document.querySelectorAll("[data-report]").forEach((button) => button.addEventListener("click", openScan));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeFinding();
    closeScan();
  }
});

document.querySelector(".dismiss-notice")?.addEventListener("click", (event) => event.currentTarget.closest(".notice-bar")?.remove());
document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => {
  document.querySelectorAll(".nav-item").forEach((navItem) => navItem.classList.remove("active"));
  item.classList.add("active");
}));

const filterInputs = [
  document.querySelector("#finding-search"),
  document.querySelector("#severity-filter"),
  document.querySelector("#confidence-filter"),
  document.querySelector("#status-filter"),
];

function filterFindings() {
  const [search, severity, confidence, status] = filterInputs.map((input) => input?.value.toLowerCase() ?? "");
  let visible = 0;
  document.querySelectorAll("#findings-table tr[data-search]").forEach((row) => {
    const matches = (!search || row.dataset.search.includes(search))
      && (!severity || row.dataset.severity.toLowerCase() === severity)
      && (!confidence || row.dataset.confidence.toLowerCase() === confidence)
      && (!status || row.dataset.status.toLowerCase() === status);
    row.hidden = !matches;
    if (matches) visible += 1;
  });
  const count = document.querySelector("#finding-count");
  if (count) count.textContent = `Showing ${visible} of 12 recorded findings`;
}

filterInputs.forEach((input) => input?.addEventListener("input", filterFindings));
document.querySelector("#clear-filters")?.addEventListener("click", () => {
  filterInputs.forEach((input) => { if (input) input.value = ""; });
  filterFindings();
});

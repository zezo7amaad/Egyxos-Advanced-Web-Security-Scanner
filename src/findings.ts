import fs from "node:fs";
import path from "node:path";
import { ensureProject } from "./project.js";
import { assertSafeName, safeChildPath } from "./config.js";
import type { Finding } from "./types.js";

export class FindingStore {
  projectName?: string;
  storageRoot?: string;

  constructor(projectName?: string, storageRoot?: string) {
    this.projectName = projectName;
    this.storageRoot = storageRoot;
  }

  private getProjectDir(): string {
    const project = ensureProject(this.projectName, this.storageRoot);
    return project.path;
  }

  addFinding(finding: Finding): Finding {
    const projectDir = this.getProjectDir();
    const findingsDir = path.join(projectDir, "findings");
    const filePath = safeChildPath(findingsDir, `${assertSafeName(finding.id, "Finding ID")}.json`, "Finding ID");
    fs.writeFileSync(filePath, JSON.stringify(finding, null, 2));
    return finding;
  }

  listFindings(): Finding[] {
    const projectDir = this.getProjectDir();
    const findingsDir = path.join(projectDir, "findings");
    if (!fs.existsSync(findingsDir)) {
      return [];
    }

    return fs
      .readdirSync(findingsDir)
      .filter((file) => file.endsWith(".json"))
      .map((file) => JSON.parse(fs.readFileSync(path.join(findingsDir, file), "utf8")) as Finding)
      .sort((a, b) => a.title.localeCompare(b.title));
  }

  getFinding(id: string): Finding | undefined {
    return this.listFindings().find((finding) => finding.id === id);
  }

  updateFinding(id: string, changes: Partial<Pick<Finding, "status" | "remediation">>): Finding {
    const finding = this.getFinding(id);
    if (!finding) {
      throw new Error(`Finding '${id}' not found.`);
    }
    const updated = { ...finding, ...changes };
    const findingsDir = path.join(this.getProjectDir(), "findings");
    const filePath = safeChildPath(findingsDir, `${assertSafeName(id, "Finding ID")}.json`, "Finding ID");
    fs.writeFileSync(filePath, JSON.stringify(updated, null, 2));
    return updated;
  }
}

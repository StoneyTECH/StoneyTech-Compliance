import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { persistAuditRun } from "../src/audit.js";
import { runCli } from "../src/cli.js";
import { RepositoryDiff } from "../src/git.js";
import {
  formatComplianceReportMarkdown,
  generateComplianceReport
} from "../src/report.js";
import { reviewDiff } from "../src/review.js";

const fakeApiKey = ["sk", "live", "1234567890abcdef"].join("_");
const fakeAuthBypass = ["skip", "Auth"].join("");

const sampleDiff = `diff --git a/src/app.ts b/src/app.ts
index 1111111..2222222 100644
--- a/src/app.ts
+++ b/src/app.ts
@@ -1,2 +1,5 @@
 export function handler() {
+  const apiKey = "${fakeApiKey}";
+  if (${fakeAuthBypass}) return { ok: true };
+  return apiKey;
 }
`;

describe("compliance report", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("summarizes repositories, merge coverage, controls, and remediation queue", () => {
    const seeded = seedReportDatabase(tempDirs);

    const report = generateComplianceReport({
      dbPath: seeded.dbPath,
      scope: "portfolio",
      days: 30,
      limit: 10
    });

    expect(report.summary.repositoryCount).toBe(1);
    expect(report.summary.auditRunCount).toBe(1);
    expect(report.summary.auditedMergeCount).toBe(1);
    expect(report.summary.pendingMergeCount).toBe(1);
    expect(report.summary.findingCount).toBeGreaterThan(0);
    expect(report.summary.openPriorityCounts.critical).toBeGreaterThan(0);
    expect(report.findingsByControl.length).toBeGreaterThan(0);
    expect(report.remediationQueue.length).toBeGreaterThan(0);
    expect(report.pendingUnauditedMerges[0]?.id).toBe("merge_pending");

    const markdown = formatComplianceReportMarkdown(report);
    expect(markdown).toContain("## Executive Summary");
    expect(markdown).toContain("## Pending Unaudited Merges");
    expect(markdown).toContain("## Standards Catalog Version Snapshot");
  });

  it("supports audit-run scoped reports", () => {
    const seeded = seedReportDatabase(tempDirs);

    const report = generateComplianceReport({
      dbPath: seeded.dbPath,
      scope: "audit_run",
      auditRunId: seeded.auditRunId
    });

    expect(report.summary.auditRunCount).toBe(1);
    expect(report.summary.findingCount).toBeGreaterThan(0);
    expect(report.repositories[0]?.id).toBe(seeded.repositoryId);
  });

  it("prints JSON reports through the CLI", async () => {
    const seeded = seedReportDatabase(tempDirs);
    const stdout: string[] = [];
    const stderr: string[] = [];

    const code = await runCli([
      "report",
      "--db",
      seeded.dbPath,
      "--format",
      "json"
    ], {
      stdout: (text) => stdout.push(text),
      stderr: (text) => stderr.push(text)
    });

    expect(code).toBe(0);
    expect(stderr.join("")).toBe("");
    const payload = JSON.parse(stdout.join(""));
    expect(payload.reportVersion).toBe("compliance-report-v1");
    expect(payload.summary.pendingMergeCount).toBe(1);
  });
});

function seedReportDatabase(tempDirs: string[]): {
  dbPath: string;
  auditRunId: string;
  repositoryId: string;
} {
  const dir = mkdtempSync(path.join(tmpdir(), "compliance-report-"));
  tempDirs.push(dir);
  const dbPath = path.join(dir, "compliance.db");
  const repoDiff: RepositoryDiff = {
    repoRoot: dir,
    diffText: sampleDiff,
    truncated: false,
    mode: "working-tree",
    command: "git diff --no-ext-diff --find-renames"
  };
  const report = reviewDiff(sampleDiff, { profile: "security", riskAreas: ["api"] });
  const persisted = persistAuditRun({
    dbPath,
    repoDiff,
    report,
    reviewRequest: { profile: "security", riskAreas: ["api"] }
  });

  const db = new DatabaseSync(dbPath);
  try {
    insertMergeEvent(db, {
      id: "merge_audited",
      repositoryId: persisted.repositoryId,
      providerEventId: "github:pr:repo:1:2222222",
      mergeCommitSha: "2222222222222222222222222222222222222222",
      title: "Audited change",
      status: "audited",
      auditRunId: persisted.auditRunId,
      mergedAt: "2026-05-03T00:01:00.000Z"
    });
    insertMergeEvent(db, {
      id: "merge_pending",
      repositoryId: persisted.repositoryId,
      providerEventId: "github:pr:repo:2:3333333",
      mergeCommitSha: "3333333333333333333333333333333333333333",
      title: "Pending change",
      status: "pending",
      mergedAt: "2026-05-03T00:02:00.000Z"
    });
  } finally {
    db.close();
  }

  return {
    dbPath,
    auditRunId: persisted.auditRunId,
    repositoryId: persisted.repositoryId
  };
}

function insertMergeEvent(db: DatabaseSync, options: {
  id: string;
  repositoryId: string;
  providerEventId: string;
  mergeCommitSha: string;
  title: string;
  status: "pending" | "audited";
  auditRunId?: string;
  mergedAt: string;
}): void {
  db.prepare(`INSERT INTO merge_events (
    id, repository_id, provider, provider_event_id, event_type, branch,
    base_sha, head_sha, merge_commit_sha, pr_number, title, author, merged_at,
    html_url, audit_run_id, status, metadata_json
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    options.id,
    options.repositoryId,
    "github",
    options.providerEventId,
    "pull_request_merged",
    "main",
    "1111111111111111111111111111111111111111",
    options.mergeCommitSha,
    options.mergeCommitSha,
    7,
    options.title,
    "example-user",
    options.mergedAt,
    "https://github.com/example-org/example/pull/7",
    options.auditRunId ?? null,
    options.status,
    "{}"
  );
}

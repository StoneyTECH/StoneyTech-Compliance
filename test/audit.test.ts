import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  getAuditRun,
  initAuditDatabase,
  listAuditRuns,
  persistAuditRun,
  summarizeAuditTrends
} from "../src/audit.js";
import { RepositoryDiff } from "../src/git.js";
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

describe("audit persistence", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("initializes, persists, and queries audit runs", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "compliance-audit-"));
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

    const init = initAuditDatabase({ dbPath });
    expect(init.initialized).toBe(true);

    const persisted = persistAuditRun({
      dbPath,
      repoDiff,
      report,
      reviewRequest: { profile: "security", riskAreas: ["api"] }
    });

    expect(persisted.auditRunId).toMatch(/^audit_/);
    expect(persisted.findingIds.length).toBeGreaterThan(0);
    expect(persisted.manifest.diffHash).toMatch(/^sha256:/);
    expect(persisted.manifest.standardsSnapshotHash).toMatch(/^sha256:/);

    const history = listAuditRuns({ dbPath, limit: 10 });
    expect(history.auditRuns).toHaveLength(1);
    expect(history.auditRuns[0]?.id).toBe(persisted.auditRunId);

    const detail = getAuditRun({ dbPath, auditRunId: persisted.auditRunId });
    expect(detail.auditRun?.findings.length).toBeGreaterThan(0);
    expect(detail.auditRun?.findings[0]?.controls.length).toBeGreaterThan(0);
    expect(detail.auditRun?.findings[0]?.priority?.band).toBeDefined();

    const trends = summarizeAuditTrends({ dbPath, days: 7 });
    expect(trends.totals.auditRuns).toBe(1);
    expect(trends.totals.findings).toBeGreaterThan(0);

    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const edgeCount = db.prepare("SELECT COUNT(*) AS count FROM graph_edges").get() as { count: number };
      expect(edgeCount.count).toBeGreaterThan(0);
      const impactEdgeCount = db.prepare("SELECT COUNT(*) AS count FROM graph_edges WHERE edge_type IN ('AFFECTS_COMPONENT', 'BLOCKS', 'AMPLIFIES', 'SHARES_ROOT_CAUSE_WITH')").get() as { count: number };
      expect(impactEdgeCount.count).toBeGreaterThan(0);
    } finally {
      db.close();
    }
  });
});

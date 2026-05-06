import { describe, expect, it } from "vitest";
import { formatPriorityPlanMarkdown, prioritizeFindings } from "../src/priority.js";
import { reviewDiff } from "../src/review.js";

const fakeApiKey = ["sk", "live", "1234567890abcdef"].join("_");
const fakeAuthBypass = ["skip", "Auth"].join("");
const fakeFetchCall = ["fe", "tch"].join("") + "(\"https://example.com/data\")";
const fakeLogCall = ["console", "log"].join(".") + "(\"token\", apiKey)";

const sampleDiff = `diff --git a/src/api/admin.ts b/src/api/admin.ts
index 1111111..2222222 100644
--- a/src/api/admin.ts
+++ b/src/api/admin.ts
@@ -1,2 +1,7 @@
 export function handler() {
+  const apiKey = "${fakeApiKey}";
+  if (${fakeAuthBypass}) return { ok: true };
+  ${fakeLogCall};
+  return ${fakeFetchCall};
 }
`;

describe("priority planning", () => {
  it("orders findings by deterministic priority and emits graph edges", () => {
    const report = reviewDiff(sampleDiff, { profile: "security" });
    const plan = prioritizeFindings(report.findings);

    expect(plan.findingCount).toBeGreaterThan(0);
    expect(plan.counts.critical).toBeGreaterThan(0);
    expect(plan.remediationSteps[0]?.priorityBand).toBe("critical");
    expect(plan.remediationSteps[0]?.score).toBeGreaterThan(plan.remediationSteps.at(-1)?.score ?? 0);
    expect(plan.graph.nodes.some((node) => node.kind === "standard_control")).toBe(true);
    expect(plan.graph.edges.some((edge) => edge.type === "VIOLATES_CONTROL")).toBe(true);
    expect(plan.graph.edges.some((edge) => edge.type === "BLOCKS" || edge.type === "AMPLIFIES")).toBe(true);

    const criticalStep = plan.remediationSteps.find((step) => step.priorityBand === "critical");
    expect(criticalStep?.standards.length).toBeGreaterThan(0);
  });

  it("formats a human-readable remediation plan", () => {
    const report = reviewDiff(sampleDiff, { profile: "security" });
    const markdown = formatPriorityPlanMarkdown(prioritizeFindings(report.findings));

    expect(markdown).toContain("Priority Order");
    expect(markdown).toContain("Remediation Steps");
    expect(markdown).toContain("critical");
  });
});

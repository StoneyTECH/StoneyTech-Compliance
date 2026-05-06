import { describe, expect, it } from "vitest";
import {
  CHECKLIST_STANDARD_REFERENCES,
  RULE_STANDARD_REFERENCES,
  STANDARDS_CATALOG
} from "../src/standards.js";

describe("standards catalog", () => {
  it("tracks the current OWASP Top 10 and CWE Top 25 pins", () => {
    expect(STANDARDS_CATALOG).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "owasp-top10-2025", version: "2025" }),
      expect.objectContaining({ id: "mitre-cwe-top25-2025", version: "2025" })
    ]));
  });

  it("uses resolvable standard ids in checklist and rule mappings", () => {
    const standardIds = new Set(STANDARDS_CATALOG.map((standard) => standard.id));
    const references = [
      ...Object.values(CHECKLIST_STANDARD_REFERENCES).flat(),
      ...Object.values(RULE_STANDARD_REFERENCES).flat()
    ];

    expect(references.length).toBeGreaterThan(0);
    for (const reference of references) {
      expect(standardIds.has(reference.standardId)).toBe(true);
    }
  });
});


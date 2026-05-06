import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  MCP_TOOL_SECURITY_POLICIES,
  assertMcpPathAllowed,
  assertSafeGitRef,
  securityPolicyPayload
} from "../src/security.js";

describe("MCP security guardrails", () => {
  const tempDirs: string[] = [];
  const originalAllowedRoots = process.env.MCP_COMPLIANCE_SCAN_ALLOWED_ROOTS;
  const originalAllowAny = process.env.MCP_COMPLIANCE_SCAN_ALLOW_ANY_ROOT;

  afterEach(() => {
    restoreEnv("MCP_COMPLIANCE_SCAN_ALLOWED_ROOTS", originalAllowedRoots);
    restoreEnv("MCP_COMPLIANCE_SCAN_ALLOW_ANY_ROOT", originalAllowAny);
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("allows paths under configured roots and rejects paths outside them", () => {
    const allowed = mkdtempSync(path.join(tmpdir(), "compliance-allowed-"));
    const outside = mkdtempSync(path.join(tmpdir(), "compliance-outside-"));
    tempDirs.push(allowed, outside);
    process.env.MCP_COMPLIANCE_SCAN_ALLOWED_ROOTS = allowed;
    delete process.env.MCP_COMPLIANCE_SCAN_ALLOW_ANY_ROOT;

    expect(assertMcpPathAllowed(path.join(allowed, "repo"), "repoPath")).toBe(path.join(allowed, "repo"));
    expect(() => assertMcpPathAllowed(path.join(outside, "repo"), "repoPath")).toThrow(/outside the configured MCP allowed roots/);
  });

  it("requires an explicit override to allow arbitrary roots", () => {
    const outside = mkdtempSync(path.join(tmpdir(), "compliance-any-root-"));
    tempDirs.push(outside);
    process.env.MCP_COMPLIANCE_SCAN_ALLOWED_ROOTS = path.join(outside, "not-this");
    process.env.MCP_COMPLIANCE_SCAN_ALLOW_ANY_ROOT = "1";

    expect(assertMcpPathAllowed(outside, "repoPath")).toBe(outside);
  });

  it("rejects suspicious git refs", () => {
    expect(() => assertSafeGitRef("main", "baseRef")).not.toThrow();
    expect(() => assertSafeGitRef("origin/feature-1", "baseRef")).not.toThrow();
    expect(() => assertSafeGitRef("--upload-pack=evil", "baseRef")).toThrow(/not an allowed git ref/);
    expect(() => assertSafeGitRef("main..evil", "baseRef")).toThrow(/not an allowed git ref/);
    expect(() => assertSafeGitRef("main\nHEAD", "baseRef")).toThrow(/not an allowed git ref/);
  });

  it("labels every MCP tool with security effects and guardrails", () => {
    const payload = securityPolicyPayload();

    expect(payload.tools.length).toBeGreaterThanOrEqual(20);
    expect(MCP_TOOL_SECURITY_POLICIES.audit_merge.effects).toContain("repo-clone");
    expect(MCP_TOOL_SECURITY_POLICIES.audit_merge.defaultDecision).toBe("validate");
    expect(MCP_TOOL_SECURITY_POLICIES.review_repository.guardrails.join(" ")).toContain("allowed roots");
  });
});

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

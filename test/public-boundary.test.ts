import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

describe("public repo and local data boundary", () => {
  it("keeps local runtime and database paths ignored", () => {
    const gitignore = readFileSync(".gitignore", "utf8");

    for (const pattern of [".local/", "local/", "data/", "audit-runs/", "reports/", "exports/", ".n8n/", "n8n-data/", "*.sqlite", "*.sqlite3", "*.db"]) {
      expect(gitignore).toContain(pattern);
    }
  });

  it("keeps committed n8n workflow templates credential-free", () => {
    const workflow = JSON.parse(readFileSync("workflows/n8n/standards-monitor.template.json", "utf8"));
    const serialized = JSON.stringify(workflow).toLowerCase();

    expect(workflow.name).toBe("Standards Monitor");
    expect(serialized).not.toContain("\"credentials\"");
    expect(serialized).not.toContain("access_token");
    expect(serialized).not.toContain("secret");
  });

  it("keeps published files free of private workspace markers", () => {
    const files = execFileSync("git", ["ls-files"], { encoding: "utf8" })
      .split(/\r?\n/)
      .filter(Boolean);

    for (const file of files) {
      if (!existsSync(file)) {
        continue;
      }
      const content = readFileSync(file, "utf8");
      expect(content).not.toContain(["stoney", "arch"].join("-"));
      expect(content).not.toContain(["", "Users", ""].join("/"));
      expect(content).not.toContain(["STONEYTECH", "COMPLIANCE", "TOKEN"].join("_"));
      expect(content).not.toContain(["UN", "LICENSED"].join(""));
    }
  });

  it("publishes under Apache-2.0", () => {
    const packageJson = JSON.parse(readFileSync("package.json", "utf8")) as { license?: string };
    const license = readFileSync("LICENSE", "utf8");

    expect(packageJson.license).toBe("Apache-2.0");
    expect(license).toContain("Apache License");
    expect(license).toContain("Version 2.0");
    expect(license).toContain("Copyright 2026 StoneyTECH");
  });

  it("ships local audit schema with rollback coverage", () => {
    const schema = readFileSync("schema/audit-ledger.sql", "utf8");
    const rollback = readFileSync("schema/audit-ledger.rollback.sql", "utf8");

    for (const table of ["standard_versions", "controls", "rule_packs", "audit_runs", "findings", "graph_edges"]) {
      expect(schema).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
      expect(rollback).toContain(`DROP TABLE IF EXISTS ${table}`);
    }
  });
});

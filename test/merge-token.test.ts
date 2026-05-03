import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { syncGithubRepositories } from "../src/merge.js";

describe("GitHub token discovery", () => {
  const tempDirs: string[] = [];
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("falls back to the GitHub CLI token when token env vars are absent", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "compliance-gh-token-"));
    tempDirs.push(dir);
    const binDir = path.join(dir, "bin");
    mkdirSync(binDir);
    const ghPath = path.join(binDir, "gh");
    writeFileSync(ghPath, "#!/bin/sh\nif [ \"$1\" = \"auth\" ] && [ \"$2\" = \"token\" ]; then echo fake-gh-token; exit 0; fi\nexit 1\n");
    chmodSync(ghPath, 0o755);

    delete process.env.MCP_COMPLIANCE_SCAN_GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;
    delete process.env.GH_TOKEN;
    process.env.PATH = `${binDir}${path.delimiter}${originalEnv.PATH ?? ""}`;

    let authorizationHeader = "";
    const result = await syncGithubRepositories({
      dbPath: path.join(dir, "compliance.db"),
      limit: 1,
      fetchImpl: async (_input, init) => {
        authorizationHeader = String(new Headers(init?.headers).get("authorization") ?? "");
        return new Response(JSON.stringify([
          {
            id: 1,
            name: "TokenTest",
            full_name: "example-org/TokenTest",
            clone_url: "https://github.com/example-org/TokenTest.git",
            html_url: "https://github.com/example-org/TokenTest",
            private: true,
            visibility: "private",
            archived: false,
            fork: false,
            is_template: false,
            default_branch: "main",
            description: "Token fallback test",
            pushed_at: "2026-05-03T00:00:00.000Z",
            updated_at: "2026-05-03T00:00:00.000Z",
            topics: []
          }
        ]), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
    });

    expect(result.repositoryCount).toBe(1);
    expect(authorizationHeader).toBe("Bearer fake-gh-token");
  });
});

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  auditMergeEvent,
  listRegisteredRepositories,
  mergeAuditHistory,
  syncGithubRepositories,
  syncRepositoryMerges
} from "../src/merge.js";

const fakeApiKey = ["sk", "live", "1234567890abcdef"].join("_");

describe("merge tracking", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("syncs repositories, records merge events, and audits an exact merge diff", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "compliance-merge-"));
    tempDirs.push(dir);
    const dbPath = path.join(dir, "compliance.db");
    const repoPath = path.join(dir, "repo");
    mkdirSync(repoPath);
    git(repoPath, "init", "-b", "main");
    git(repoPath, "config", "user.email", "codex@example.com");
    git(repoPath, "config", "user.name", "Codex Test");
    mkdirSync(path.join(repoPath, "src"));
    writeFileSync(path.join(repoPath, "src", "app.ts"), "export const ok = true;\n");
    git(repoPath, "add", ".");
    git(repoPath, "commit", "-m", "initial");
    const baseSha = git(repoPath, "rev-parse", "HEAD");
    writeFileSync(path.join(repoPath, "src", "app.ts"), `export const apiKey = "${fakeApiKey}";\n`);
    git(repoPath, "add", ".");
    git(repoPath, "commit", "-m", "add api client");
    const mergeSha = git(repoPath, "rev-parse", "HEAD");

    const fetchImpl = fakeGithubFetch({
      repoPath,
      baseSha,
      mergeSha
    });

    const syncRepos = await syncGithubRepositories({
      dbPath,
      token: "test-token",
      fetchImpl
    });
    expect(syncRepos.repositoryCount).toBe(1);

    const registered = listRegisteredRepositories({ dbPath });
    expect(registered.repositories[0]?.name).toBe("example-org/TestApi");
    expect(registered.repositories[0]?.trackMerges).toBe(true);

    const syncMerges = await syncRepositoryMerges({
      dbPath,
      repository: "example-org/TestApi",
      token: "test-token",
      fetchImpl,
      since: "2026-01-01T00:00:00.000Z",
      includeDefaultBranchCommits: true
    });
    expect(syncMerges.mergeEventCount).toBe(1);
    expect(syncMerges.mergeEvents[0]?.baseSha).toBe(baseSha);
    expect(syncMerges.mergeEvents[0]?.mergeCommitSha).toBe(mergeSha);

    const mergeEventId = syncMerges.mergeEvents[0]?.id;
    expect(mergeEventId).toBeDefined();

    const audited = await auditMergeEvent({
      dbPath,
      mergeEventId: mergeEventId!,
      repoPath,
      profile: "security"
    });
    expect(audited.auditRunId).toMatch(/^audit_/);
    expect(audited.findingCount).toBeGreaterThan(0);

    const history = mergeAuditHistory({ dbPath });
    expect(history.mergeEvents[0]?.status).toBe("audited");
    expect(history.mergeEvents[0]?.auditRunId).toBe(audited.auditRunId);
  });

  it("audits root commits by diffing against the empty tree", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "compliance-root-merge-"));
    tempDirs.push(dir);
    const dbPath = path.join(dir, "compliance.db");
    const repoPath = path.join(dir, "repo");
    mkdirSync(repoPath);
    git(repoPath, "init", "-b", "main");
    git(repoPath, "config", "user.email", "codex@example.com");
    git(repoPath, "config", "user.name", "Codex Test");
    mkdirSync(path.join(repoPath, "src"));
    writeFileSync(path.join(repoPath, "src", "app.ts"), `export const apiKey = "${fakeApiKey}";\n`);
    git(repoPath, "add", ".");
    git(repoPath, "commit", "-m", "initial secret");
    const rootSha = git(repoPath, "rev-parse", "HEAD");

    const fetchImpl = fakeGithubFetch({
      repoPath,
      mergeSha: rootSha
    });

    await syncGithubRepositories({
      dbPath,
      token: "test-token",
      fetchImpl
    });
    const syncMerges = await syncRepositoryMerges({
      dbPath,
      repository: "example-org/TestApi",
      token: "test-token",
      fetchImpl,
      since: "2026-01-01T00:00:00.000Z",
      includeDefaultBranchCommits: true
    });

    expect(syncMerges.mergeEvents[0]?.baseSha).toBeUndefined();

    const audited = await auditMergeEvent({
      dbPath,
      mergeEventId: syncMerges.mergeEvents[0]!.id,
      repoPath,
      profile: "security"
    });
    expect(audited.findingCount).toBeGreaterThan(0);
  });
});

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

function fakeGithubFetch(options: {
  repoPath: string;
  baseSha?: string;
  mergeSha: string;
}): typeof fetch {
  return async (input) => {
    const url = String(input);
    if (url.includes("/user/repos")) {
      return jsonResponse([
        {
          id: 1001,
          name: "TestApi",
          full_name: "example-org/TestApi",
          clone_url: options.repoPath,
          html_url: "https://github.com/example-org/TestApi",
          private: true,
          visibility: "private",
          archived: false,
          fork: false,
          is_template: false,
          default_branch: "main",
          description: "API service",
          pushed_at: "2026-05-03T00:00:00.000Z",
          updated_at: "2026-05-03T00:00:00.000Z",
          topics: ["api"]
        }
      ]);
    }

    if (url.includes("/pulls?")) {
      return jsonResponse([
        {
          number: 7,
          title: "Add API client",
          html_url: "https://github.com/example-org/TestApi/pull/7",
          merged_at: "2026-05-03T00:01:00.000Z",
          merge_commit_sha: options.mergeSha,
          user: { login: "example-user" },
          base: { ref: "main", sha: options.baseSha },
          head: { sha: options.mergeSha }
        }
      ]);
    }

    if (url.includes("/commits?")) {
      return jsonResponse([
        {
          sha: options.mergeSha,
          html_url: "https://github.com/example-org/TestApi/commit/example",
          commit: {
            message: "Add API client",
            author: { name: "Auston", date: "2026-05-03T00:01:00.000Z" },
            committer: { name: "Auston", date: "2026-05-03T00:01:00.000Z" }
          },
          author: { login: "example-user" },
          parents: options.baseSha ? [{ sha: options.baseSha }] : []
        }
      ]);
    }

    return new Response(JSON.stringify({ message: `Unhandled ${url}` }), { status: 404 });
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: {
      "content-type": "application/json"
    }
  });
}

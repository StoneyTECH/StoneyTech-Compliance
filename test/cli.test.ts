import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

const fakeApiKey = ["sk", "live", "1234567890abcdef"].join("_");

describe("CLI", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reviews a repository and exits nonzero when findings meet the fail threshold", async () => {
    const repoPath = createRepoWithSecret(tempDirs);
    const stdout: string[] = [];
    const stderr: string[] = [];

    const code = await runCli([
      "review",
      "--repo",
      repoPath,
      "--profile",
      "security",
      "--format",
      "json",
      "--fail-on",
      "critical"
    ], {
      stdout: (text) => stdout.push(text),
      stderr: (text) => stderr.push(text)
    });

    expect(stderr.join("")).toBe("");
    expect(code).toBe(1);
    const payload = JSON.parse(stdout.join(""));
    expect(payload.review.status).toBe("fail");
    expect(payload.priorityPlan.counts.critical).toBeGreaterThan(0);
  });

  it("supports GitHub annotation output without forcing failure", async () => {
    const repoPath = createRepoWithSecret(tempDirs);
    const stdout: string[] = [];

    const code = await runCli([
      "review",
      "--repo",
      repoPath,
      "--profile",
      "security",
      "--format",
      "github",
      "--fail-on",
      "none"
    ], {
      stdout: (text) => stdout.push(text),
      stderr: () => undefined
    });

    expect(code).toBe(0);
    expect(stdout.join("")).toContain("::error");
  });
});

function createRepoWithSecret(tempDirs: string[]): string {
  const dir = mkdtempSync(path.join(tmpdir(), "compliance-cli-"));
  tempDirs.push(dir);
  git(dir, "init", "-b", "main");
  git(dir, "config", "user.email", "codex@example.com");
  git(dir, "config", "user.name", "Codex Test");
  mkdirSync(path.join(dir, "src"));
  writeFileSync(path.join(dir, "src", "app.ts"), "export const ok = true;\n");
  git(dir, "add", ".");
  git(dir, "commit", "-m", "initial");
  writeFileSync(path.join(dir, "src", "app.ts"), `export const apiKey = "${fakeApiKey}";\n`);
  return dir;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

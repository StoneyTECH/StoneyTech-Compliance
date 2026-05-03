import { execFile } from "node:child_process";
import { access, mkdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DEFAULT_MAX_BYTES = 512_000;
const MAX_UNTRACKED_FILE_BYTES = 256_000;

const TEXT_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".conf",
  ".cpp",
  ".cs",
  ".css",
  ".go",
  ".graphql",
  ".html",
  ".java",
  ".js",
  ".json",
  ".jsx",
  ".kt",
  ".md",
  ".mjs",
  ".php",
  ".prisma",
  ".py",
  ".rb",
  ".rs",
  ".sh",
  ".sql",
  ".swift",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".vue",
  ".xml",
  ".yaml",
  ".yml"
]);

export type ReviewMode = "working-tree" | "staged" | "range";

export interface RepositoryDiffOptions {
  repoPath: string;
  mode?: ReviewMode;
  baseRef?: string;
  targetRef?: string;
  includeUntracked?: boolean;
  maxBytes?: number;
}

export interface RepositoryDiff {
  repoRoot: string;
  diffText: string;
  truncated: boolean;
  mode: ReviewMode;
  command: string;
  baseCommitSha?: string;
  targetCommitSha?: string;
  branch?: string;
}

export interface ExactRepositoryDiffOptions {
  repoPath: string;
  baseRef: string;
  targetRef: string;
  maxBytes?: number;
}

export interface CloneOrUpdateRepositoryOptions {
  remoteUrl: string;
  localPath: string;
}

export async function getRepositoryDiff(options: RepositoryDiffOptions): Promise<RepositoryDiff> {
  const mode = options.mode ?? "working-tree";
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const repoRoot = await resolveRepositoryRoot(options.repoPath);
  const args = buildDiffArgs(mode, options.baseRef, options.targetRef);
  const diff = await runGit(repoRoot, args);
  const untracked = options.includeUntracked ?? mode === "working-tree"
    ? await buildUntrackedDiff(repoRoot, maxBytes)
    : "";
  const combined = `${diff}${untracked}`;
  const truncated = Buffer.byteLength(combined, "utf8") > maxBytes;
  const diffText = truncated ? combined.slice(0, maxBytes) : combined;

  return {
    repoRoot,
    diffText,
    truncated,
    mode,
    command: `git ${args.join(" ")}`
  };
}

export async function getRepositoryExactDiff(options: ExactRepositoryDiffOptions): Promise<RepositoryDiff> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const repoRoot = await resolveRepositoryRoot(options.repoPath);
  const args = ["diff", "--no-ext-diff", "--find-renames", `${options.baseRef}..${options.targetRef}`];
  const diff = await runGit(repoRoot, args);
  const truncated = Buffer.byteLength(diff, "utf8") > maxBytes;

  return {
    repoRoot,
    diffText: truncated ? diff.slice(0, maxBytes) : diff,
    truncated,
    mode: "range",
    command: `git ${args.join(" ")}`,
    baseCommitSha: options.baseRef,
    targetCommitSha: options.targetRef
  };
}

export async function fetchRepository(repoPath: string, remote = "origin"): Promise<void> {
  const repoRoot = await resolveRepositoryRoot(repoPath);
  await runGit(repoRoot, ["fetch", "--prune", remote]);
}

export async function cloneOrUpdateRepository(options: CloneOrUpdateRepositoryOptions): Promise<string> {
  const localPath = path.resolve(options.localPath);

  try {
    return await resolveRepositoryRoot(localPath);
  } catch {
    await mkdir(path.dirname(localPath), { recursive: true });
    await runGit(path.dirname(localPath), ["clone", options.remoteUrl, localPath]);
    return resolveRepositoryRoot(localPath);
  }
}

async function resolveRepositoryRoot(repoPath: string): Promise<string> {
  const absolute = path.resolve(repoPath);
  await access(absolute);
  const output = await runGit(absolute, ["rev-parse", "--show-toplevel"]);
  return output.trim();
}

function buildDiffArgs(mode: ReviewMode, baseRef?: string, targetRef?: string): string[] {
  const args = ["diff", "--no-ext-diff", "--find-renames"];

  if (mode === "staged") {
    return [...args, "--cached"];
  }

  if (mode === "range") {
    const base = baseRef ?? "main";
    const target = targetRef ?? "HEAD";
    return [...args, `${base}...${target}`];
  }

  if (baseRef && targetRef) {
    return [...args, `${baseRef}...${targetRef}`];
  }

  if (baseRef) {
    return [...args, baseRef];
  }

  return args;
}

async function runGit(cwd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: 20 * 1024 * 1024,
      encoding: "utf8"
    });
    return stdout;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`git ${args.join(" ")} failed in ${cwd}: ${message}`);
  }
}

async function buildUntrackedDiff(repoRoot: string, maxBytes: number): Promise<string> {
  const output = await runGit(repoRoot, ["ls-files", "--others", "--exclude-standard"]);
  const files = output.split(/\r?\n/).filter(Boolean);
  const chunks: string[] = [];
  let usedBytes = 0;

  for (const file of files) {
    if (!isReviewableTextPath(file)) {
      continue;
    }

    const absolute = path.resolve(repoRoot, file);
    if (!absolute.startsWith(repoRoot + path.sep)) {
      continue;
    }

    const fileStat = await stat(absolute);
    if (!fileStat.isFile() || fileStat.size > MAX_UNTRACKED_FILE_BYTES) {
      continue;
    }

    const content = await readFile(absolute, "utf8");
    if (content.includes("\u0000")) {
      continue;
    }

    const diff = toNewFileDiff(file, content);
    usedBytes += Buffer.byteLength(diff, "utf8");
    if (usedBytes > maxBytes) {
      chunks.push("\n# Compliance review: untracked file diff truncated\n");
      break;
    }
    chunks.push(diff);
  }

  return chunks.join("");
}

function toNewFileDiff(file: string, content: string): string {
  const lines = content.split(/\r?\n/);
  const added = lines.map((line) => `+${line}`).join("\n");
  return [
    `diff --git a/${file} b/${file}`,
    "new file mode 100644",
    "index 0000000..0000000",
    "--- /dev/null",
    `+++ b/${file}`,
    `@@ -0,0 +1,${Math.max(lines.length, 1)} @@`,
    added,
    ""
  ].join("\n");
}

function isReviewableTextPath(file: string): boolean {
  const base = path.basename(file);
  if (base.startsWith(".")) {
    return [".env.example", ".gitignore"].includes(base);
  }

  if (["Dockerfile", "Makefile", "package.json", "tsconfig.json"].includes(base)) {
    return true;
  }

  return TEXT_EXTENSIONS.has(path.extname(file));
}

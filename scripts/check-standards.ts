#!/usr/bin/env tsx
import { STANDARDS_CATALOG, StandardSource } from "../src/standards.js";

type OutputFormat = "json" | "markdown";
type FailMode = "updates" | "errors" | "never";
type CheckStatus = "ok" | "update_available" | "tracking" | "error";

interface VersionCheckResult {
  standardId: string;
  name: string;
  authority: string;
  currentVersion: string;
  latestVersion?: string;
  latestUrl?: string;
  sourceUrl: string;
  status: CheckStatus;
  notes?: string;
}

interface VersionResolver {
  sourceUrl: string;
  latestUrl?: (latestVersion: string) => string;
  compare?: boolean;
  detect: (text: string) => string | undefined;
}

interface Report {
  checkedAt: string;
  summary: {
    total: number;
    okCount: number;
    updateCount: number;
    trackingCount: number;
    errorCount: number;
  };
  results: VersionCheckResult[];
}

const CHECKS: Record<string, VersionResolver> = {
  "owasp-asvs-5.0.0": {
    sourceUrl: "https://raw.githubusercontent.com/OWASP/ASVS/master/README.md",
    latestUrl: (version) => `https://github.com/OWASP/ASVS/tree/v${version}`,
    detect: (text) => firstMatch(text, /Latest Stable Version\s*-\s*([0-9.]+)/i)
  },
  "owasp-api-top10-2023": {
    sourceUrl: "https://owasp.org/www-project-api-security/",
    latestUrl: (version) => `https://owasp.org/API-Security/editions/${version}/en/0x00-header/`,
    detect: (text) => maxMatch(text, /OWASP API Security Top 10\s+(20\d{2})/gi)
  },
  "owasp-top10-2025": {
    sourceUrl: "https://owasp.org/www-project-top-ten/",
    latestUrl: (version) => `https://owasp.org/Top10/${version}/`,
    detect: (text) =>
      firstMatch(text, /most current released version is[^<]+<a[^>]+>OWASP Top Ten\s+(20\d{2})/i)
      ?? firstMatch(text, /OWASP Top 10:(20\d{2})/i)
      ?? maxMatch(text, /OWASP Top 10[: -]+(20\d{2})/gi)
  },
  "owasp-rest-cheat-sheet": {
    sourceUrl: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    compare: false,
    detect: (text) => text.includes("REST Security Cheat Sheet") ? "current" : undefined
  },
  "nist-ssdf-1.1": {
    sourceUrl: "https://csrc.nist.gov/pubs/sp/800/218/final",
    latestUrl: () => "https://csrc.nist.gov/pubs/sp/800/218/final",
    detect: (text) => firstMatch(text, /Version\s+([0-9.]+): Recommendations for Mitigating the Risk/i)
  },
  "mitre-cwe-top25-2025": {
    sourceUrl: "https://cwe.mitre.org/top25/index.html",
    latestUrl: () => "https://cwe.mitre.org/top25/index.html",
    detect: (text) => firstMatch(text, /Welcome to the\s+(20\d{2})\s+Common Weakness Enumeration/i)
  },
  "openssf-slsa-1.2": {
    sourceUrl: "https://slsa.dev/spec/latest/",
    latestUrl: () => "https://slsa.dev/spec/latest/",
    detect: (text) => firstMatch(text, /Version\s+([0-9]+(?:\.[0-9]+)+)/i)
  },
  "openssf-scorecard": {
    sourceUrl: "https://raw.githubusercontent.com/ossf/scorecard/main/README.md",
    latestUrl: () => "https://scorecard.dev/",
    compare: false,
    detect: (text) => text.includes("OpenSSF Scorecard") || text.includes("Scorecard assesses") ? "current" : undefined
  },
  "oauth-rfc9700": {
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9700",
    latestUrl: () => "https://www.rfc-editor.org/rfc/rfc9700",
    detect: (text) => firstMatch(text, /RFC\s*(9700)/i)
  },
  "mcp-security-best-practices": {
    sourceUrl: "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices",
    compare: false,
    detect: (text) => text.includes("Security Best Practices") ? "current" : undefined
  },
  "mcp-authorization-spec": {
    sourceUrl: "https://modelcontextprotocol.io/specification",
    compare: false,
    detect: (text) => firstMatch(text, /current protocol version is\s+([0-9-]+)/i) ?? "current"
  }
};

const args = parseArgs(process.argv.slice(2));
const format = (args.format ?? "markdown") as OutputFormat;
const failOn = (args["fail-on"] ?? "updates") as FailMode;

const report = await buildReport();

if (format === "json") {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  process.stdout.write(formatMarkdown(report));
}

if (shouldFail(report, failOn)) {
  process.exitCode = 1;
}

async function buildReport(): Promise<Report> {
  const results = await Promise.all(STANDARDS_CATALOG.map(checkStandard));
  const summary = {
    total: results.length,
    okCount: results.filter((result) => result.status === "ok").length,
    updateCount: results.filter((result) => result.status === "update_available").length,
    trackingCount: results.filter((result) => result.status === "tracking").length,
    errorCount: results.filter((result) => result.status === "error").length
  };

  return {
    checkedAt: new Date().toISOString(),
    summary,
    results
  };
}

async function checkStandard(standard: StandardSource): Promise<VersionCheckResult> {
  const resolver = CHECKS[standard.id];
  if (!resolver) {
    return {
      standardId: standard.id,
      name: standard.name,
      authority: standard.authority,
      currentVersion: standard.version,
      sourceUrl: standard.url,
      status: "tracking",
      notes: "No automated version resolver configured; catalog source is tracked for manual review."
    };
  }

  try {
    const text = await fetchText(resolver.sourceUrl);
    const latestVersion = resolver.detect(text);
    if (!latestVersion) {
      return {
        standardId: standard.id,
        name: standard.name,
        authority: standard.authority,
        currentVersion: standard.version,
        sourceUrl: resolver.sourceUrl,
        status: "error",
        notes: "Could not detect a version marker in the upstream source."
      };
    }

    const compare = resolver.compare ?? isComparableVersion(standard.version);
    const latestUrl = resolver.latestUrl?.(latestVersion) ?? standard.url;
    const status = compare && normalizeVersion(standard.version) !== normalizeVersion(latestVersion)
      ? "update_available"
      : compare ? "ok" : "tracking";

    return {
      standardId: standard.id,
      name: standard.name,
      authority: standard.authority,
      currentVersion: standard.version,
      latestVersion,
      latestUrl,
      sourceUrl: resolver.sourceUrl,
      status,
      notes: status === "tracking" ? "Unversioned or rolling source; reachability and marker were verified." : undefined
    };
  } catch (error) {
    return {
      standardId: standard.id,
      name: standard.name,
      authority: standard.authority,
      currentVersion: standard.version,
      sourceUrl: resolver.sourceUrl,
      status: "error",
      notes: error instanceof Error ? error.message : String(error)
    };
  }
}

async function fetchText(url: string): Promise<string> {
  const timeoutMs = Number.parseInt(process.env.STANDARDS_CHECK_TIMEOUT_MS ?? "15000", 10);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { signal: controller.signal, headers: {
        "User-Agent": "mcp-compliance-scan-standards-check/0.1"
      } });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    return await response.text();
  } finally {
    clearTimeout(timeout);
  }
}

function firstMatch(text: string, pattern: RegExp): string | undefined {
  return text.match(pattern)?.[1];
}

function maxMatch(text: string, pattern: RegExp): string | undefined {
  const matches = [...text.matchAll(pattern)]
    .map((match) => match[1])
    .filter((value): value is string => Boolean(value))
    .map((value) => Number.parseInt(value, 10))
    .filter(Number.isFinite);

  return matches.length > 0 ? String(Math.max(...matches)) : undefined;
}

function normalizeVersion(version: string): string {
  const rfc = version.match(/RFC\s*(\d+)/i)?.[1];
  if (rfc) {
    return rfc;
  }

  const year = version.match(/\b(20\d{2})\b/)?.[1];
  if (year) {
    return year;
  }

  const semver = version.match(/v?(\d+(?:\.\d+)+)/i)?.[1];
  if (semver) {
    return semver;
  }

  return version.trim().toLowerCase();
}

function isComparableVersion(version: string): boolean {
  return !["current", "draft/current"].includes(version.trim().toLowerCase());
}

function parseArgs(rawArgs: string[]): Record<string, string | undefined> {
  const parsed: Record<string, string | undefined> = {};

  for (const arg of rawArgs) {
    if (!arg.startsWith("--")) {
      continue;
    }

    const [key, value] = arg.slice(2).split("=", 2);
    if (!key) {
      continue;
    }
    parsed[key] = value ?? "true";
  }

  return parsed;
}

function shouldFail(report: Report, failOn: FailMode): boolean {
  if (failOn === "never") {
    return false;
  }

  if (failOn === "errors") {
    return report.summary.errorCount > 0;
  }

  return report.summary.errorCount > 0 || report.summary.updateCount > 0;
}

function formatMarkdown(report: Report): string {
  const lines = [
    "# Standards Version Check",
    "",
    `Checked: ${report.checkedAt}`,
    `Summary: ${report.summary.okCount} ok, ${report.summary.updateCount} update(s), ${report.summary.trackingCount} tracking, ${report.summary.errorCount} error(s)`,
    "",
    "| Status | Standard | Catalog | Upstream | Source |",
    "| --- | --- | --- | --- | --- |"
  ];

  for (const result of report.results) {
    const source = result.latestUrl ?? result.sourceUrl;
    lines.push(`| ${result.status} | ${escapeTable(`${result.authority} ${result.name}`)} | ${escapeTable(result.currentVersion)} | ${escapeTable(result.latestVersion ?? "unknown")} | ${source} |`);
  }

  const notes = report.results.filter((result) => result.notes);
  if (notes.length > 0) {
    lines.push("", "## Notes");
    for (const result of notes) {
      lines.push(`- ${result.standardId}: ${result.notes}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

function escapeTable(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

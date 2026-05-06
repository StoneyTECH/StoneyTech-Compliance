#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  formatAuditHistoryMarkdown,
  formatAuditTrendsMarkdown,
  getAuditRun,
  initAuditDatabase,
  listAuditRuns,
  persistAuditRun,
  summarizeAuditTrends
} from "./audit.js";
import { getRepositoryDiff } from "./git.js";
import {
  auditMergeEvent,
  auditUnprocessedMerges,
  formatMergeHistoryMarkdown,
  formatRepositoryListMarkdown,
  getMergeAudit,
  listRegisteredRepositories,
  mergeAuditHistory,
  syncGithubRepositories,
  syncRepositoryMerges
} from "./merge.js";
import { POLICY_TEXT, POLICY_URI, buildChecklist } from "./policy.js";
import { formatPriorityPlanMarkdown, prioritizeFindings } from "./priority.js";
import {
  formatComplianceReportMarkdown,
  generateComplianceReport
} from "./report.js";
import { formatReviewMarkdown, reviewDiff } from "./review.js";
import {
  assertMcpPathAllowed,
  assertSafeGitRef,
  formatSecurityPolicyMarkdown,
  securityPolicyPayload
} from "./security.js";
import {
  STANDARDS_CATALOG,
  STANDARDS_CATALOG_URI,
  formatStandardsCatalogMarkdown
} from "./standards.js";

const ReviewProfileSchema = z.enum(["standard", "strict", "security"]).default("standard");
const OutputFormatSchema = z.enum(["markdown", "json"]).default("markdown");
const ComplianceReportScopeSchema = z.enum(["portfolio", "repository", "audit_run", "merge_window"]).default("portfolio");
const RepositoryReviewInputSchema = {
  repoPath: z.string().min(1).describe("Path to the repository to review."),
  mode: z.enum(["working-tree", "staged", "range"]).default("working-tree"),
  baseRef: z.string().optional().describe("Base git ref. For range mode, defaults to main."),
  targetRef: z.string().optional().describe("Target git ref. For range mode, defaults to HEAD."),
  includeUntracked: z.boolean().default(true),
  maxBytes: z.number().int().min(10_000).max(5_000_000).default(512_000),
  profile: ReviewProfileSchema,
  maxFindings: z.number().int().min(1).max(200).default(50),
  language: z.string().optional(),
  framework: z.string().optional(),
  riskAreas: z.array(z.string()).optional()
};

const server = new McpServer({
  name: "mcp-compliance-scan",
  version: "0.1.0"
});

server.registerResource(
  "code-review-policy",
  POLICY_URI,
  {
    title: "Code Review Policy",
    description: "Review gates and severity definitions for compliance reviews.",
    mimeType: "text/markdown"
  },
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        mimeType: "text/markdown",
        text: POLICY_TEXT
      }
    ]
  })
);

server.registerResource(
  "standards-catalog",
  STANDARDS_CATALOG_URI,
  {
    title: "Standards Catalog",
    description: "Authoritative standards and frameworks used by compliance reviews.",
    mimeType: "text/markdown"
  },
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        mimeType: "text/markdown",
        text: formatStandardsCatalogMarkdown()
      }
    ]
  })
);

server.registerTool(
  "mcp_security_policy",
  {
    title: "MCP Security Policy",
    description: "Show local MCP path-root restrictions, tool effect labels, and injection guardrails.",
    inputSchema: {
      outputFormat: OutputFormatSchema
    }
  },
  async ({ outputFormat }) => {
    const payload = securityPolicyPayload();
    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(payload, null, 2) : formatSecurityPolicyMarkdown()
        }
      ]
    };
  }
);

server.registerTool(
  "standards_catalog",
  {
    title: "Standards Catalog",
    description: "List the standards and frameworks used by compliance reviews.",
    inputSchema: {
      domain: z.enum(["mcp", "api", "cli", "web", "oauth", "supply-chain", "secure-sdlc", "weakness"]).optional(),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ domain, outputFormat }) => {
    const standards = domain
      ? STANDARDS_CATALOG.filter((standard) => standard.domains.includes(domain))
      : STANDARDS_CATALOG;
    const payload = {
      domain,
      standards
    };
    const markdown = domain
      ? formatStandardsCatalogMarkdownFor(standards, `# Compliance Standards Catalog: ${domain}`)
      : formatStandardsCatalogMarkdown();

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(payload, null, 2) : markdown
        }
      ]
    };
  }
);

server.registerTool(
  "review_diff",
  {
    title: "Review Diff",
    description: "Run compliance checks against supplied unified diff text.",
    inputSchema: {
      diff: z.string().min(1).describe("Unified diff text to review."),
      profile: ReviewProfileSchema.describe("Review profile to apply."),
      outputFormat: OutputFormatSchema.describe("Return markdown for humans or JSON for automation."),
      maxFindings: z.number().int().min(1).max(200).default(50),
      language: z.string().optional(),
      framework: z.string().optional(),
      riskAreas: z.array(z.string()).optional()
    }
  },
  async ({ diff, profile, outputFormat, maxFindings, language, framework, riskAreas }) => {
    const report = reviewDiff(diff, {
      profile,
      maxFindings,
      language,
      framework,
      riskAreas
    });
    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(report, null, 2) : formatReviewMarkdown(report)
        }
      ]
    };
  }
);

server.registerTool(
  "review_repository",
  {
    title: "Review Repository",
    description: "Run compliance checks against local git changes.",
    inputSchema: {
      ...RepositoryReviewInputSchema,
      outputFormat: OutputFormatSchema,
    }
  },
  async ({
    repoPath,
    mode,
    baseRef,
    targetRef,
    includeUntracked,
    maxBytes,
    profile,
    outputFormat,
    maxFindings,
    language,
    framework,
    riskAreas
  }) => {
    validateOptionalGitRefs([baseRef, "baseRef"], [targetRef, "targetRef"]);
    const repoDiff = await getRepositoryDiff({
      repoPath: requiredMcpPath(repoPath, "repoPath"),
      mode,
      baseRef,
      targetRef,
      includeUntracked,
      maxBytes
    });
    const report = reviewDiff(repoDiff.diffText, {
      profile,
      maxFindings,
      language,
      framework,
      riskAreas,
      truncated: repoDiff.truncated
    });
    const payload = {
      repository: {
        root: repoDiff.repoRoot,
        mode: repoDiff.mode,
        command: repoDiff.command,
        diffBytes: Buffer.byteLength(repoDiff.diffText, "utf8"),
        truncated: repoDiff.truncated
      },
      review: report
    };

    const markdown = [
      `Repository: ${repoDiff.repoRoot}`,
      `Mode: ${repoDiff.mode}`,
      `Command: ${repoDiff.command}`,
      ``,
      formatReviewMarkdown(report)
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(payload, null, 2) : markdown
        }
      ]
    };
  }
);

server.registerTool(
  "init_audit_db",
  {
    title: "Initialize Audit Database",
    description: "Initialize the local SQLite audit ledger and seed the current standards/control catalog.",
    inputSchema: {
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ dbPath, outputFormat }) => {
    const result = initAuditDatabase({ dbPath: optionalMcpPath(dbPath, "dbPath") });
    const markdown = [
      "# Audit Database",
      "",
      `Database: ${result.dbPath}`,
      `Schema: ${result.schemaPath}`,
      `Initialized: ${result.initialized}`
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "review_repository_and_persist",
  {
    title: "Review Repository And Persist",
    description: "Run compliance checks against local git changes and persist the audit run to SQLite.",
    inputSchema: {
      ...RepositoryReviewInputSchema,
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({
    repoPath,
    mode,
    baseRef,
    targetRef,
    includeUntracked,
    maxBytes,
    profile,
    outputFormat,
    maxFindings,
    language,
    framework,
    riskAreas,
    dbPath
  }) => {
    validateOptionalGitRefs([baseRef, "baseRef"], [targetRef, "targetRef"]);
    const repoDiff = await getRepositoryDiff({
      repoPath: requiredMcpPath(repoPath, "repoPath"),
      mode,
      baseRef,
      targetRef,
      includeUntracked,
      maxBytes
    });
    const reviewRequest = {
      repoPath,
      mode,
      baseRef,
      targetRef,
      includeUntracked,
      maxBytes,
      profile,
      maxFindings,
      language,
      framework,
      riskAreas
    };
    const report = reviewDiff(repoDiff.diffText, {
      profile,
      maxFindings,
      language,
      framework,
      riskAreas,
      truncated: repoDiff.truncated
    });
    const persisted = persistAuditRun({
      dbPath: optionalMcpPath(dbPath, "dbPath"),
      repoDiff,
      report,
      reviewRequest
    });
    const payload = {
      audit: persisted,
      repository: {
        root: repoDiff.repoRoot,
        mode: repoDiff.mode,
        command: repoDiff.command,
        diffBytes: Buffer.byteLength(repoDiff.diffText, "utf8"),
        truncated: repoDiff.truncated
      },
      review: report
    };
    const markdown = [
      `Audit run: ${persisted.auditRunId}`,
      `Database: ${persisted.dbPath}`,
      `Repository: ${repoDiff.repoRoot}`,
      `Mode: ${repoDiff.mode}`,
      `Command: ${repoDiff.command}`,
      ``,
      formatReviewMarkdown(report)
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(payload, null, 2) : markdown
        }
      ]
    };
  }
);

server.registerTool(
  "audit_history",
  {
    title: "Audit History",
    description: "List recent persisted local SQLite audit runs.",
    inputSchema: {
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      limit: z.number().int().min(1).max(200).default(20),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ dbPath, limit, outputFormat }) => {
    const result = listAuditRuns({ dbPath: optionalMcpPath(dbPath, "dbPath"), limit });
    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : formatAuditHistoryMarkdown(result)
        }
      ]
    };
  }
);

server.registerTool(
  "get_audit_run",
  {
    title: "Get Audit Run",
    description: "Fetch one persisted audit run with findings and mapped standards controls.",
    inputSchema: {
      auditRunId: z.string().min(1),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ auditRunId, dbPath, outputFormat }) => {
    const result = getAuditRun({ auditRunId, dbPath: optionalMcpPath(dbPath, "dbPath") });
    const markdown = result.auditRun
      ? [
          "# Audit Run",
          "",
          `Audit run: ${result.auditRun.id}`,
          `Database: ${result.dbPath}`,
          `Repository: ${result.auditRun.repositoryName ?? "unknown"}`,
          `Status: ${result.auditRun.status}`,
          `Findings: ${result.auditRun.findingCount}`,
          "",
          ...result.auditRun.findings.map((finding) => [
            `## [${finding.severity}] ${finding.title}`,
            "",
            `- Rule: ${finding.ruleId}`,
            `- Location: ${finding.file ?? "repository"}${finding.line ? `:${finding.line}` : ""}`,
            `- Standards: ${finding.controls.map((control) => `${control.standardId}:${control.control}`).join(", ")}`,
            `- Remediation: ${finding.remediation}`
          ].join("\n"))
        ].join("\n")
      : `Audit run not found: ${auditRunId}\n`;

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "audit_trends",
  {
    title: "Audit Trends",
    description: "Summarize persisted local audit runs by day and rule.",
    inputSchema: {
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      days: z.number().int().min(1).max(365).default(30),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ dbPath, days, outputFormat }) => {
    const trends = summarizeAuditTrends({ dbPath: optionalMcpPath(dbPath, "dbPath"), days });
    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(trends, null, 2) : formatAuditTrendsMarkdown(trends)
        }
      ]
    };
  }
);

server.registerTool(
  "prioritize_audit_run",
  {
    title: "Prioritize Audit Run",
    description: "Order persisted audit findings by deterministic critical/high/medium/low priority and standards-backed impact.",
    inputSchema: {
      auditRunId: z.string().min(1),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ auditRunId, dbPath, outputFormat }) => {
    const payload = priorityPayloadForAuditRun(auditRunId, optionalMcpPath(dbPath, "dbPath"));
    const markdown = payload.priorityPlan
      ? [
          `Audit run: ${auditRunId}`,
          `Database: ${payload.dbPath}`,
          `Repository: ${payload.auditRun?.repositoryName ?? "unknown"}`,
          "",
          formatPriorityPlanMarkdown(payload.priorityPlan, "Audit Priority Plan")
        ].join("\n")
      : `Audit run not found: ${auditRunId}\n`;

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(payload, null, 2) : markdown
        }
      ]
    };
  }
);

server.registerTool(
  "remediation_plan",
  {
    title: "Remediation Plan",
    description: "Return the dependency-aware remediation order for a persisted audit run.",
    inputSchema: {
      auditRunId: z.string().min(1),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ auditRunId, dbPath, outputFormat }) => {
    const payload = priorityPayloadForAuditRun(auditRunId, optionalMcpPath(dbPath, "dbPath"));
    const plan = payload.priorityPlan
      ? {
          dbPath: payload.dbPath,
          auditRunId,
          repository: payload.auditRun?.repositoryName,
          remediationSteps: payload.priorityPlan.remediationSteps,
          counts: payload.priorityPlan.counts
        }
      : {
          dbPath: payload.dbPath,
          auditRunId,
          remediationSteps: []
        };
    const markdown = payload.priorityPlan
      ? [
          "# Remediation Plan",
          "",
          `Audit run: ${auditRunId}`,
          `Repository: ${payload.auditRun?.repositoryName ?? "unknown"}`,
          "",
          "| Rank | Priority | Score | Finding | Unlocks |",
          "| ---: | --- | ---: | --- | --- |",
          ...payload.priorityPlan.remediationSteps.map((step) => `| ${step.rank} | ${step.priorityBand} | ${step.score} | ${step.title} | ${step.unlocks.length} |`)
        ].join("\n")
      : `Audit run not found: ${auditRunId}\n`;

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(plan, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "repository_impact_graph",
  {
    title: "Repository Impact Graph",
    description: "Return graph nodes and edges linking audit findings to components, standards controls, and dependent findings.",
    inputSchema: {
      auditRunId: z.string().min(1),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ auditRunId, dbPath, outputFormat }) => {
    const payload = priorityPayloadForAuditRun(auditRunId, optionalMcpPath(dbPath, "dbPath"));
    const graphPayload = payload.priorityPlan
      ? {
          dbPath: payload.dbPath,
          auditRunId,
          repository: payload.auditRun?.repositoryName,
          graph: payload.priorityPlan.graph
        }
      : {
          dbPath: payload.dbPath,
          auditRunId
        };
    const markdown = payload.priorityPlan
      ? [
          "# Repository Impact Graph",
          "",
          `Audit run: ${auditRunId}`,
          `Nodes: ${payload.priorityPlan.graph.nodes.length}`,
          `Edges: ${payload.priorityPlan.graph.edges.length}`,
          "",
          "| Edge | From | To | Rationale |",
          "| --- | --- | --- | --- |",
          ...payload.priorityPlan.graph.edges
            .filter((edge) => edge.type === "BLOCKS" || edge.type === "AMPLIFIES" || edge.type === "SHARES_ROOT_CAUSE_WITH")
            .slice(0, 50)
            .map((edge) => `| ${edge.type} | ${edge.from} | ${edge.to} | ${edge.rationale} |`)
        ].join("\n")
      : `Audit run not found: ${auditRunId}\n`;

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(graphPayload, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "sync_github_repositories",
  {
    title: "Sync GitHub Repositories",
    description: "Inventory GitHub repositories into the local SQLite registry without storing credentials.",
    inputSchema: {
      owner: z.string().optional().describe("Optional GitHub user or organization login. Omit to sync repositories visible to the token."),
      ownerType: z.enum(["user", "org"]).default("user"),
      includeArchived: z.boolean().default(false),
      limit: z.number().int().min(1).max(1000).default(500),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ owner, ownerType, includeArchived, limit, dbPath, outputFormat }) => {
    const result = await syncGithubRepositories({ owner, ownerType, includeArchived, limit, dbPath: optionalMcpPath(dbPath, "dbPath") });
    const markdown = [
      "# GitHub Repository Sync",
      "",
      `Database: ${result.dbPath}`,
      `Synced: ${result.syncedAt}`,
      `Repositories: ${result.repositoryCount}`,
      "",
      ...result.repositories.slice(0, 50).map((repo) => `- ${repo.name} (${repo.riskTier}, ${repo.scanProfile}, track merges: ${repo.trackMerges ? "yes" : "no"})`)
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "list_registered_repositories",
  {
    title: "List Registered Repositories",
    description: "List repositories registered in the local compliance database with merge tracking policy.",
    inputSchema: {
      includeInventoryOnly: z.boolean().default(false),
      limit: z.number().int().min(1).max(1000).default(500),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ includeInventoryOnly, limit, dbPath, outputFormat }) => {
    const result = listRegisteredRepositories({ includeInventoryOnly, limit, dbPath: optionalMcpPath(dbPath, "dbPath") });
    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : formatRepositoryListMarkdown(result)
        }
      ]
    };
  }
);

server.registerTool(
  "sync_repository_merges",
  {
    title: "Sync Repository Merges",
    description: "Poll GitHub for merged PRs and default-branch commits, then store merge events locally.",
    inputSchema: {
      repository: z.string().min(1).describe("Registered repository id or GitHub full name, for example owner/repo."),
      branch: z.string().optional(),
      since: z.string().optional().describe("ISO timestamp. Defaults to the repository cursor or the last 30 days."),
      days: z.number().int().min(1).max(3650).default(30),
      limit: z.number().int().min(1).max(500).default(100),
      includeDefaultBranchCommits: z.boolean().default(true),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ repository, branch, since, days, limit, includeDefaultBranchCommits, dbPath, outputFormat }) => {
    validateOptionalGitRefs([branch, "branch"]);
    const result = await syncRepositoryMerges({
      repository,
      branch,
      since,
      days,
      limit,
      includeDefaultBranchCommits,
      dbPath: optionalMcpPath(dbPath, "dbPath")
    });
    const markdown = [
      "# Merge Sync",
      "",
      `Database: ${result.dbPath}`,
      `Repository: ${result.repository.name}`,
      `Branch: ${result.branch}`,
      `Since: ${result.since}`,
      `Merge events: ${result.mergeEventCount}`,
      "",
      ...result.mergeEvents.slice(0, 50).map((event) => `- ${event.id}: ${event.eventType} ${event.mergeCommitSha.slice(0, 12)} ${event.title ?? ""}`)
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "audit_merge",
  {
    title: "Audit Merge",
    description: "Audit the exact diff for one persisted merge event and link the audit run to that merge.",
    inputSchema: {
      mergeEventId: z.string().min(1),
      repoPath: z.string().optional().describe("Optional local checkout path. If omitted, the server uses or creates .local/repos."),
      checkoutRoot: z.string().optional(),
      maxBytes: z.number().int().min(10_000).max(5_000_000).default(512_000),
      profile: ReviewProfileSchema,
      maxFindings: z.number().int().min(1).max(200).default(50),
      language: z.string().optional(),
      framework: z.string().optional(),
      riskAreas: z.array(z.string()).optional(),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ mergeEventId, repoPath, checkoutRoot, maxBytes, profile, maxFindings, language, framework, riskAreas, dbPath, outputFormat }) => {
    const result = await auditMergeEvent({
      mergeEventId,
      repoPath: optionalMcpPath(repoPath, "repoPath"),
      checkoutRoot: optionalMcpPath(checkoutRoot, "checkoutRoot"),
      maxBytes,
      profile,
      maxFindings,
      language,
      framework,
      riskAreas,
      dbPath: optionalMcpPath(dbPath, "dbPath")
    });
    const markdown = [
      "# Merge Audit",
      "",
      `Merge event: ${result.mergeEvent.id}`,
      `Audit run: ${result.auditRunId}`,
      `Repository path: ${result.repositoryPath}`,
      `Findings: ${result.findingCount}`,
      "",
      result.reviewMarkdown
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : markdown
        }
      ]
    };
  }
);

server.registerTool(
  "audit_unprocessed_merges",
  {
    title: "Audit Unprocessed Merges",
    description: "Audit pending merge events in chronological order.",
    inputSchema: {
      repository: z.string().optional().describe("Optional registered repository id or GitHub full name."),
      checkoutRoot: z.string().optional(),
      limit: z.number().int().min(1).max(100).default(20),
      maxBytes: z.number().int().min(10_000).max(5_000_000).default(512_000),
      profile: ReviewProfileSchema,
      maxFindings: z.number().int().min(1).max(200).default(50),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ repository, checkoutRoot, limit, maxBytes, profile, maxFindings, dbPath, outputFormat }) => {
    const result = await auditUnprocessedMerges({
      repository,
      checkoutRoot: optionalMcpPath(checkoutRoot, "checkoutRoot"),
      limit,
      maxBytes,
      profile,
      maxFindings,
      dbPath: optionalMcpPath(dbPath, "dbPath")
    });
    const markdown = [
      "# Pending Merge Audits",
      "",
      `Database: ${result.dbPath}`,
      `Processed: ${result.processed.length}`,
      `Errors: ${result.errors.length}`,
      "",
      ...result.processed.map((item) => `- ${item.mergeEvent.id}: ${item.auditRunId} (${item.findingCount} finding(s))`),
      ...result.errors.map((item) => `- ERROR ${item.mergeEventId}: ${item.error}`)
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "merge_audit_history",
  {
    title: "Merge Audit History",
    description: "List persisted merge events and their linked audit status.",
    inputSchema: {
      repository: z.string().optional().describe("Optional registered repository id or GitHub full name."),
      limit: z.number().int().min(1).max(500).default(50),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ repository, limit, dbPath, outputFormat }) => {
    const result = mergeAuditHistory({ repository, limit, dbPath: optionalMcpPath(dbPath, "dbPath") });
    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : formatMergeHistoryMarkdown(result)
        }
      ]
    };
  }
);

server.registerTool(
  "get_merge_audit",
  {
    title: "Get Merge Audit",
    description: "Fetch one persisted merge event and linked audit run id.",
    inputSchema: {
      mergeEventId: z.string().min(1),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ mergeEventId, dbPath, outputFormat }) => {
    const result = getMergeAudit({ mergeEventId, dbPath: optionalMcpPath(dbPath, "dbPath") });
    const markdown = result.mergeEvent
      ? [
          "# Merge Audit",
          "",
          `Merge event: ${result.mergeEvent.id}`,
          `Repository: ${result.mergeEvent.repositoryName}`,
          `Branch: ${result.mergeEvent.branch}`,
          `Commit: ${result.mergeEvent.mergeCommitSha}`,
          `Status: ${result.mergeEvent.status}`,
          `Audit run: ${result.mergeEvent.auditRunId ?? ""}`
        ].join("\n")
      : `Merge event not found: ${mergeEventId}\n`;

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(result, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

server.registerTool(
  "compliance_report",
  {
    title: "Compliance Report",
    description: "Generate a human-facing local compliance report from the SQLite audit ledger.",
    inputSchema: {
      scope: ComplianceReportScopeSchema.describe("portfolio, repository, audit_run, or merge_window."),
      repository: z.string().optional().describe("Repository id or full GitHub name. Required for repository scope and optional for merge_window."),
      auditRunId: z.string().optional().describe("Audit run id. Required for audit_run scope."),
      days: z.number().int().min(1).max(3650).default(30).describe("Window size for merge_window and recent-change sections."),
      limit: z.number().int().min(1).max(500).default(20).describe("Maximum rows in queue-style report sections."),
      dbPath: z.string().optional().describe("Optional SQLite database path. Defaults to .local/audit/compliance.db."),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ scope, repository, auditRunId, days, limit, dbPath, outputFormat }) => {
    const report = generateComplianceReport({
      scope,
      repository,
      auditRunId,
      days,
      limit,
      dbPath: optionalMcpPath(dbPath, "dbPath")
    });

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(report, null, 2) : formatComplianceReportMarkdown(report)
        }
      ]
    };
  }
);

server.registerTool(
  "compliance_checklist",
  {
    title: "Compliance Checklist",
    description: "Return the code-review checklist for a profile, language, framework, or risk area.",
    inputSchema: {
      profile: ReviewProfileSchema,
      language: z.string().optional(),
      framework: z.string().optional(),
      riskAreas: z.array(z.string()).optional(),
      outputFormat: OutputFormatSchema
    }
  },
  async ({ profile, language, framework, riskAreas, outputFormat }) => {
    const checklist = buildChecklist({ profile, language, framework, riskAreas });
    const payload = {
      profile,
      language,
      framework,
      riskAreas: riskAreas ?? [],
      checklist
    };
    const markdown = [
      "# Compliance Checklist",
      "",
      `Profile: ${profile}`,
      language ? `Language: ${language}` : undefined,
      framework ? `Framework: ${framework}` : undefined,
      "",
      ...checklist.map((item) => {
        const standards = item.standards.map((standard) => `${standard.standardId}:${standard.control}`).join(", ");
        return `- [${item.required ? "required" : "recommended"}] ${item.category}/${item.id}: ${item.prompt} [${standards}]`;
      })
    ].filter(Boolean).join("\n");

    return {
      content: [
        {
          type: "text",
          text: outputFormat === "json" ? JSON.stringify(payload, null, 2) : `${markdown}\n`
        }
      ]
    };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);

function formatStandardsCatalogMarkdownFor(standards: typeof STANDARDS_CATALOG, title: string): string {
  const lines = [title, ""];

  for (const standard of standards) {
    lines.push(
      `## ${standard.authority}: ${standard.name}`,
      "",
      `- ID: ${standard.id}`,
      `- Version: ${standard.version}`,
      `- Domains: ${standard.domains.join(", ")}`,
      `- Source: ${standard.url}`,
      `- Use: ${standard.summary}`,
      ""
    );
  }

  return lines.join("\n");
}

function priorityPayloadForAuditRun(auditRunId: string, dbPath?: string): ReturnType<typeof getAuditRun> & { priorityPlan?: ReturnType<typeof prioritizeFindings> } {
  const result = getAuditRun({ auditRunId, dbPath });
  if (!result.auditRun) {
    return result;
  }

  return {
    ...result,
    priorityPlan: prioritizeFindings(result.auditRun.findings)
  };
}

function requiredMcpPath(input: string, label: string): string {
  return assertMcpPathAllowed(input, label) ?? input;
}

function optionalMcpPath(input: string | undefined, label: string): string | undefined {
  return assertMcpPathAllowed(input, label);
}

function validateOptionalGitRefs(...refs: Array<[string | undefined, string]>): void {
  for (const [ref, label] of refs) {
    assertSafeGitRef(ref, label);
  }
}

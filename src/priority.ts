import { createHash } from "node:crypto";
import path from "node:path";
import { ReviewFinding, Severity } from "./review.js";
import { StandardReference } from "./standards.js";

export type PriorityBand = "critical" | "high" | "medium" | "low" | "info";
export type RemediationTier = "fix-now" | "fix-next" | "plan" | "backlog" | "track";
export type ImpactEdgeType =
  | "AFFECTS_COMPONENT"
  | "VIOLATES_CONTROL"
  | "BLOCKS"
  | "AMPLIFIES"
  | "SHARES_ROOT_CAUSE_WITH";

export interface PriorityFactor {
  key: string;
  label: string;
  value: number;
  reason: string;
}

export interface FindingPriority {
  rank: number;
  band: PriorityBand;
  remediationTier: RemediationTier;
  score: number;
  severityBand: PriorityBand;
  factors: PriorityFactor[];
}

export interface PrioritizableFinding extends ReviewFinding {
  id?: string;
  status?: string;
  fingerprint?: string;
  controls?: StandardReference[];
}

export interface PrioritizedFinding extends PrioritizableFinding {
  key: string;
  component: string;
  priority: FindingPriority;
}

export interface ImpactGraphNode {
  id: string;
  kind: "finding" | "component" | "standard_control";
  label: string;
  metadata: Record<string, unknown>;
}

export interface ImpactGraphEdge {
  id: string;
  from: string;
  to: string;
  type: ImpactEdgeType;
  weight: number;
  rationale: string;
  metadata: Record<string, unknown>;
}

export interface RemediationStep {
  rank: number;
  findingKey: string;
  title: string;
  ruleId: string;
  priorityBand: PriorityBand;
  score: number;
  severity: Severity;
  component: string;
  location: string;
  standards: string[];
  dependsOn: string[];
  unlocks: string[];
  why: string;
  remediation: string;
}

export interface PriorityPlan {
  generatedAt: string;
  findingCount: number;
  counts: Record<PriorityBand, number>;
  orderedFindings: PrioritizedFinding[];
  remediationSteps: RemediationStep[];
  graph: {
    nodes: ImpactGraphNode[];
    edges: ImpactGraphEdge[];
  };
}

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  blocker: 100,
  high: 70,
  medium: 40,
  low: 15
};

const EDGE_WEIGHTS: Record<ImpactEdgeType, number> = {
  AFFECTS_COMPONENT: 1,
  VIOLATES_CONTROL: 1,
  BLOCKS: 10,
  AMPLIFIES: 7,
  SHARES_ROOT_CAUSE_WITH: 3
};

export function prioritizeFindings(findings: PrioritizableFinding[]): PriorityPlan {
  const assessed = findings.map((finding) => {
    const key = findingKey(finding);
    const component = componentForFinding(finding);
    const priority = assessFindingPriority(finding, 0);
    return {
      ...finding,
      key,
      component,
      priority
    };
  });
  const graph = buildImpactGraph(assessed);
  const dependencyImpact = dependencyImpactByFinding(graph.edges);
  const orderedFindings = assessed
    .map((finding) => ({
      ...finding,
      priority: assessFindingPriority(finding, dependencyImpact.get(finding.key) ?? 0)
    }))
    .sort(comparePrioritizedFindings)
    .map((finding, index) => ({
      ...finding,
      priority: {
        ...finding.priority,
        rank: index + 1
      }
    }));

  const counts = orderedFindings.reduce<Record<PriorityBand, number>>(
    (acc, finding) => {
      acc[finding.priority.band] += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    generatedAt: new Date().toISOString(),
    findingCount: findings.length,
    counts,
    orderedFindings,
    remediationSteps: orderedFindings.map((finding) => remediationStepFor(finding, graph.edges)),
    graph: {
      nodes: graph.nodes,
      edges: graph.edges
    }
  };
}

export function formatPriorityPlanMarkdown(plan: PriorityPlan, title = "Priority Plan"): string {
  const lines = [
    `# ${title}`,
    "",
    `Findings: ${plan.findingCount}`,
    `Priority mix: critical ${plan.counts.critical}, high ${plan.counts.high}, medium ${plan.counts.medium}, low ${plan.counts.low}, info ${plan.counts.info}`,
    "",
    "## Priority Order",
    "",
    "| Rank | Priority | Score | Rule | Component | Location | Standards |",
    "| ---: | --- | ---: | --- | --- | --- | --- |"
  ];

  for (const step of plan.remediationSteps) {
    lines.push(`| ${step.rank} | ${step.priorityBand} | ${step.score} | ${step.ruleId} | ${step.component} | ${step.location} | ${step.standards.join("<br>")} |`);
  }

  lines.push("", "## Remediation Steps");
  for (const step of plan.remediationSteps) {
    lines.push(
      "",
      `### ${step.rank}. [${step.priorityBand}] ${step.title}`,
      "",
      `- Score: ${step.score}`,
      `- Component: ${step.component}`,
      `- Location: ${step.location}`,
      `- Why: ${step.why}`,
      `- Standards: ${step.standards.join(", ") || "none"}`,
      `- Unlocks: ${step.unlocks.join(", ") || "none"}`,
      `- Depends on: ${step.dependsOn.join(", ") || "none"}`,
      `- Remediation: ${step.remediation}`
    );
  }

  const impactEdges = plan.graph.edges.filter((edge) => edge.type === "BLOCKS" || edge.type === "AMPLIFIES" || edge.type === "SHARES_ROOT_CAUSE_WITH");
  if (impactEdges.length > 0) {
    lines.push("", "## Impact Edges", "", "| From | Edge | To | Rationale |", "| --- | --- | --- | --- |");
    for (const edge of impactEdges.slice(0, 30)) {
      lines.push(`| ${labelForNode(plan.graph.nodes, edge.from)} | ${edge.type} | ${labelForNode(plan.graph.nodes, edge.to)} | ${edge.rationale} |`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export function findingKey(finding: PrioritizableFinding): string {
  return finding.id ?? `finding_${shortHash([
    finding.ruleId,
    finding.file ?? "repository",
    finding.line ?? "",
    finding.title,
    finding.fingerprint ?? finding.evidence
  ].join("|"))}`;
}

function assessFindingPriority(finding: PrioritizableFinding, dependencyImpact: number): FindingPriority {
  const factors = [
    factor("severity", "Severity", SEVERITY_WEIGHTS[finding.severity], `${finding.severity} deterministic severity`),
    exploitabilityFactor(finding),
    exposureFactor(finding),
    assetCriticalityFactor(finding),
    dataSensitivityFactor(finding),
    dependencyCentralityFactor(finding),
    blastRadiusFactor(finding),
    standardsWeightFactor(finding),
    factor("confidence", "Confidence", Math.round(finding.confidence * 10), `scanner confidence ${finding.confidence.toFixed(2)}`),
    factor("dependency_impact", "Dependency impact", dependencyImpact, dependencyImpact > 0 ? "finding unlocks or amplifies other findings" : "no dependent finding impact detected"),
    mitigationCreditFactor(finding)
  ];
  const score = Math.max(0, Math.round(factors.reduce((sum, item) => sum + item.value, 0)));
  const band = bandForScore(finding.severity, score);

  return {
    rank: 0,
    band,
    remediationTier: remediationTierForBand(band),
    score,
    severityBand: baseBandForSeverity(finding.severity),
    factors
  };
}

function buildImpactGraph(findings: PrioritizedFinding[]): PriorityPlan["graph"] {
  const nodes = new Map<string, ImpactGraphNode>();
  const edges = new Map<string, ImpactGraphEdge>();

  for (const finding of findings) {
    addNode(nodes, {
      id: finding.key,
      kind: "finding",
      label: finding.title,
      metadata: {
        ruleId: finding.ruleId,
        severity: finding.severity,
        component: finding.component,
        file: finding.file,
        line: finding.line
      }
    });

    const componentId = componentNodeId(finding.component);
    addNode(nodes, {
      id: componentId,
      kind: "component",
      label: finding.component,
      metadata: {}
    });
    addEdge(edges, finding.key, componentId, "AFFECTS_COMPONENT", "Finding affects this repository component", {
      component: finding.component
    });

    for (const standard of controlsForFinding(finding)) {
      const controlId = controlNodeId(standard);
      addNode(nodes, {
        id: controlId,
        kind: "standard_control",
        label: `${standard.standardId}:${standard.control}`,
        metadata: {
          standardId: standard.standardId,
          control: standard.control,
          title: standard.title,
          url: standard.url
        }
      });
      addEdge(edges, finding.key, controlId, "VIOLATES_CONTROL", "Finding maps to this standards control", {
        standardId: standard.standardId,
        control: standard.control
      });
    }
  }

  for (let index = 0; index < findings.length; index += 1) {
    for (let otherIndex = index + 1; otherIndex < findings.length; otherIndex += 1) {
      addPairEdges(edges, findings[index]!, findings[otherIndex]!);
    }
  }

  return {
    nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.id.localeCompare(b.id))
  };
}

function addPairEdges(edges: Map<string, ImpactGraphEdge>, left: PrioritizedFinding, right: PrioritizedFinding): void {
  if (left.ruleId === right.ruleId) {
    addEdge(edges, left.key, right.key, "SHARES_ROOT_CAUSE_WITH", "Same deterministic rule fired more than once", {
      ruleId: left.ruleId
    });
    addEdge(edges, right.key, left.key, "SHARES_ROOT_CAUSE_WITH", "Same deterministic rule fired more than once", {
      ruleId: left.ruleId
    });
  }

  if (left.component === right.component && left.category === right.category && left.category !== "quality") {
    addAmplifierEdge(edges, left, right, "Same component and risk category increases combined blast radius");
  }

  addDirectedPolicyEdges(edges, left, right);
  addDirectedPolicyEdges(edges, right, left);
}

function addDirectedPolicyEdges(edges: Map<string, ImpactGraphEdge>, source: PrioritizedFinding, target: PrioritizedFinding): void {
  if (source.ruleId === "security.auth-bypass" && target.category !== "quality") {
    addEdge(edges, source.key, target.key, "AMPLIFIES", "Authorization boundary weakness amplifies nearby security, privacy, and resilience findings", {
      component: source.component
    });
  }

  if ((source.ruleId === "security.hardcoded-secret" || source.ruleId === "security.private-key") && target.ruleId === "privacy.sensitive-logging") {
    addEdge(edges, source.key, target.key, "BLOCKS", "Secret removal and rotation should happen before closing sensitive logging exposure", {});
  }

  if (source.ruleId === "supply-chain.unpinned-dependency" && target.ruleId === "supply-chain.lockfile-drift") {
    addEdge(edges, source.key, target.key, "BLOCKS", "Dependency policy should be corrected before regenerating lockfiles", {});
  }

  if (isExploitFoundation(source.ruleId) && target.ruleId === "quality.missing-tests") {
    addEdge(edges, source.key, target.key, "BLOCKS", "Fix the exploit path first, then prove the remediation with tests", {});
  }

  if (isExploitFoundation(source.ruleId) && source.component === target.component && target.priority.score < source.priority.score) {
    addEdge(edges, source.key, target.key, "AMPLIFIES", "Higher-impact exploit path in the same component raises remediation urgency", {
      component: source.component
    });
  }
}

function addAmplifierEdge(edges: Map<string, ImpactGraphEdge>, left: PrioritizedFinding, right: PrioritizedFinding, rationale: string): void {
  const [source, target] = comparePrioritizedFindings(left, right) <= 0 ? [left, right] : [right, left];
  if (source.priority.score > target.priority.score) {
    addEdge(edges, source.key, target.key, "AMPLIFIES", rationale, {
      component: source.component,
      category: source.category
    });
  }
}

function remediationStepFor(finding: PrioritizedFinding, edges: ImpactGraphEdge[]): RemediationStep {
  const outgoing = edges.filter((edge) => edge.from === finding.key && (edge.type === "BLOCKS" || edge.type === "AMPLIFIES"));
  const incoming = edges.filter((edge) => edge.to === finding.key && edge.type === "BLOCKS");
  const topFactors = finding.priority.factors
    .filter((factorItem) => factorItem.value > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, 4)
    .map((factorItem) => `${factorItem.label.toLowerCase()} ${factorItem.value}`);

  return {
    rank: finding.priority.rank,
    findingKey: finding.key,
    title: finding.title,
    ruleId: finding.ruleId,
    priorityBand: finding.priority.band,
    score: finding.priority.score,
    severity: finding.severity,
    component: finding.component,
    location: locationForFinding(finding),
    standards: controlsForFinding(finding).map((standard) => `${standard.standardId}:${standard.control}`),
    dependsOn: uniqueStrings(incoming.map((edge) => edge.from)),
    unlocks: uniqueStrings(outgoing.map((edge) => edge.to)),
    why: topFactors.length > 0 ? topFactors.join(", ") : "lowest deterministic impact factors",
    remediation: finding.remediation
  };
}

function dependencyImpactByFinding(edges: ImpactGraphEdge[]): Map<string, number> {
  const result = new Map<string, number>();
  for (const edge of edges) {
    if (edge.type === "AFFECTS_COMPONENT" || edge.type === "VIOLATES_CONTROL") {
      continue;
    }
    result.set(edge.from, Math.min(30, (result.get(edge.from) ?? 0) + edge.weight));
  }
  return result;
}

function exploitabilityFactor(finding: PrioritizableFinding): PriorityFactor {
  const ruleWeights: Record<string, number> = {
    "security.private-key": 35,
    "security.hardcoded-secret": 30,
    "security.command-execution": 30,
    "security.sql-construction": 28,
    "security.dynamic-execution": 26,
    "security.auth-bypass": 26,
    "security.tls-disabled": 20,
    "security.dom-sink": 16,
    "security.debug-enabled": 12,
    "privacy.sensitive-logging": 12,
    "supply-chain.unpinned-dependency": 10,
    "supply-chain.lockfile-drift": 8,
    "reliability.fetch-timeout": 4,
    "quality.missing-tests": 2,
    "quality.unexplained-suppression": 2,
    "process.security-todo": 2,
    "data.migration-rollback": 2
  };
  const value = ruleWeights[finding.ruleId] ?? 5;
  return factor("exploitability", "Exploitability", value, value >= 20 ? "direct exploit or credential path" : "limited or indirect exploit signal");
}

function exposureFactor(finding: PrioritizableFinding): PriorityFactor {
  const file = finding.file ?? "";
  if (/(^|\/)(api|routes?|controllers?|pages\/api|app\/api|workers?|server|middleware)\b/i.test(file)) {
    return factor("external_exposure", "External exposure", 18, "changed path is commonly externally reachable");
  }
  if (/(^|\/)(deploy|infra|cloud|terraform|wrangler|docker)/i.test(file) || /^(Dockerfile|docker-compose\.yml|package\.json)$/i.test(path.basename(file))) {
    return factor("external_exposure", "External exposure", 10, "changed path affects deploy, runtime, or package posture");
  }
  if (/\.(tsx?|jsx?|vue|svelte)$/i.test(file) && finding.ruleId === "security.dom-sink") {
    return factor("external_exposure", "External exposure", 10, "browser rendering sink may be user reachable");
  }
  return factor("external_exposure", "External exposure", 0, "no external surface signal detected");
}

function assetCriticalityFactor(finding: PrioritizableFinding): PriorityFactor {
  const text = searchableFindingText(finding);
  if (/\b(auth|oauth|oidc|session|jwt|token|permission|role|tenant|admin)\b/i.test(text)) {
    return factor("asset_criticality", "Asset criticality", 18, "identity, authorization, or tenant-boundary asset");
  }
  if (/\b(payment|billing|invoice|checkout|customer|account)\b/i.test(text)) {
    return factor("asset_criticality", "Asset criticality", 14, "business-critical account or money movement asset");
  }
  if (/\b(db|database|sql|migration|schema|secret|key|credential|mcp)\b/i.test(text)) {
    return factor("asset_criticality", "Asset criticality", 12, "data, credential, database, or MCP control surface");
  }
  return factor("asset_criticality", "Asset criticality", 0, "no critical asset signal detected");
}

function dataSensitivityFactor(finding: PrioritizableFinding): PriorityFactor {
  const text = searchableFindingText(finding);
  if (/\b(private key|secret|password|passwd|token|api.?key|credential)\b/i.test(text)) {
    return factor("data_sensitivity", "Data sensitivity", 22, "credential or secret material signal");
  }
  if (/\b(email|ssn|dob|address|phone|pii|personal|customer)\b/i.test(text) || finding.category === "privacy") {
    return factor("data_sensitivity", "Data sensitivity", 14, "personal or sensitive data signal");
  }
  return factor("data_sensitivity", "Data sensitivity", 0, "no sensitive data signal detected");
}

function dependencyCentralityFactor(finding: PrioritizableFinding): PriorityFactor {
  const file = finding.file ?? "";
  if (/^(package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Dockerfile|docker-compose\.yml|wrangler\.toml)$/i.test(path.basename(file))) {
    return factor("dependency_centrality", "Dependency centrality", 16, "root package, deploy, or runtime config affects broad execution");
  }
  if (/(^|\/)(shared|common|lib|core|middleware|auth|db|config|infra)\//i.test(file)) {
    return factor("dependency_centrality", "Dependency centrality", 12, "shared component has broad downstream use");
  }
  if (finding.file === undefined) {
    return factor("dependency_centrality", "Dependency centrality", 10, "repository-level finding affects more than one file");
  }
  return factor("dependency_centrality", "Dependency centrality", 0, "localized file path");
}

function blastRadiusFactor(finding: PrioritizableFinding): PriorityFactor {
  if (["security.auth-bypass", "security.command-execution", "security.sql-construction", "security.dynamic-execution"].includes(finding.ruleId)) {
    return factor("blast_radius", "Blast radius", 18, "control failure can affect confidentiality, integrity, or availability");
  }
  if (["security.private-key", "security.hardcoded-secret"].includes(finding.ruleId)) {
    return factor("blast_radius", "Blast radius", 16, "credential exposure can escape the repository boundary");
  }
  if (finding.category === "supply-chain") {
    return factor("blast_radius", "Blast radius", 12, "dependency posture can affect builds and consumers");
  }
  return factor("blast_radius", "Blast radius", 0, "no broad blast-radius signal detected");
}

function standardsWeightFactor(finding: PrioritizableFinding): PriorityFactor {
  const standards = controlsForFinding(finding);
  let value = Math.min(12, standards.length * 3);
  if (standards.some((standard) => /cwe|top10|api-top10/i.test(standard.standardId))) {
    value += 4;
  }
  if (standards.some((standard) => /mcp|oauth/i.test(standard.standardId))) {
    value += 3;
  }
  return factor("standards_weight", "Standards weight", Math.min(18, value), `${standards.length} mapped standards control(s)`);
}

function mitigationCreditFactor(finding: PrioritizableFinding): PriorityFactor {
  if (finding.status === "waived") {
    return factor("mitigation_credit", "Mitigation credit", -20, "finding has an active waiver");
  }
  if (finding.status === "false_positive") {
    return factor("mitigation_credit", "Mitigation credit", -40, "finding is marked false positive");
  }
  return factor("mitigation_credit", "Mitigation credit", 0, "no waiver or mitigation credit");
}

function comparePrioritizedFindings(left: PrioritizedFinding, right: PrioritizedFinding): number {
  return bandWeight(right.priority.band) - bandWeight(left.priority.band)
    || right.priority.score - left.priority.score
    || SEVERITY_WEIGHTS[right.severity] - SEVERITY_WEIGHTS[left.severity]
    || right.confidence - left.confidence
    || left.ruleId.localeCompare(right.ruleId)
    || locationForFinding(left).localeCompare(locationForFinding(right));
}

function bandForScore(severity: Severity, score: number): PriorityBand {
  if (severity === "blocker" || score >= 110) return "critical";
  if (severity === "high" || score >= 80) return "high";
  if (severity === "medium" || score >= 45) return "medium";
  if (severity === "low" || score >= 15) return "low";
  return "info";
}

function baseBandForSeverity(severity: Severity): PriorityBand {
  switch (severity) {
    case "blocker":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
  }
}

function remediationTierForBand(band: PriorityBand): RemediationTier {
  switch (band) {
    case "critical":
      return "fix-now";
    case "high":
      return "fix-next";
    case "medium":
      return "plan";
    case "low":
      return "backlog";
    case "info":
      return "track";
  }
}

function bandWeight(band: PriorityBand): number {
  switch (band) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
  }
}

function componentForFinding(finding: PrioritizableFinding): string {
  const text = `${finding.file ?? ""} ${finding.ruleId} ${finding.title}`.toLowerCase();
  if (/\bmcp\b/.test(text)) return "mcp";
  if (/\b(oauth|oidc|auth|session|jwt|permission|role|tenant)\b/.test(text)) return "identity";
  if (/(^|\/)(api|routes?|controllers?|pages\/api|app\/api)\b/.test(text)) return "api";
  if (/\b(db|database|sql|migration|schema|prisma)\b/.test(text)) return "data";
  if (/\b(package|lockfile|dependency|docker|slsa|scorecard|supply-chain)\b/.test(text)) return "supply-chain";
  if (/\b(web|browser|dom|html|tsx|jsx|vue|svelte)\b/.test(text)) return "web";
  if (finding.file) {
    return finding.file.split("/").filter(Boolean)[0] ?? "repository";
  }
  return "repository";
}

function controlsForFinding(finding: PrioritizableFinding): StandardReference[] {
  return finding.controls && finding.controls.length > 0 ? finding.controls : finding.standards;
}

function isExploitFoundation(ruleId: string): boolean {
  return [
    "security.auth-bypass",
    "security.command-execution",
    "security.sql-construction",
    "security.dynamic-execution",
    "security.private-key",
    "security.hardcoded-secret",
    "security.tls-disabled"
  ].includes(ruleId);
}

function locationForFinding(finding: PrioritizableFinding): string {
  return finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "repository";
}

function searchableFindingText(finding: PrioritizableFinding): string {
  return [
    finding.ruleId,
    finding.category,
    finding.title,
    finding.file,
    finding.evidence,
    finding.remediation,
    controlsForFinding(finding).map((standard) => `${standard.standardId} ${standard.control} ${standard.title}`).join(" ")
  ].filter(Boolean).join(" ");
}

function addNode(nodes: Map<string, ImpactGraphNode>, node: ImpactGraphNode): void {
  nodes.set(node.id, node);
}

function addEdge(
  edges: Map<string, ImpactGraphEdge>,
  from: string,
  to: string,
  type: ImpactEdgeType,
  rationale: string,
  metadata: Record<string, unknown>
): void {
  if (from === to) {
    return;
  }

  const id = `edge_${shortHash(`${from}:${type}:${to}`)}`;
  edges.set(id, {
    id,
    from,
    to,
    type,
    weight: EDGE_WEIGHTS[type],
    rationale,
    metadata
  });
}

function componentNodeId(component: string): string {
  return `component_${component.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}`;
}

function controlNodeId(reference: StandardReference): string {
  return `control_${shortHash(`${reference.standardId}:${reference.control}`)}`;
}

function labelForNode(nodes: ImpactGraphNode[], id: string): string {
  return nodes.find((node) => node.id === id)?.label ?? id;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}

function factor(key: string, label: string, value: number, reason: string): PriorityFactor {
  return {
    key,
    label,
    value,
    reason
  };
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

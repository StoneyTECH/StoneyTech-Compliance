export type StandardDomain = "mcp" | "api" | "cli" | "web" | "oauth" | "supply-chain" | "secure-sdlc" | "weakness";

export interface StandardSource {
  id: string;
  name: string;
  authority: string;
  version: string;
  url: string;
  domains: StandardDomain[];
  summary: string;
}

export interface StandardReference {
  standardId: string;
  control: string;
  title: string;
  url?: string;
}

export const STANDARDS_CATALOG_URI = "compliance://standards/catalog";

export const STANDARDS_CATALOG: StandardSource[] = [
  {
    id: "owasp-asvs-5.0.0",
    name: "Application Security Verification Standard",
    authority: "OWASP",
    version: "5.0.0",
    url: "https://github.com/OWASP/ASVS/tree/v5.0.0",
    domains: ["api", "web", "oauth", "secure-sdlc"],
    summary: "Primary application, API, web frontend, OAuth/OIDC, data protection, logging, and secure communication requirements."
  },
  {
    id: "owasp-api-top10-2023",
    name: "API Security Top 10",
    authority: "OWASP",
    version: "2023",
    url: "https://owasp.org/API-Security/editions/2023/en/0x00-header/",
    domains: ["api"],
    summary: "API risk prioritization baseline covering object authorization, authentication, resource use, SSRF, misconfiguration, inventory, and unsafe API consumption."
  },
  {
    id: "owasp-top10-2025",
    name: "Top 10 Web Application Security Risks",
    authority: "OWASP",
    version: "2025",
    url: "https://owasp.org/Top10/2025/",
    domains: ["web"],
    summary: "Web application risk awareness baseline for access control, misconfiguration, supply-chain failures, cryptographic failures, injection, logging, and exceptional-condition handling."
  },
  {
    id: "owasp-rest-cheat-sheet",
    name: "REST Security Cheat Sheet",
    authority: "OWASP",
    version: "current",
    url: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    domains: ["api"],
    summary: "Implementation guidance for REST authentication, authorization, input validation, error handling, headers, and transport security."
  },
  {
    id: "nist-ssdf-1.1",
    name: "Secure Software Development Framework",
    authority: "NIST",
    version: "SP 800-218 v1.1",
    url: "https://csrc.nist.gov/pubs/sp/800/218/final",
    domains: ["secure-sdlc", "cli", "supply-chain"],
    summary: "Secure development process baseline for preparing the organization, protecting software, producing well-secured software, and responding to vulnerabilities."
  },
  {
    id: "mitre-cwe-top25-2025",
    name: "CWE Top 25 Most Dangerous Software Weaknesses",
    authority: "MITRE",
    version: "2025",
    url: "https://cwe.mitre.org/top25/index.html",
    domains: ["weakness"],
    summary: "Precise weakness identifiers for exploitable coding flaws such as injection, XSS, missing authorization, hard-coded credentials, and sensitive data exposure."
  },
  {
    id: "openssf-slsa-1.2",
    name: "Supply-chain Levels for Software Artifacts",
    authority: "OpenSSF",
    version: "1.2",
    url: "https://slsa.dev/spec/latest/",
    domains: ["supply-chain"],
    summary: "Supply-chain integrity requirements for source, build, provenance, and artifact traceability."
  },
  {
    id: "openssf-scorecard",
    name: "Scorecard",
    authority: "OpenSSF",
    version: "current",
    url: "https://scorecard.dev/",
    domains: ["supply-chain", "secure-sdlc"],
    summary: "Repository and dependency posture checks such as pinned dependencies, dependency update tooling, CI tests, SAST, signed releases, and token permissions."
  },
  {
    id: "oauth-rfc9700",
    name: "Best Current Practice for OAuth 2.0 Security",
    authority: "IETF",
    version: "RFC 9700",
    url: "https://www.rfc-editor.org/rfc/rfc9700",
    domains: ["oauth"],
    summary: "OAuth 2.0 security best current practice, including redirect URI matching, open redirector avoidance, PKCE, token handling, and deprecated flows."
  },
  {
    id: "mcp-security-best-practices",
    name: "MCP Security Best Practices",
    authority: "Model Context Protocol",
    version: "current",
    url: "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices",
    domains: ["mcp", "oauth"],
    summary: "MCP-specific threats and mitigations, including confused deputy risk, token passthrough, session security, consent, and proxy behavior."
  },
  {
    id: "mcp-authorization-spec",
    name: "MCP Authorization Specification",
    authority: "Model Context Protocol",
    version: "draft/current",
    url: "https://modelcontextprotocol.io/specification/draft/basic/authorization",
    domains: ["mcp", "oauth"],
    summary: "Authorization requirements for HTTP-based MCP transports using OAuth 2.1, protected resource metadata, authorization server discovery, and least-privilege scopes."
  }
];

const REFS = {
  asvsSecretManagement: ref("owasp-asvs-5.0.0", "V13.3.1", "Secrets management; secrets must not be in source or build artifacts"),
  asvsLeastPrivilegeSecrets: ref("owasp-asvs-5.0.0", "V13.3.2", "Secret access follows least privilege"),
  asvsSqlInjection: ref("owasp-asvs-5.0.0", "V1.2.4", "Parameterized database queries protect against injection"),
  asvsCommandInjection: ref("owasp-asvs-5.0.0", "V1.2.5", "OS command injection protection"),
  asvsDynamicExecution: ref("owasp-asvs-5.0.0", "V1.3.2", "Avoid eval and dynamic code execution"),
  asvsDomRendering: ref("owasp-asvs-5.0.0", "V3.2.2", "Safe rendering functions prevent unintended script execution"),
  asvsHtmlSanitization: ref("owasp-asvs-5.0.0", "V1.3.1", "Use secure HTML sanitization for untrusted HTML"),
  asvsAuthorization: ref("owasp-asvs-5.0.0", "V8.2.1/V8.2.2/V8.3.1", "Function, data, and trusted-service-layer authorization"),
  asvsAuthn: ref("owasp-asvs-5.0.0", "V6.3.4", "Consistent authentication pathways and controls"),
  asvsTlsClientValidation: ref("owasp-asvs-5.0.0", "V12.3.2", "TLS clients validate certificates before communication"),
  asvsSensitiveLogging: ref("owasp-asvs-5.0.0", "V16.2.5", "Sensitive data logging follows data protection level"),
  asvsErrorHandling: ref("owasp-asvs-5.0.0", "V16.5.1/V16.5.2", "No sensitive error leakage and secure behavior on external failure"),
  asvsDebugDisabled: ref("owasp-asvs-5.0.0", "V13.4.2", "Debug modes disabled in production"),
  asvsOAuthClient: ref("owasp-asvs-5.0.0", "V10.1/V10.2", "OAuth clients bind flows to the user-agent session and defend against CSRF/mix-up"),
  asvsOAuthResourceServer: ref("owasp-asvs-5.0.0", "V10.3", "Resource servers validate audience and enforce delegated authorization claims"),
  asvsOAuthAuthorizationServer: ref("owasp-asvs-5.0.0", "V10.4", "Authorization servers validate redirect URIs, PKCE, scopes, grants, and token lifecycle"),
  owaspApiBola: ref("owasp-api-top10-2023", "API1:2023/API5:2023", "Broken object and function level authorization"),
  owaspApiResourceUse: ref("owasp-api-top10-2023", "API4:2023", "Unrestricted resource consumption"),
  owaspApiMisconfiguration: ref("owasp-api-top10-2023", "API8:2023", "Security misconfiguration"),
  owaspApiInventory: ref("owasp-api-top10-2023", "API9:2023", "Improper inventory management"),
  owaspApiUnsafeConsumption: ref("owasp-api-top10-2023", "API10:2023", "Unsafe consumption of APIs"),
  owaspTopAccessControl: ref("owasp-top10-2025", "A01:2025", "Broken Access Control"),
  owaspTopCrypto: ref("owasp-top10-2025", "A04:2025", "Cryptographic Failures"),
  owaspTopInjection: ref("owasp-top10-2025", "A05:2025", "Injection"),
  owaspTopMisconfiguration: ref("owasp-top10-2025", "A02:2025", "Security Misconfiguration"),
  owaspTopLogging: ref("owasp-top10-2025", "A09:2025", "Security Logging and Alerting Failures"),
  cweHardcodedCredentials: ref("mitre-cwe-top25-2025", "CWE-798", "Use of hard-coded credentials"),
  cweSensitiveExposure: ref("mitre-cwe-top25-2025", "CWE-200/CWE-532", "Sensitive information exposure or insertion into log files"),
  cweSqlInjection: ref("mitre-cwe-top25-2025", "CWE-89", "SQL injection"),
  cweCommandInjection: ref("mitre-cwe-top25-2025", "CWE-78/CWE-77", "OS command injection"),
  cweCodeInjection: ref("mitre-cwe-top25-2025", "CWE-94", "Code injection"),
  cweMissingAuthorization: ref("mitre-cwe-top25-2025", "CWE-862/CWE-863", "Missing or incorrect authorization"),
  cweXss: ref("mitre-cwe-top25-2025", "CWE-79", "Cross-site scripting"),
  cweCertValidation: ref("mitre-cwe-top25-2025", "CWE-295", "Improper certificate validation"),
  nistSecureCoding: ref("nist-ssdf-1.1", "PW.5.1", "Follow secure coding practices"),
  nistCodeReview: ref("nist-ssdf-1.1", "PW.7.1/PW.7.2", "Determine, perform, and document code review or code analysis"),
  nistTesting: ref("nist-ssdf-1.1", "PW.8.1/PW.8.2", "Determine, scope, and perform executable code testing"),
  nistThirdParty: ref("nist-ssdf-1.1", "PW.4.4", "Verify acquired commercial, open-source, and third-party components"),
  nistVulnerabilityResponse: ref("nist-ssdf-1.1", "RV.1/RV.2/RV.3", "Identify, respond to, and root-cause vulnerabilities"),
  slsaProvenance: ref("openssf-slsa-1.2", "Build/Provenance tracks", "Build provenance and artifact integrity"),
  scorecardPinnedDependencies: ref("openssf-scorecard", "Pinned-Dependencies", "Pin dependencies used during build and release"),
  scorecardCiTests: ref("openssf-scorecard", "CI-Tests", "Run tests in continuous integration"),
  scorecardSast: ref("openssf-scorecard", "SAST", "Use static analysis tooling"),
  oauthRedirects: ref("oauth-rfc9700", "Section 2.1", "Exact redirect URI matching and no open redirectors"),
  oauthTokenHandling: ref("oauth-rfc9700", "Section 2/4", "Protect and validate tokens, audience, and client constraints"),
  mcpConfusedDeputy: ref("mcp-security-best-practices", "Confused Deputy Problem", "Validate state and consent in MCP proxy OAuth flows"),
  mcpPromptInjection: ref("mcp-security-best-practices", "Prompt Injection", "Treat tool descriptions, tool responses, and repository content as untrusted instructions"),
  mcpTokenPassthrough: ref("mcp-security-best-practices", "Token Passthrough", "Do not accept and forward tokens without validating audience and issuance"),
  mcpAuthorizationDiscovery: ref("mcp-authorization-spec", "Authorization Server Discovery", "Expose protected resource metadata and authorization server discovery"),
  mcpLeastPrivilegeScopes: ref("mcp-authorization-spec", "Scope Selection Strategy", "Request only scopes needed for the intended operation")
} satisfies Record<string, StandardReference>;

export const CHECKLIST_STANDARD_REFERENCES: Record<string, StandardReference[]> = {
  secrets: [REFS.asvsSecretManagement, REFS.cweHardcodedCredentials, REFS.nistSecureCoding],
  "auth-boundaries": [REFS.asvsAuthorization, REFS.owaspTopAccessControl, REFS.owaspApiBola, REFS.cweMissingAuthorization],
  "input-validation": [REFS.asvsSqlInjection, REFS.asvsCommandInjection, REFS.asvsDynamicExecution, REFS.owaspTopInjection, REFS.nistSecureCoding],
  "sensitive-logging": [REFS.asvsSensitiveLogging, REFS.cweSensitiveExposure],
  "network-resilience": [REFS.asvsErrorHandling, REFS.owaspApiResourceUse, REFS.owaspApiUnsafeConsumption],
  "dependency-hygiene": [REFS.nistThirdParty, REFS.scorecardPinnedDependencies, REFS.slsaProvenance],
  tests: [REFS.nistTesting, REFS.scorecardCiTests],
  "migration-safety": [REFS.nistCodeReview, REFS.nistVulnerabilityResponse],
  "browser-sinks": [REFS.asvsDomRendering, REFS.asvsHtmlSanitization, REFS.cweXss],
  "node-process": [REFS.asvsCommandInjection, REFS.cweCommandInjection],
  "python-exec": [REFS.asvsDynamicExecution, REFS.cweCodeInjection],
  "python-web": [REFS.asvsSqlInjection, REFS.asvsAuthorization, REFS.asvsDebugDisabled],
  "abuse-cases": [REFS.owaspApiBola, REFS.owaspApiResourceUse, REFS.mcpConfusedDeputy],
  "data-minimization": [REFS.asvsSensitiveLogging, REFS.cweSensitiveExposure],
  "mcp-authorization": [REFS.mcpAuthorizationDiscovery, REFS.mcpLeastPrivilegeScopes, REFS.mcpTokenPassthrough],
  "mcp-tool-safety": [REFS.mcpConfusedDeputy, REFS.asvsAuthorization, REFS.nistCodeReview],
  "oauth-redirects": [REFS.oauthRedirects, REFS.asvsOAuthAuthorizationServer],
  "oauth-token-validation": [REFS.oauthTokenHandling, REFS.asvsOAuthResourceServer, REFS.mcpTokenPassthrough],
  "api-rate-limits": [REFS.owaspApiResourceUse, REFS.asvsErrorHandling],
  "api-inventory": [REFS.owaspApiMisconfiguration, REFS.owaspApiInventory]
};

export const RULE_STANDARD_REFERENCES: Record<string, StandardReference[]> = {
  "security.private-key": [REFS.asvsSecretManagement, REFS.asvsLeastPrivilegeSecrets, REFS.cweHardcodedCredentials, REFS.nistSecureCoding],
  "security.hardcoded-secret": [REFS.asvsSecretManagement, REFS.cweHardcodedCredentials, REFS.nistSecureCoding],
  "security.tls-disabled": [REFS.asvsTlsClientValidation, REFS.owaspTopCrypto, REFS.cweCertValidation],
  "security.dynamic-execution": [REFS.asvsDynamicExecution, REFS.owaspTopInjection, REFS.cweCodeInjection],
  "security.command-execution": [REFS.asvsCommandInjection, REFS.owaspTopInjection, REFS.cweCommandInjection],
  "security.sql-construction": [REFS.asvsSqlInjection, REFS.owaspTopInjection, REFS.cweSqlInjection],
  "security.auth-bypass": [REFS.asvsAuthorization, REFS.owaspTopAccessControl, REFS.owaspApiBola, REFS.cweMissingAuthorization],
  "privacy.sensitive-logging": [REFS.asvsSensitiveLogging, REFS.owaspTopLogging, REFS.cweSensitiveExposure],
  "security.dom-sink": [REFS.asvsDomRendering, REFS.asvsHtmlSanitization, REFS.owaspTopInjection, REFS.cweXss],
  "reliability.fetch-timeout": [REFS.asvsErrorHandling, REFS.owaspApiResourceUse, REFS.owaspApiUnsafeConsumption],
  "process.security-todo": [REFS.nistCodeReview, REFS.nistVulnerabilityResponse],
  "quality.unexplained-suppression": [REFS.nistCodeReview, REFS.scorecardSast],
  "supply-chain.unpinned-dependency": [REFS.scorecardPinnedDependencies, REFS.nistThirdParty, REFS.slsaProvenance],
  "security.debug-enabled": [REFS.asvsDebugDisabled, REFS.owaspTopMisconfiguration],
  "mcp.prompt-injection": [REFS.mcpPromptInjection, REFS.mcpConfusedDeputy, REFS.nistCodeReview],
  "quality.missing-tests": [REFS.nistTesting, REFS.scorecardCiTests],
  "supply-chain.lockfile-drift": [REFS.scorecardPinnedDependencies, REFS.nistThirdParty, REFS.slsaProvenance],
  "data.migration-rollback": [REFS.nistCodeReview, REFS.nistVulnerabilityResponse]
};

export function referencesForChecklistItem(itemId: string): StandardReference[] {
  return CHECKLIST_STANDARD_REFERENCES[itemId] ?? [REFS.nistSecureCoding];
}

export function referencesForRule(ruleId: string): StandardReference[] {
  return RULE_STANDARD_REFERENCES[ruleId] ?? [REFS.nistCodeReview];
}

export function formatStandardReference(reference: StandardReference): string {
  return `${reference.standardId} ${reference.control} - ${reference.title}`;
}

export function formatStandardsCatalogMarkdown(): string {
  const lines = ["# Compliance Standards Catalog", ""];

  for (const standard of STANDARDS_CATALOG) {
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

function ref(standardId: string, control: string, title: string): StandardReference {
  const standard = STANDARDS_CATALOG.find((candidate) => candidate.id === standardId);
  return {
    standardId,
    control,
    title,
    url: standard?.url
  };
}

import type { ActionType } from './actions.js';
import type { RiskPrimitive } from './verdict.js';

/**
 * Definition of a URL threat type.
 */
export interface ThreatDefinition {
  /** Unique threat ID (e.g., "U01") */
  id: string;
  /** Human-readable threat name */
  name: string;
  /** Which risk primitive this threat maps to */
  primitive: RiskPrimitive;
  /** Default severity score */
  severity: number;
  /** Description of the threat */
  description: string;
}

/**
 * Schema for the URL patterns database (urls.json).
 */
export interface UrlPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  trackerDomains: string[];
  adClickParams: string[];
  shorteners: string[];
  freeHostingPlatforms: string[];
  riskyTlds: string[];
  redirectParamKeys: string[];
  highRiskKeywords: string[];
  suspiciousExtensions: string[];
  internalIpRanges: string[];
  cloudMetadataEndpoints: string[];
}

/**
 * A single brand with its typosquatting variants and legitimate domains.
 */
export interface BrandEntry {
  /** Brand name */
  brand: string;
  /** Known typosquatting variants */
  variants: string[];
  /** Legitimate domains (false-positive exclusion) */
  legitimateDomains: string[];
}

/**
 * Schema for the brands pattern database (brands.json).
 */
export interface BrandPatternDatabase {
  version: string;
  brands: BrandEntry[];
}

/**
 * Schema for the command patterns database (commands.json).
 */
export interface CommandPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  destructiveCommands: string[];
  destructiveFlags: Record<string, string[]>;
  criticalPaths: string[];
  exfiltrationCommands: string[];
  exfiltrationPatterns: string[];
  reverseShellPatterns: string[];
  privilegeEscalation: string[];
  persistenceTargets: string[];
  networkCommands: string[];
  containerEscapePatterns: string[];
  packageManagers: string[];
  encodingCommands: string[];
  pipeToShell: string[];
  safeCommands: string[];
}

// ── Text Patterns (M2) ─────────────────────────────────────────────────

/**
 * Schema for the text/prompt injection patterns database (text.json).
 */
export interface TextPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  directInjectionPatterns: string[];
  goalHijackingPatterns: string[];
  personaHijackingPatterns: string[];
  toolManipulationPatterns: string[];
  exfiltrationRequestPatterns: string[];
  encodingEvasionPatterns: string[];
  contextPoisoningIndicators: string[];
  markupInjectionPatterns: string[];
  delayedTriggerPatterns: string[];
  systemPromptIndicators: string[];
  safePatterns: string[];
}

// ── File Read Patterns (M2) ─────────────────────────────────────────────

/**
 * An entry in a sensitive path list with score, threat ID, and match type.
 */
export interface SensitivePathEntry {
  pattern: string;
  score: number;
  threatId: string;
  reason: string;
  matchType?: 'exact' | 'prefix' | 'basename' | 'contains';
}

/**
 * An entry for sensitive file extensions.
 */
export interface SensitiveExtensionEntry {
  extension: string;
  score: number;
  threatId: string;
  reason: string;
}

/**
 * Schema for the file-read patterns database (file-read.json).
 */
export interface FileReadPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  criticalPaths: SensitivePathEntry[];
  highPaths: SensitivePathEntry[];
  mediumPaths: SensitivePathEntry[];
  sensitiveExtensions: SensitiveExtensionEntry[];
  browserDataPaths: SensitivePathEntry[];
  safePaths: string[];
  safeExtensions: string[];
}

// ── File Write Patterns (M2) ────────────────────────────────────────────

/**
 * An entry in a file write path list.
 */
export interface FileWritePathEntry {
  pattern: string;
  score: number;
  threatId: string;
  reason: string;
  primitive: RiskPrimitive;
  matchType?: 'exact' | 'prefix' | 'basename' | 'contains';
}

/**
 * A content pattern entry for detecting dangerous file contents.
 */
export interface ContentPatternEntry {
  pattern: string;
  score: number;
  threatId: string;
  reason: string;
  primitive: RiskPrimitive;
  isRegex?: boolean;
}

/**
 * Schema for the file-write patterns database (file-write.json).
 */
export interface FileWritePatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  criticalPaths: FileWritePathEntry[];
  persistencePaths: FileWritePathEntry[];
  shellConfigPaths: FileWritePathEntry[];
  buildConfigPaths: FileWritePathEntry[];
  credentialPaths: FileWritePathEntry[];
  dangerousContentPatterns: ContentPatternEntry[];
  packageJsonScriptPatterns: ContentPatternEntry[];
  safeExtensions: string[];
  safeDirectories: string[];
}

// ── API Call Patterns (M5) ────────────────────────────────────────────

/**
 * Schema for the API call patterns database (api-call.json).
 */
export interface ApiCallPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  destructiveEndpoints: string[];
  exfiltrationPatterns: string[];
  ssrfTargets: string[];
  sensitiveHeaders: string[];
  webhookPatterns: string[];
  transactionEndpoints: string[];
  safeEndpoints: string[];
}

// ── Query Patterns (M5) ──────────────────────────────────────────────

/**
 * Schema for the query patterns database (query.json).
 */
export interface QueryPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  destructiveDdl: string[];
  destructiveDml: string[];
  exfiltrationPatterns: string[];
  escalationPatterns: string[];
  persistencePatterns: string[];
  obfuscationPatterns: string[];
  safePatterns: string[];
}

// ── Code Patterns (M5) ──────────────────────────────────────────────

/**
 * Schema for the code patterns database (code.json).
 */
export interface CodePatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  backdoorPatterns: string[];
  vulnerabilityPatterns: string[];
  dependencyConfusion: string[];
  obfuscationPatterns: string[];
  phoneHomePatterns: string[];
  insecureDefaults: string[];
  logicBombPatterns: string[];
  cryptoReplacement: string[];
  safePatterns: string[];
}

// ── Message Patterns (M7) ────────────────────────────────────────────

/**
 * Schema for the message patterns database (message.json).
 */
export interface MessagePatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  emailPatterns: string[];
  slackPatterns: string[];
  smsPatterns: string[];
  socialMediaPatterns: string[];
  sensitiveContentPatterns: string[];
  impersonationPatterns: string[];
  safePatterns: string[];
}

// ── Transaction Patterns (M7) ────────────────────────────────────────

/**
 * Schema for the transaction patterns database (transaction.json).
 */
export interface TransactionPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  paymentEndpoints: string[];
  transferPatterns: string[];
  cryptoPatterns: string[];
  tradingPatterns: string[];
  subscriptionPatterns: string[];
  pricingPatterns: string[];
  highRiskAmountThreshold: number;
  safePatterns: string[];
}

// ── Auth Patterns (M7) ──────────────────────────────────────────────

/**
 * Schema for the auth patterns database (auth.json).
 */
export interface AuthPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  accountCreationPatterns: string[];
  permissionPatterns: string[];
  credentialPatterns: string[];
  oauthPatterns: string[];
  mfaPatterns: string[];
  legalPatterns: string[];
  safePatterns: string[];
}

// ── Git Patterns (M8) ────────────────────────────────────────────────

/**
 * Schema for the git patterns database (git.json).
 */
export interface GitPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  forcePushPatterns: string[];
  mergePatterns: string[];
  cicdPatterns: string[];
  releasePatterns: string[];
  branchDeletePatterns: string[];
  gitignorePatterns: string[];
  protectedBranches: string[];
  safePatterns: string[];
}

// ── UI Action Patterns (M8) ─────────────────────────────────────────

/**
 * Schema for the UI action patterns database (ui-action.json).
 */
export interface UiActionPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  destructiveButtonPatterns: string[];
  formCorruptionPatterns: string[];
  dialogAcceptancePatterns: string[];
  paymentFormPatterns: string[];
  maliciousDownloadPatterns: string[];
  screenCapturePatterns: string[];
  sensitiveElements: string[];
  safePatterns: string[];
}

// ── Infra Patterns (M8) ─────────────────────────────────────────────

/**
 * Schema for the infrastructure patterns database (infra.json).
 */
export interface InfraPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  containerEscapePatterns: string[];
  iacModificationPatterns: string[];
  firewallPatterns: string[];
  certificatePatterns: string[];
  dnsModificationPatterns: string[];
  secretStorePatterns: string[];
  resourceProvisioningPatterns: string[];
  iamPatterns: string[];
  securityGroupPatterns: string[];
  backupDeletionPatterns: string[];
  productionDeployPatterns: string[];
  cloudSecretPatterns: string[];
  productionEnvironments: string[];
  safePatterns: string[];
}

// ── Agent Comm Patterns (M9) ─────────────────────────────────────────

/**
 * Schema for the agent communication patterns database (agent-comm.json).
 */
export interface AgentCommPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  taskDelegationPatterns: string[];
  contextPoisoningPatterns: string[];
  toolSharingPatterns: string[];
  mcpAbusePatterns: string[];
  sensitiveTools: string[];
  safePatterns: string[];
}

// ── Data Pipeline Patterns (M9) ──────────────────────────────────────

/**
 * Schema for the data pipeline/ML patterns database (data-pipeline.json).
 */
export interface DataPipelinePatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  etlModificationPatterns: string[];
  modelPoisoningPatterns: string[];
  trainingDataPatterns: string[];
  vectorStorePatterns: string[];
  datasetExportPatterns: string[];
  productionModels: string[];
  safePatterns: string[];
}

// ── Document Patterns (M9) ───────────────────────────────────────────

/**
 * Schema for the document patterns database (document.json).
 */
export interface DocumentPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  contractModificationPatterns: string[];
  spreadsheetTamperingPatterns: string[];
  externalSharingPatterns: string[];
  publicPublicationPatterns: string[];
  sensitiveDocTypes: string[];
  safePatterns: string[];
}

// ── IoT Patterns (M9) ───────────────────────────────────────────────

/**
 * Schema for the IoT/physical device patterns database (iot.json).
 */
export interface IotPatternDatabase {
  version: string;
  threats: ThreatDefinition[];
  smartLockPatterns: string[];
  industrialControlPatterns: string[];
  securityCameraPatterns: string[];
  vehicleCommandPatterns: string[];
  criticalDeviceTypes: string[];
  safePatterns: string[];
}

// ── Chain Patterns (M6) ──────────────────────────────────────────────

/**
 * A single step in a multi-step attack chain.
 */
export interface ChainStepDefinition {
  /** Action types that can match this step */
  actionTypes: ActionType[];
  /** If specified, the action must trigger one of these primitives */
  primitives?: RiskPrimitive[];
  /** Minimum score required to match this step */
  minScore?: number;
  /** Regex patterns to match against the action value */
  valuePatterns?: string[];
  /** Human-readable label for this step */
  label: string;
  /** If true, this step can repeat (for accumulation patterns) */
  repeat?: boolean;
}

/**
 * A multi-step attack chain definition.
 */
export interface ChainDefinition {
  /** Unique chain ID (e.g., "CH01") */
  id: string;
  /** Human-readable chain name */
  name: string;
  /** Description of the attack pattern */
  description: string;
  /** The primary risk primitive this chain maps to */
  primitive: RiskPrimitive;
  /** Score boost applied when chain is detected */
  scoreBoost: number;
  /** Time window in milliseconds for all steps to occur */
  windowMs: number;
  /** Ordered steps in the chain */
  steps: ChainStepDefinition[];
  /** Minimum number of step occurrences (for repeat patterns) */
  minOccurrences?: number;
}

/**
 * Schema for the chain patterns database (chains.json).
 */
export interface ChainPatternDatabase {
  version: string;
  chains: ChainDefinition[];
}

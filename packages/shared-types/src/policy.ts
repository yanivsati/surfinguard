import type { ActionType } from './actions.js';
import type { RiskLevel, RiskPrimitive } from './verdict.js';

/**
 * Policy enforcement levels.
 */
export type PolicyLevel = 'permissive' | 'balanced' | 'strict';

/**
 * A single policy rule that defines conditions and thresholds.
 */
export interface PolicyRule {
  /** Which action types this rule applies to */
  actionTypes?: ActionType[];
  /** Which primitives this rule targets */
  primitives?: RiskPrimitive[];
  /** Minimum score to trigger this rule */
  minScore?: number;
  /** The risk level at which to block */
  blockLevel: RiskLevel;
}

/**
 * An entry in the policy allowlist — always permitted regardless of score.
 */
export interface AllowlistEntry {
  /** Action type this entry applies to */
  type: ActionType;
  /** Glob or regex pattern to match against the value */
  pattern: string;
  /** If true, pattern is a regex; otherwise it's a glob */
  isRegex?: boolean;
  /** Reason for allowing */
  reason?: string;
}

/**
 * An entry in the policy blocklist — always blocked regardless of score.
 */
export interface BlocklistEntry {
  /** Action type this entry applies to */
  type: ActionType;
  /** Glob or regex pattern to match against the value */
  pattern: string;
  /** If true, pattern is a regex; otherwise it's a glob */
  isRegex?: boolean;
  /** Reason for blocking */
  reason?: string;
}

/**
 * Environment-specific policy overrides.
 */
export interface EnvironmentOverride {
  /** Environment name (e.g., 'development', 'staging', 'production') */
  environment: string;
  /** Override the base policy level for this environment */
  level?: PolicyLevel;
  /** Additional rules for this environment */
  rules?: PolicyRule[];
}

/**
 * Built-in policy template names.
 */
export type PolicyTemplate =
  | 'open-development'
  | 'standard-production'
  | 'high-security'
  | 'compliance-strict';

/**
 * A complete policy configuration.
 */
export interface Policy {
  /** Unique policy ID (server-assigned) */
  id?: string;
  /** Policy name */
  name: string;
  /** Base enforcement level */
  level: PolicyLevel;
  /** Custom rules (override defaults) */
  rules?: PolicyRule[];
  /** Allowlist — entries that bypass risk scoring */
  allowlist?: AllowlistEntry[];
  /** Blocklist — entries that are always blocked */
  blocklist?: BlocklistEntry[];
  /** Environment-specific overrides */
  environments?: EnvironmentOverride[];
  /** Require human approval for CAUTION results */
  requireApprovalForCaution?: boolean;
  /** Require human approval for DANGER results */
  requireApprovalForDanger?: boolean;
  /** Maximum cumulative risk score before session is locked */
  sessionRiskCeiling?: number;
  /** When the policy was created */
  createdAt?: string;
  /** When the policy was last updated */
  updatedAt?: string;
}

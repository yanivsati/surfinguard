import type { RiskLevel, RiskPrimitive } from './verdict.js';

/**
 * All action types the SDK can analyze.
 * M0: url, M1: command, M2: text, file_read, file_write.
 * M5: api_call, query, code_eval.
 * M7: message, transaction, auth.
 * M8: git, ui_action, infra.
 */
export type ActionType =
  | 'url'
  | 'command'
  | 'text'
  | 'file_read'
  | 'file_write'
  | 'file_delete'
  | 'api_call'
  | 'query'
  | 'dns_lookup'
  | 'network_connect'
  | 'process_spawn'
  | 'env_read'
  | 'env_write'
  | 'registry_read'
  | 'registry_write'
  | 'clipboard_read'
  | 'clipboard_write'
  | 'screenshot'
  | 'keylog'
  | 'code_eval'
  | 'message'
  | 'transaction'
  | 'auth'
  | 'git'
  | 'ui_action'
  | 'infra'
  | 'agent_comm'
  | 'data_pipeline'
  | 'document'
  | 'iot';

/**
 * Input to the engine for a single action to analyze.
 */
export interface ActionInput {
  /** The type of action being performed */
  type: ActionType;
  /** The primary value (URL string, command string, file path, etc.) */
  value: string;
  /** Optional metadata about the action */
  metadata?: Record<string, unknown>;
}

/**
 * Lightweight summary of a completed action and its result.
 * Used by SessionTracker and context engine for chain detection.
 */
export interface ActionSummary {
  type: ActionType;
  value: string;
  score: number;
  level: RiskLevel;
  primitive: RiskPrimitive | null;
  timestamp: number;
}

/**
 * Contextual information about the agent/environment performing the action.
 * Used by ContextEngine for behavioral analysis and session-aware scoring.
 */
export interface ActionContext {
  /** Identifier for the agent performing the action */
  agentId?: string;
  /** The session or conversation ID */
  sessionId?: string;
  /** Previous actions in this session (for pattern analysis) */
  priorActions?: ActionSummary[];
  /** The stated goal or task description */
  taskDescription?: string;
  /** Trust level of the agent (0-1) */
  trustLevel?: number;
  /** The environment name (e.g., 'development', 'production') */
  environment?: string;
}

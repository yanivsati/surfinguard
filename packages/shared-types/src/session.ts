import type { ActionType } from './actions.js';
import type { ActionSummary } from './actions.js';
import type { RiskLevel, RiskPrimitive, CheckResult, ChainDetection } from './verdict.js';

/**
 * State of an active session for multi-step analysis.
 */
export interface SessionState {
  sessionId: string;
  agentId?: string;
  startedAt: number;
  lastActivityAt: number;
  actionCount: number;
  /** Cumulative scores per primitive */
  cumulativePrimitiveScores: Record<RiskPrimitive, number>;
  /** Highest single-action score seen in this session */
  peakScore: number;
  /** Action history (capped) */
  actions: ActionSummary[];
  /** Currently active chain IDs */
  activeChains: string[];
  /** Risk trend: rising, stable, or declining */
  riskTrend: 'rising' | 'stable' | 'declining';
}

/**
 * Input for batch checking multiple actions.
 */
export interface BatchCheckInput {
  /** Actions to check */
  actions: Array<{ type: ActionType; value: string; metadata?: Record<string, unknown> }>;
  /** Session ID to use (creates one if not provided) */
  sessionId?: string;
  /** Agent identifier */
  agentId?: string;
  /** If true, check actions sequentially with progressive context */
  sequential?: boolean;
  /** If true, use LLM enhancement for CAUTION results */
  enhance?: boolean;
}

/**
 * Result of a batch check.
 */
export interface BatchCheckResult {
  /** Individual results for each action */
  results: CheckResult[];
  /** Session ID used */
  sessionId: string;
  /** Chain detections across the batch */
  chainDetections: ChainDetection[];
  /** Overall risk level (max across all results) */
  overallLevel: RiskLevel;
  /** Overall risk score (max across all results) */
  overallScore: number;
}

/**
 * Summary info about a session (for SDK/API responses).
 */
export interface SessionInfo {
  sessionId: string;
  agentId?: string;
  startedAt: number;
  lastActivityAt: number;
  actionCount: number;
  peakScore: number;
  riskTrend: 'rising' | 'stable' | 'declining';
  activeChains: string[];
}

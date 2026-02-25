/**
 * The five risk primitives that all threats map to.
 */
export type RiskPrimitive =
  | 'DESTRUCTION'
  | 'EXFILTRATION'
  | 'ESCALATION'
  | 'PERSISTENCE'
  | 'MANIPULATION';

/**
 * Risk classification levels.
 * SAFE: score 0-2, CAUTION: score 3-6, DANGER: score 7+
 */
export type RiskLevel = 'SAFE' | 'CAUTION' | 'DANGER';

/**
 * Score for a single risk primitive.
 */
export interface PrimitiveScore {
  primitive: RiskPrimitive;
  score: number;
  reasons: string[];
}

/**
 * A detected multi-step attack chain.
 */
export interface ChainDetection {
  /** Chain definition ID (e.g., "CH01") */
  chainId: string;
  /** Human-readable chain name */
  name: string;
  /** Labels of the matched steps in order */
  matchedSteps: string[];
  /** Score boost applied due to chain detection */
  scoreBoost: number;
}

/**
 * Complete result of analyzing a single action.
 */
export interface CheckResult {
  /** Whether the action should be allowed */
  allow: boolean;
  /** Composite risk score (0-10) */
  score: number;
  /** Overall risk level */
  level: RiskLevel;
  /** The primary (highest-scoring) risk primitive */
  primitive: RiskPrimitive | null;
  /** Per-primitive score breakdown */
  primitiveScores: PrimitiveScore[];
  /** Human-readable reasons for the score */
  reasons: string[];
  /** Suggested safer alternatives, if any */
  alternatives?: string[];
  /** Time taken for analysis in milliseconds */
  latencyMs: number;
  /** Score boost from context engine (session awareness) */
  contextBoost?: number;
  /** Multi-step attack chains detected in session */
  chainDetections?: ChainDetection[];
  /** Risk trend within the current session */
  riskTrend?: 'rising' | 'stable' | 'declining';
}

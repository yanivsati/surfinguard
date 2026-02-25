export { Guard } from './guard.js';
export { SurfinguardError, AuthenticationError, RateLimitError, APIError, NotAllowedError } from './errors.js';
export type {
  Mode,
  SimplePolicy,
  SimplePolicy as Policy,
  GuardOptions,
  HealthResponse,
  SessionInfo,
  BatchOptions,
  BatchResult,
  CheckResult,
  RiskLevel,
  RiskPrimitive,
  PrimitiveScore,
  ChainDetection,
  ActionType,
  BatchCheckResult,
  AgentProfile,
  ComplianceReport,
} from './types.js';
export type { Policy as RichPolicy, PolicyTemplate } from './types.js';

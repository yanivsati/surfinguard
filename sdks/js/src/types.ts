export type { CheckResult, RiskLevel, RiskPrimitive, PrimitiveScore, ChainDetection, Policy, PolicyTemplate, ActionType, BatchCheckResult } from '@surfinguard/types';

export type Mode = 'local' | 'api';
export type SimplePolicy = 'permissive' | 'moderate' | 'strict';

export interface GuardOptions {
  apiKey?: string;
  baseUrl?: string;
  mode?: Mode;
  policy?: SimplePolicy;
  timeout?: number;
  sessionId?: string;
  agentId?: string;
  policyConfig?: import('@surfinguard/types').Policy | import('@surfinguard/types').PolicyTemplate;
  telemetry?: boolean;
}

export interface AgentProfile {
  name: string;
  description?: string;
  domain: 'healthcare' | 'finance' | 'legal' | 'education' | 'hr' | 'law_enforcement' | 'critical_infrastructure' | 'general';
  autonomyLevel: 'supervised' | 'semi_autonomous' | 'fully_autonomous';
  usesPersonalData?: boolean;
  affectsSafety?: boolean;
  makesDecisions?: boolean;
  interactsWithPublic?: boolean;
}

export interface ComplianceReport {
  framework: string;
  riskClassification: string;
  overallStatus: string;
  requirements: Array<{
    id: string;
    article: string;
    title: string;
    description: string;
    appliesTo: string[];
    status: string;
    details?: string;
  }>;
  summary: { total: number; compliant: number; partial: number; nonCompliant: number };
  assessedAt: string;
}

export interface HealthResponse {
  ok: boolean;
  version: string;
  analyzers: string[];
  auth: boolean;
  llm: boolean;
  sessions: boolean;
  policies: boolean;
  uptime: number;
}

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

export interface BatchOptions {
  sessionId?: string;
  agentId?: string;
  sequential?: boolean;
  enhance?: boolean;
}

export interface BatchResult {
  results: import('@surfinguard/types').CheckResult[];
  sessionId: string;
  chainDetections: import('@surfinguard/types').ChainDetection[];
  overallLevel: import('@surfinguard/types').RiskLevel;
  overallScore: number;
}

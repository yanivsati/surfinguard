import { initialize, CoreEngine, SessionTracker, PolicyEngine } from '@surfinguard/core-engine-wasm';
import type { CheckResult, ActionType, Policy, PolicyTemplate } from '@surfinguard/types';
import { SurfinguardHTTPClient } from './http.js';
import { reportTelemetry } from './telemetry.js';
import { NotAllowedError } from './errors.js';
import type { Mode, SimplePolicy, GuardOptions, HealthResponse, SessionInfo, BatchOptions, BatchResult, AgentProfile, ComplianceReport } from './types.js';

const DEFAULT_BASE_URL = 'https://api.surfinguard.com';
const DEFAULT_TIMEOUT = 5000;
const SDK_VERSION = '0.10.0';

export class Guard {
  private engine?: CoreEngine;
  private http?: SurfinguardHTTPClient;
  private mode: Mode;
  private policy: SimplePolicy;
  private policyEngine?: PolicyEngine;
  private sessionTracker?: SessionTracker;
  private sessionId?: string;
  private agentId?: string;
  private telemetryEnabled: boolean;

  /**
   * Async factory method (recommended). Initializes WASM then constructs Guard.
   */
  static async create(options: GuardOptions = {}): Promise<Guard> {
    if ((options.mode ?? 'local') === 'local') {
      await initialize();
    }
    return new Guard(options);
  }

  constructor(options: GuardOptions = {}) {
    this.mode = options.mode ?? 'local';
    this.policy = options.policy ?? 'moderate';
    this.sessionId = options.sessionId;
    this.agentId = options.agentId;
    this.telemetryEnabled = options.telemetry ?? false;

    if (this.mode === 'local') {
      this.engine = new CoreEngine();
      // Create session tracker for local mode session awareness
      if (options.sessionId) {
        this.sessionTracker = new SessionTracker();
      }
      // Rich policy config takes precedence over simple policy
      if (options.policyConfig) {
        if (typeof options.policyConfig === 'string') {
          this.policyEngine = PolicyEngine.fromTemplate(options.policyConfig);
        } else {
          this.policyEngine = new PolicyEngine(options.policyConfig);
        }
      }
    }

    if (this.mode === 'api') {
      if (!options.apiKey) {
        throw new Error('apiKey is required for API mode');
      }
      this.http = new SurfinguardHTTPClient(
        options.baseUrl ?? DEFAULT_BASE_URL,
        options.apiKey,
        options.timeout ?? DEFAULT_TIMEOUT,
      );
    }
  }

  checkUrl(url: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('url', url);
    }
    return this.apiCheck('/v2/check/url', { url });
  }

  checkCommand(command: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('command', command);
    }
    return this.apiCheck('/v2/check/command', { command });
  }

  checkText(text: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('text', text);
    }
    return this.apiCheck('/v2/check/text', { text });
  }

  checkFileRead(path: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('file_read', path);
    }
    return this.apiCheck('/v2/check/file', { path, operation: 'read' });
  }

  checkFileWrite(path: string, content?: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('file_write', path, content ? { content } : undefined);
    }
    const payload: Record<string, unknown> = { path, operation: 'write' };
    if (content !== undefined) {
      payload.content = content;
    }
    return this.apiCheck('/v2/check/file', payload);
  }

  check(type: string, value: string, metadata?: Record<string, unknown>): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck(type as ActionType, value, metadata);
    }
    const payload: Record<string, unknown> = { type, value };
    if (metadata) {
      payload.metadata = metadata;
    }
    return this.apiCheck('/v2/check', payload);
  }

  checkApiCall(url: string, method?: string, headers?: Record<string, string>, body?: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      const metadata: Record<string, unknown> = {};
      if (method) metadata.method = method;
      if (headers) metadata.headers = headers;
      if (body) metadata.body = body;
      return this.localCheck('api_call', url, Object.keys(metadata).length > 0 ? metadata : undefined);
    }
    const payload: Record<string, unknown> = { url };
    if (method) payload.method = method;
    if (headers) payload.headers = headers;
    if (body) payload.body = body;
    return this.apiCheck('/v2/check/api-call', payload);
  }

  checkQuery(query: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('query', query);
    }
    return this.apiCheck('/v2/check/query', { query });
  }

  checkCode(code: string, language?: string): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('code_eval', code, language ? { language } : undefined);
    }
    const payload: Record<string, unknown> = { code };
    if (language) payload.language = language;
    return this.apiCheck('/v2/check/code', payload);
  }

  checkMessage(body: string, metadata?: { channel?: string; to?: string; subject?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('message', body, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { body };
    if (metadata?.channel) payload.channel = metadata.channel;
    if (metadata?.to) payload.to = metadata.to;
    if (metadata?.subject) payload.subject = metadata.subject;
    return this.apiCheck('/v2/check/message', payload);
  }

  checkTransaction(description: string, metadata?: { amount?: number; currency?: string; recipient?: string; type?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('transaction', description, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { description };
    if (metadata?.amount !== undefined) payload.amount = metadata.amount;
    if (metadata?.currency) payload.currency = metadata.currency;
    if (metadata?.recipient) payload.recipient = metadata.recipient;
    if (metadata?.type) payload.type = metadata.type;
    return this.apiCheck('/v2/check/transaction', payload);
  }

  checkAuth(action: string, metadata?: { scope?: string; role?: string; target?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('auth', action, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { action };
    if (metadata?.scope) payload.scope = metadata.scope;
    if (metadata?.role) payload.role = metadata.role;
    if (metadata?.target) payload.target = metadata.target;
    return this.apiCheck('/v2/check/auth', payload);
  }

  checkGit(command: string, metadata?: { branch?: string; remote?: string; files?: string[] }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('git', command, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { command };
    if (metadata?.branch) payload.branch = metadata.branch;
    if (metadata?.remote) payload.remote = metadata.remote;
    if (metadata?.files) payload.files = metadata.files;
    return this.apiCheck('/v2/check/git', payload);
  }

  checkUiAction(action: string, metadata?: { element?: string; url?: string; application?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('ui_action', action, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { action };
    if (metadata?.element) payload.element = metadata.element;
    if (metadata?.url) payload.url = metadata.url;
    if (metadata?.application) payload.application = metadata.application;
    return this.apiCheck('/v2/check/ui-action', payload);
  }

  checkInfra(action: string, metadata?: { provider?: string; environment?: string; resource?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('infra', action, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { action };
    if (metadata?.provider) payload.provider = metadata.provider;
    if (metadata?.environment) payload.environment = metadata.environment;
    if (metadata?.resource) payload.resource = metadata.resource;
    return this.apiCheck('/v2/check/infra', payload);
  }

  checkAgentComm(action: string, metadata?: { agent_id?: string; target_agent?: string; tool?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('agent_comm', action, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { action };
    if (metadata?.agent_id) payload.agent_id = metadata.agent_id;
    if (metadata?.target_agent) payload.target_agent = metadata.target_agent;
    if (metadata?.tool) payload.tool = metadata.tool;
    return this.apiCheck('/v2/check/agent-comm', payload);
  }

  checkDataPipeline(action: string, metadata?: { operation?: string; dataset?: string; model?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('data_pipeline', action, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { action };
    if (metadata?.operation) payload.operation = metadata.operation;
    if (metadata?.dataset) payload.dataset = metadata.dataset;
    if (metadata?.model) payload.model = metadata.model;
    return this.apiCheck('/v2/check/data-pipeline', payload);
  }

  checkDocument(action: string, metadata?: { operation?: string; content?: string; recipient?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('document', action, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { action };
    if (metadata?.operation) payload.operation = metadata.operation;
    if (metadata?.content) payload.content = metadata.content;
    if (metadata?.recipient) payload.recipient = metadata.recipient;
    return this.apiCheck('/v2/check/document', payload);
  }

  checkIot(command: string, metadata?: { device_type?: string; device_id?: string; resource?: string }): CheckResult | Promise<CheckResult> {
    if (this.mode === 'local') {
      return this.localCheck('iot', command, metadata as Record<string, unknown> | undefined);
    }
    const payload: Record<string, unknown> = { command };
    if (metadata?.device_type) payload.device_type = metadata.device_type;
    if (metadata?.device_id) payload.device_id = metadata.device_id;
    if (metadata?.resource) payload.resource = metadata.resource;
    return this.apiCheck('/v2/check/iot', payload);
  }

  /**
   * Check multiple actions in a batch with session tracking and chain detection.
   */
  checkBatch(
    actions: Array<{ type: string; value: string; metadata?: Record<string, unknown> }>,
    options?: BatchOptions,
  ): BatchResult | Promise<BatchResult> {
    if (this.mode === 'local') {
      const batchInput = {
        actions: actions.map((a) => ({ type: a.type as ActionType, value: a.value, metadata: a.metadata })),
        sessionId: options?.sessionId ?? this.sessionId,
        agentId: options?.agentId ?? this.agentId,
        sequential: options?.sequential ?? true,
      };
      const result = this.engine!.checkBatch(batchInput);
      // Enforce policy on overall result
      for (const r of result.results) {
        this.enforcePolicy(r);
      }
      return result as BatchResult;
    }

    return this.http!.post<BatchResult>('/v2/check/batch', {
      actions,
      sessionId: options?.sessionId ?? this.sessionId,
      agentId: options?.agentId ?? this.agentId,
      sequential: options?.sequential ?? true,
      enhance: options?.enhance,
    });
  }

  /**
   * Get current session info (API mode only).
   */
  async getSession(): Promise<SessionInfo> {
    if (this.mode === 'local') {
      if (!this.sessionTracker || !this.sessionId) {
        throw new Error('No active session. Provide sessionId in constructor.');
      }
      const info = this.sessionTracker.getSessionInfo(this.sessionId);
      if (!info) {
        throw new Error('Session not found');
      }
      return info;
    }
    if (!this.sessionId) {
      throw new Error('No active session. Provide sessionId in constructor.');
    }
    return this.http!.get<SessionInfo>(`/v2/sessions/${this.sessionId}`);
  }

  /**
   * Reset/clear the current session.
   */
  resetSession(): void | Promise<void> {
    if (this.mode === 'local') {
      if (this.sessionTracker && this.sessionId) {
        this.sessionTracker.clearSession(this.sessionId);
      }
      return;
    }
    if (!this.sessionId) return;
    return this.http!.delete(`/v2/sessions/${this.sessionId}`).then(() => undefined);
  }

  /**
   * Create a policy (API mode only).
   */
  async createPolicy(policy: { name: string; level?: string; rules?: unknown[]; allowlist?: unknown[]; blocklist?: unknown[] }): Promise<{ id: string }> {
    if (!this.http) throw new Error('createPolicy requires API mode');
    return this.http.post('/v2/policies', policy);
  }

  /**
   * List policies (API mode only).
   */
  async listPolicies(): Promise<{ policies: unknown[] }> {
    if (!this.http) throw new Error('listPolicies requires API mode');
    return this.http.get('/v2/policies');
  }

  /**
   * Activate a policy (API mode only).
   */
  async activatePolicy(policyId: string): Promise<{ ok: boolean }> {
    if (!this.http) throw new Error('activatePolicy requires API mode');
    return this.http.post(`/v2/policies/${policyId}/activate`, {});
  }

  async health(): Promise<HealthResponse> {
    if (!this.http) {
      throw new Error('health() requires API mode or an apiKey');
    }
    return this.http.get<HealthResponse>('/v2/health');
  }

  private localCheck(type: ActionType, value: string, metadata?: Record<string, unknown>): CheckResult {
    const input = { type, value, metadata };

    // Build context from session if available
    const context = this.sessionTracker && this.sessionId
      ? this.sessionTracker.buildContext(this.sessionId)
      : undefined;

    let result = this.engine!.check(input, context);

    // Record in session tracker
    if (this.sessionTracker && this.sessionId) {
      const sessionResult = this.sessionTracker.recordAction(this.sessionId, input, result, this.agentId);
      if (sessionResult.chainDetections.length > 0) {
        result = { ...result, chainDetections: sessionResult.chainDetections, riskTrend: sessionResult.riskTrend };
      }
    }

    // Rich policy evaluation (takes precedence)
    if (this.policyEngine) {
      const decision = this.policyEngine.evaluate(input, result);
      if (!decision.allowed) {
        throw new NotAllowedError(result);
      }
      return result;
    }

    this.enforcePolicy(result);
    this.reportTelemetryIfEnabled(type, value, result);
    return result;
  }

  private async apiCheck(path: string, body: Record<string, unknown>): Promise<CheckResult> {
    // Add session/agent context to API requests
    if (this.sessionId) body.sessionId = this.sessionId;
    if (this.agentId) body.agentId = this.agentId;

    const result = await this.http!.post<CheckResult>(path, body);
    this.enforcePolicy(result);
    // Telemetry for API mode — extract type/value from body for hashing
    if (this.telemetryEnabled && this.http) {
      const actionType = (body.type ?? body.url ? 'url' : body.command ? 'command' : body.text ? 'text' : 'unknown') as string;
      const value = (body.value ?? body.url ?? body.command ?? body.text ?? body.path ?? body.query ?? body.code ?? body.action ?? body.body ?? body.description ?? '') as string;
      void reportTelemetry(this.http, actionType, value, result, SDK_VERSION);
    }
    return result;
  }

  /**
   * Assess an agent profile against the EU AI Act compliance framework.
   * API mode only — calls POST /v2/compliance/assess.
   */
  async assessCompliance(profile: AgentProfile): Promise<ComplianceReport> {
    if (!this.http) {
      throw new Error('assessCompliance requires API mode');
    }
    return this.http.post<ComplianceReport>('/v2/compliance/assess', { agentProfile: profile });
  }

  private reportTelemetryIfEnabled(type: ActionType, value: string, result: CheckResult): void {
    if (!this.telemetryEnabled || !this.http) return;
    void reportTelemetry(this.http, type, value, result, SDK_VERSION);
  }

  private enforcePolicy(result: CheckResult): void {
    if (this.policy === 'permissive') return;

    if (this.policy === 'moderate' && result.level === 'DANGER') {
      throw new NotAllowedError(result);
    }

    if (this.policy === 'strict' && (result.level === 'CAUTION' || result.level === 'DANGER')) {
      throw new NotAllowedError(result);
    }
  }
}

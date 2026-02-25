import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Guard } from '../src/guard.js';
import { AuthenticationError, RateLimitError, APIError, NotAllowedError } from '../src/errors.js';
import type { CheckResult } from '@surfinguard/types';

const SAFE_RESULT: CheckResult = {
  allow: true,
  score: 0,
  level: 'SAFE',
  primitive: null,
  primitiveScores: [],
  reasons: [],
  latencyMs: 1,
};

const DANGER_RESULT: CheckResult = {
  allow: false,
  score: 9,
  level: 'DANGER',
  primitive: 'DESTRUCTION',
  primitiveScores: [{ primitive: 'DESTRUCTION', score: 9, reasons: ['Destructive'] }],
  reasons: ['Destructive operation'],
  latencyMs: 1,
};

const CAUTION_RESULT: CheckResult = {
  allow: true,
  score: 5,
  level: 'CAUTION',
  primitive: 'ESCALATION',
  primitiveScores: [{ primitive: 'ESCALATION', score: 5, reasons: ['Privilege escalation'] }],
  reasons: ['Potential escalation'],
  latencyMs: 1,
};

function mockFetch(response: unknown, status = 200, headers: Record<string, string> = {}) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(response),
    headers: new Map(Object.entries(headers)),
  } as unknown as Response);
}

describe('Guard (API mode)', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('throws if apiKey not provided for API mode', () => {
    expect(() => new Guard({ mode: 'api' })).toThrow('apiKey is required for API mode');
  });

  it('checkUrl calls /v2/check/url', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkUrl('https://google.com');

    expect(result.level).toBe('SAFE');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/url');
    expect(JSON.parse(init.body as string)).toEqual({ url: 'https://google.com' });
  });

  it('checkCommand calls /v2/check/command', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkCommand('ls -la');

    expect(result.level).toBe('SAFE');
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/command');
  });

  it('checkText calls /v2/check/text', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkText('hello');

    expect(result.level).toBe('SAFE');
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/text');
  });

  it('checkFileRead calls /v2/check/file with read', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    await guard.checkFileRead('/tmp/test.txt');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toEqual({ path: '/tmp/test.txt', operation: 'read' });
  });

  it('checkFileWrite calls /v2/check/file with write + content', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    await guard.checkFileWrite('/tmp/test.txt', 'data');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toEqual({ path: '/tmp/test.txt', operation: 'write', content: 'data' });
  });

  it('checkApiCall calls /v2/check/api-call', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkApiCall('https://api.example.com/health', 'GET');

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/api-call');
    expect(JSON.parse(init.body as string)).toEqual({ url: 'https://api.example.com/health', method: 'GET' });
  });

  it('checkApiCall sends headers and body', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    await guard.checkApiCall('https://api.example.com', 'POST', { Authorization: 'Bearer xyz' }, '{"data": 1}');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.url).toBe('https://api.example.com');
    expect(body.method).toBe('POST');
    expect(body.headers).toEqual({ Authorization: 'Bearer xyz' });
    expect(body.body).toBe('{"data": 1}');
  });

  it('checkQuery calls /v2/check/query', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkQuery('SELECT 1');

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/query');
    expect(JSON.parse(init.body as string)).toEqual({ query: 'SELECT 1' });
  });

  it('checkCode calls /v2/check/code', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkCode("print('hi')", 'python');

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/code');
    expect(JSON.parse(init.body as string)).toEqual({ code: "print('hi')", language: 'python' });
  });

  it('checkMessage calls /v2/check/message', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkMessage('notification: done', { channel: 'log' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/message');
    expect(JSON.parse(init.body as string)).toEqual({ body: 'notification: done', channel: 'log' });
  });

  it('checkTransaction calls /v2/check/transaction', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkTransaction('check balance', { amount: 100, currency: 'USD' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/transaction');
    expect(JSON.parse(init.body as string)).toEqual({ description: 'check balance', amount: 100, currency: 'USD' });
  });

  it('checkAuth calls /v2/check/auth', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkAuth('login', { role: 'user' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/auth');
    expect(JSON.parse(init.body as string)).toEqual({ action: 'login', role: 'user' });
  });

  it('checkAuth without metadata sends only action', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    await guard.checkAuth('logout');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toEqual({ action: 'logout' });
  });

  it('checkGit calls /v2/check/git', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkGit('git status', { branch: 'main' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/git');
    expect(JSON.parse(init.body as string)).toEqual({ command: 'git status', branch: 'main' });
  });

  it('checkUiAction calls /v2/check/ui-action', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkUiAction('navigate to page', { element: 'button' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/ui-action');
    expect(JSON.parse(init.body as string)).toEqual({ action: 'navigate to page', element: 'button' });
  });

  it('checkInfra calls /v2/check/infra', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkInfra('terraform plan', { environment: 'staging' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/infra');
    expect(JSON.parse(init.body as string)).toEqual({ action: 'terraform plan', environment: 'staging' });
  });

  it('checkAgentComm calls /v2/check/agent-comm', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkAgentComm('list agents', { agent_id: 'a1', target_agent: 'a2', tool: 'file_write' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/agent-comm');
    expect(JSON.parse(init.body as string)).toEqual({ action: 'list agents', agent_id: 'a1', target_agent: 'a2', tool: 'file_write' });
  });

  it('checkDataPipeline calls /v2/check/data-pipeline', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkDataPipeline('describe model', { operation: 'deploy', dataset: 'training', model: 'gpt' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/data-pipeline');
    expect(JSON.parse(init.body as string)).toEqual({ action: 'describe model', operation: 'deploy', dataset: 'training', model: 'gpt' });
  });

  it('checkDocument calls /v2/check/document', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkDocument('read file', { operation: 'view', content: 'text', recipient: 'user@example.com' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/document');
    expect(JSON.parse(init.body as string)).toEqual({ action: 'read file', operation: 'view', content: 'text', recipient: 'user@example.com' });
  });

  it('checkIot calls /v2/check/iot', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    const result = await guard.checkIot('read sensor', { device_type: 'thermostat', device_id: 'dev-001', resource: 'temperature' });

    expect(result.level).toBe('SAFE');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.surfinguard.com/v2/check/iot');
    expect(JSON.parse(init.body as string)).toEqual({ command: 'read sensor', device_type: 'thermostat', device_id: 'dev-001', resource: 'temperature' });
  });

  it('check calls /v2/check with type and value', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc123', policy: 'permissive' });
    await guard.check('url', 'https://google.com');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toEqual({ type: 'url', value: 'https://google.com' });
  });

  it('sends Authorization Bearer header', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_mykey123', policy: 'permissive' });
    await guard.checkUrl('https://google.com');

    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers.Authorization).toBe('Bearer sg_test_mykey123');
  });

  it('uses custom baseUrl', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc', baseUrl: 'https://custom.api.com', policy: 'permissive' });
    await guard.checkUrl('https://google.com');

    expect(fetchMock.mock.calls[0][0]).toBe('https://custom.api.com/v2/check/url');
  });

  it('returns async results in API mode', async () => {
    const fetchMock = mockFetch(SAFE_RESULT);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc', policy: 'permissive' });
    const result = guard.checkUrl('https://google.com');
    expect(result).toBeInstanceOf(Promise);
  });

  // ── Error mapping ──────────────────────────────────────────────

  it('throws AuthenticationError on 401', async () => {
    globalThis.fetch = mockFetch({ error: 'Invalid API key' }, 401);

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_bad', policy: 'permissive' });
    await expect(guard.checkUrl('https://google.com')).rejects.toThrow(AuthenticationError);
  });

  it('throws RateLimitError on 429', async () => {
    globalThis.fetch = mockFetch({ error: 'Rate limit exceeded' }, 429, { 'Retry-After': '60' });

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_bad', policy: 'permissive' });
    await expect(guard.checkUrl('https://google.com')).rejects.toThrow(RateLimitError);
  });

  it('throws APIError on 500', async () => {
    globalThis.fetch = mockFetch({ error: 'Internal error' }, 500);

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_bad', policy: 'permissive' });
    await expect(guard.checkUrl('https://google.com')).rejects.toThrow(APIError);
  });

  it('throws APIError on timeout', async () => {
    globalThis.fetch = vi.fn().mockImplementation(() =>
      new Promise((_, reject) => {
        const err = new DOMException('The operation was aborted', 'AbortError');
        setTimeout(() => reject(err), 10);
      }),
    );

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc', timeout: 5, policy: 'permissive' });
    await expect(guard.checkUrl('https://google.com')).rejects.toThrow(APIError);
  });

  // ── Policy enforcement in API mode ─────────────────────────────

  it('moderate policy blocks DANGER from API', async () => {
    globalThis.fetch = mockFetch(DANGER_RESULT);

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc', policy: 'moderate' });
    await expect(guard.checkUrl('https://evil.com')).rejects.toThrow(NotAllowedError);
  });

  it('moderate policy allows CAUTION from API', async () => {
    globalThis.fetch = mockFetch(CAUTION_RESULT);

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc', policy: 'moderate' });
    const result = await guard.checkUrl('https://suspicious.com');
    expect(result.level).toBe('CAUTION');
  });

  it('strict policy blocks CAUTION from API', async () => {
    globalThis.fetch = mockFetch(CAUTION_RESULT);

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc', policy: 'strict' });
    await expect(guard.checkUrl('https://suspicious.com')).rejects.toThrow(NotAllowedError);
  });

  // ── health() ───────────────────────────────────────────────────

  it('health() calls /v2/health', async () => {
    const healthResp = { ok: true, version: '2.3.0', analyzers: ['url'], auth: false, llm: false, uptime: 10 };
    const fetchMock = mockFetch(healthResp);
    globalThis.fetch = fetchMock;

    const guard = new Guard({ mode: 'api', apiKey: 'sg_test_abc', policy: 'permissive' });
    const result = await guard.health();

    expect(result.ok).toBe(true);
    expect(result.version).toBe('2.3.0');
    expect(fetchMock.mock.calls[0][0]).toContain('/v2/health');
  });

  it('health() throws if no API client', async () => {
    const guard = new Guard({ mode: 'local' });
    await expect(() => guard.health()).rejects.toThrow('health() requires API mode or an apiKey');
  });
});

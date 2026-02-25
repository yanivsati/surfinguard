import type { CheckResult } from '@surfinguard/types';

export class SurfinguardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SurfinguardError';
  }
}

export class AuthenticationError extends SurfinguardError {
  constructor(message = 'Authentication failed') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends SurfinguardError {
  retryAfter: number | null;

  constructor(message = 'Rate limit exceeded', retryAfter: number | null = null) {
    super(message);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class APIError extends SurfinguardError {
  statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = 'APIError';
    this.statusCode = statusCode;
  }
}

export class NotAllowedError extends SurfinguardError {
  result: CheckResult;

  constructor(result: CheckResult) {
    super(`Action blocked: ${result.level} (score=${result.score})`);
    this.name = 'NotAllowedError';
    this.result = result;
  }
}

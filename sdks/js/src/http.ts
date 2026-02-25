import { AuthenticationError, RateLimitError, APIError } from './errors.js';

export class SurfinguardHTTPClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;

  constructor(baseUrl: string, apiKey: string, timeout: number) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.timeout = timeout;
  }

  async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  async put<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('PUT', path, body);
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const headers: Record<string, string> = {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      };

      const init: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      if (body !== undefined) {
        init.body = JSON.stringify(body);
      }

      const response = await fetch(url, init);

      if (!response.ok) {
        await this.handleError(response);
      }

      return await response.json() as T;
    } catch (error) {
      if (error instanceof SurfinguardHTTPClient) {
        throw error;
      }
      if (error instanceof AuthenticationError || error instanceof RateLimitError || error instanceof APIError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new APIError(`Request timed out after ${this.timeout}ms`, 408);
      }
      throw new APIError(`Network error: ${(error as Error).message}`, 0);
    } finally {
      clearTimeout(timer);
    }
  }

  private async handleError(response: Response): Promise<never> {
    let message: string;
    try {
      const body = await response.json() as { error?: string };
      message = body.error ?? response.statusText;
    } catch {
      message = response.statusText;
    }

    switch (response.status) {
      case 401:
        throw new AuthenticationError(message);
      case 429: {
        const retryAfter = response.headers.get('Retry-After');
        throw new RateLimitError(message, retryAfter ? parseInt(retryAfter, 10) : null);
      }
      default:
        throw new APIError(message, response.status);
    }
  }
}

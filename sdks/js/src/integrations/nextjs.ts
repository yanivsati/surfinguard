import type { CheckResult } from '@surfinguard/types';
import type { Guard } from '../guard.js';

type NextApiRequest = {
  body?: unknown;
  method?: string;
  url?: string;
};

type NextApiResponse = {
  status(code: number): NextApiResponse;
  json(body: unknown): void;
};

type NextApiHandler = (req: NextApiRequest, res: NextApiResponse) => Promise<void> | void;

export interface WithSurfinguardOptions {
  actionType?: string;
  extractValue?: (req: NextApiRequest) => string | null;
}

export function withSurfinguard(
  guard: Guard,
  handler: NextApiHandler,
  options: WithSurfinguardOptions = {},
): NextApiHandler {
  return async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
    const value = options.extractValue
      ? options.extractValue(req)
      : inferValue(req);

    if (!value) {
      return handler(req, res);
    }

    const type = options.actionType ?? inferType(req);

    try {
      const result = await guard.check(type, value);
      (req as NextApiRequest & { surfinguard?: CheckResult }).surfinguard = result;
      return handler(req, res);
    } catch (error: unknown) {
      if (error && typeof error === 'object' && 'result' in error) {
        const notAllowed = error as { result: CheckResult };
        res.status(403).json({
          error: 'Blocked by Surfinguard',
          level: notAllowed.result.level,
          score: notAllowed.result.score,
          reasons: notAllowed.result.reasons,
        });
        return;
      }
      throw error;
    }
  };
}

function inferValue(req: NextApiRequest): string | null {
  const body = req.body as Record<string, unknown> | undefined;
  if (!body) return null;
  if (typeof body.url === 'string') return body.url;
  if (typeof body.command === 'string') return body.command;
  if (typeof body.text === 'string') return body.text;
  return null;
}

function inferType(req: NextApiRequest): string {
  const body = req.body as Record<string, unknown> | undefined;
  if (!body) return 'url';
  if (typeof body.url === 'string') return 'url';
  if (typeof body.command === 'string') return 'command';
  if (typeof body.text === 'string') return 'text';
  return 'url';
}

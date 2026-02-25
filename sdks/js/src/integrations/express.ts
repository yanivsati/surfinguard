import type { Request, Response, NextFunction } from 'express';
import type { CheckResult } from '@surfinguard/types';
import type { Guard } from '../guard.js';

export interface MiddlewareOptions {
  guard: Guard;
  actionType?: string;
  extractValue?: (req: Request) => string | null;
  onBlocked?: (req: Request, res: Response, result: CheckResult) => void;
}

export function surfinguardMiddleware(options: MiddlewareOptions) {
  const { guard, actionType, extractValue, onBlocked } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const value = extractValue ? extractValue(req) : inferValue(req);

    if (!value) {
      next();
      return;
    }

    const type = actionType ?? inferType(req);

    try {
      const result = await guard.check(type, value);
      (req as Request & { surfinguard?: CheckResult }).surfinguard = result;
      next();
    } catch (error: unknown) {
      if (error && typeof error === 'object' && 'result' in error) {
        const notAllowed = error as { result: CheckResult };
        if (onBlocked) {
          onBlocked(req, res, notAllowed.result);
        } else {
          res.status(403).json({
            error: 'Blocked by Surfinguard',
            level: notAllowed.result.level,
            score: notAllowed.result.score,
            reasons: notAllowed.result.reasons,
          });
        }
        return;
      }
      next(error);
    }
  };
}

function inferValue(req: Request): string | null {
  const body = req.body as Record<string, unknown> | undefined;
  if (!body) return null;
  if (typeof body.url === 'string') return body.url;
  if (typeof body.command === 'string') return body.command;
  if (typeof body.text === 'string') return body.text;
  return null;
}

function inferType(req: Request): string {
  const body = req.body as Record<string, unknown> | undefined;
  if (!body) return 'url';
  if (typeof body.url === 'string') return 'url';
  if (typeof body.command === 'string') return 'command';
  if (typeof body.text === 'string') return 'text';
  return 'url';
}

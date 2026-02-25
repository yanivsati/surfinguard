/**
 * Telemetry module — opt-in anonymized check result reporting.
 * Values are hashed client-side (SHA-256) before being sent; plaintext never reaches the server.
 */
import type { CheckResult } from '@surfinguard/types';
import { SurfinguardHTTPClient } from './http.js';

/**
 * SHA-256 hash a string and return hex representation.
 * Works in both Node.js and browser (via Web Crypto API).
 */
async function sha256(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Report a check result as anonymized telemetry.
 * Fire-and-forget: errors are silently swallowed.
 */
export async function reportTelemetry(
  http: SurfinguardHTTPClient,
  actionType: string,
  value: string,
  result: CheckResult,
  sdkVersion: string,
): Promise<void> {
  try {
    const valueHash = await sha256(value);

    await http.post('/v2/telemetry', {
      action_type: actionType,
      value_hash: valueHash,
      score: result.score,
      level: result.level,
      primitive: result.primitiveScores?.[0]?.primitive ?? null,
      reasons: result.reasons?.slice(0, 5) ?? [],
      threat_ids: [],
      sdk_version: sdkVersion,
    });
  } catch {
    // Fire-and-forget: telemetry errors should never block the main flow
  }
}

export { sha256 };

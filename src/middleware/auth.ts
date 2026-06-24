// =============================================================================
// THE INDEPENDENCE LAW FIRM — API AUTH GUARD
// src/middleware/auth.ts
//
// Every route that touches client data MUST be protected by this middleware.
//
// Verification flow:
//   1. Extract the Authorization header from the incoming request.
//   2. Confirm it is a Bearer token scheme.
//   3. Compare the token against API_BEARER_TOKEN using a timing-safe check
//      to prevent timing-based token enumeration attacks.
//   4. On any failure → 401. No details about why it failed are returned.
//   5. On success → call next() and let the route handler proceed.
//
// Usage:
//   import { requireBearerToken } from '../middleware/auth';
//   router.post('/clients', requireBearerToken, handler);
// =============================================================================

import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

/**
 * Compares two strings in constant time to prevent timing-based attacks.
 * Returns true only if both strings are identical in length and content.
 */
function timingSafeEqual(a: string, b: string): boolean {
  // If lengths differ, pad the shorter string so the crypto comparison
  // runs to completion rather than short-circuiting on length.
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);

  if (aBuf.length !== bBuf.length) {
    // Always run the comparison on the expected token to prevent
    // a length-based timing oracle.
    crypto.timingSafeEqual(aBuf, aBuf);
    return false;
  }

  return crypto.timingSafeEqual(aBuf, bBuf);
}

/**
 * Express middleware that enforces Bearer token authentication.
 *
 * Reads API_BEARER_TOKEN from process.env. The server startup sequence in
 * server.ts already validates this env var is present, so we can safely
 * cast it here.
 */
export function requireBearerToken(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const expectedToken = process.env.API_BEARER_TOKEN as string;

  const authHeader = req.headers['authorization'];

  // ── Missing header ─────────────────────────────────────────────────────────
  if (!authHeader) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // ── Wrong scheme ──────────────────────────────────────────────────────────
  if (!authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const providedToken = authHeader.slice('Bearer '.length);

  // ── Empty token ───────────────────────────────────────────────────────────
  if (!providedToken) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // ── Timing-safe comparison ────────────────────────────────────────────────
  if (!timingSafeEqual(providedToken, expectedToken)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // ── Authenticated — pass to route handler ─────────────────────────────────
  next();
}

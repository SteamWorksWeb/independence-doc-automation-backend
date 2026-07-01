// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENT JWT MIDDLEWARE
// src/middleware/clientJwt.ts
//
// Protects client-facing API routes (intake, dashboard data, etc.)
//
// Verification flow:
//   1. Extract Authorization: Bearer <token> header
//   2. Verify JWT signature using JWT_SECRET
//   3. Assert payload.role === 'client' — lawyer tokens cannot access client routes
//   4. Attach clientId (payload.sub) to req for use in route handlers
//   5. On any failure → 401. Generic error — no detail about why.
//
// Usage:
//   import { requireClientJwt } from '../middleware/clientJwt';
//   router.post('/intake', requireClientJwt, handler);
//
// The clientId is available downstream as:
//   (req as ClientRequest).clientId
// =============================================================================

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// ── Extend Express Request to carry the authenticated clientId ────────────────
export interface ClientRequest extends Request {
  clientId: string;
}

interface ClientJwtPayload {
  sub:  string;   // clientId
  role: string;   // must be 'client'
  iat?: number;
  exp?: number;
}

/**
 * Express middleware that verifies a client's JWT and attaches their ID
 * to the request object for downstream route handlers.
 */
export function requireClientJwt(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers['authorization'];

  // ── Missing or malformed header ───────────────────────────────────────────
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const token = authHeader.slice('Bearer '.length).trim();

  if (!token) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // ── Verify JWT ────────────────────────────────────────────────────────────
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('[clientJwt] JWT_SECRET is not configured');
    res.status(500).json({ error: 'Server configuration error' });
    return;
  }

  let payload: ClientJwtPayload;
  try {
    payload = jwt.verify(token, jwtSecret) as ClientJwtPayload;
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // ── Role assertion — lawyer tokens cannot access client routes ────────────
  if (payload.role !== 'client') {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  // ── Attach clientId for downstream handlers ───────────────────────────────
  (req as ClientRequest).clientId = payload.sub;

  next();
}

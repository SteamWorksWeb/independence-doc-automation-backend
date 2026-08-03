// =============================================================================
// THE INDEPENDENCE LAW FIRM — ADMIN AUTH MIDDLEWARE
// src/middleware/adminAuth.ts
//
// Exports:
//   requireLawyerJwt   — verifies any valid lawyer JWT.
//   requireSuperAdmin  — extends requireLawyerJwt; additionally asserts that
//                        the authenticated lawyer carries role/adminRole:
//                        'SUPER_ADMIN'.
//
// Flow for requireSuperAdmin:
//   1. Extract & verify Bearer JWT (same as requireLawyerJwt).
//   2. Assert payload carries a staff RBAC role → 403 if not.
//   3. Assert RBAC role === 'SUPER_ADMIN' → 403 Insufficient Permissions.
//   4. Attach lawyerId + adminRole to request and call next().
//
// Usage:
//   import { requireSuperAdmin } from '../middleware/adminAuth';
//   router.get('/staff', requireSuperAdmin, handler);
// =============================================================================

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// ── Augmented request types ───────────────────────────────────────────────────

export interface LawyerRequest extends Request {
  lawyerId:  string;
  adminRole: string; // 'SUPER_ADMIN' | 'LAWYER'
}

interface LawyerJwtPayload {
  sub:        string; // lawyerId
  role:       string; // 'SUPER_ADMIN' | 'LAWYER' on current tokens; 'lawyer' on legacy tokens
  adminRole?: string; // 'SUPER_ADMIN' | 'LAWYER' — present on tokens issued after RBAC migration
  email?:     string;
  iat?:       number;
  exp?:       number;
}

function getAdminRole(payload: LawyerJwtPayload): string | null {
  if (payload.role === 'SUPER_ADMIN' || payload.role === 'LAWYER') {
    return payload.role;
  }

  if (payload.adminRole === 'SUPER_ADMIN' || payload.adminRole === 'LAWYER') {
    return payload.adminRole;
  }

  return null;
}

// ── Shared JWT verification helper ────────────────────────────────────────────

function verifyLawyerToken(
  req:  Request,
  res:  Response,
): LawyerJwtPayload | null {
  const authHeader = req.headers['authorization'];

  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }

  const token = authHeader.slice('Bearer '.length).trim();
  if (!token) {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }

  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('[adminAuth] JWT_SECRET is not configured');
    res.status(500).json({ error: 'Server configuration error' });
    return null;
  }

  let payload: LawyerJwtPayload;
  try {
    payload = jwt.verify(token, jwtSecret) as LawyerJwtPayload;
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }

  if (!getAdminRole(payload)) {
    res.status(403).json({ error: 'Forbidden' });
    return null;
  }

  return payload;
}

// =============================================================================
// MIDDLEWARE: requireLawyerJwt
//
// Accepts any valid lawyer JWT regardless of adminRole.
// Equivalent to the inline requireLawyerJwt in admin.ts — re-exported here
// for use by new modular routers that import from middleware instead of admin.ts.
// =============================================================================

export function requireLawyerJwt(
  req:  Request,
  res:  Response,
  next: NextFunction,
): void {
  const payload = verifyLawyerToken(req, res);
  if (!payload) return;

  (req as LawyerRequest).lawyerId  = payload.sub;
  (req as LawyerRequest).adminRole = getAdminRole(payload) ?? 'LAWYER';

  next();
}

// =============================================================================
// MIDDLEWARE: requireSuperAdmin
//
// Extends the standard lawyer JWT check with an RBAC assertion.
// Only lawyers whose JWT carries role/adminRole === 'SUPER_ADMIN' may proceed.
//
// On failure:
//   401 — Missing, malformed, or expired token
//   403 — Valid token, wrong role or insufficient RBAC level
// =============================================================================

export function requireSuperAdmin(
  req:  Request,
  res:  Response,
  next: NextFunction,
): void {
  const payload = verifyLawyerToken(req, res);
  if (!payload) return;

  // ── RBAC check — must be SUPER_ADMIN ──────────────────────────────────────
  const adminRole = getAdminRole(payload);
  if (adminRole !== 'SUPER_ADMIN') {
    res.status(403).json({ error: 'Forbidden: Insufficient Permissions' });
    return;
  }

  (req as LawyerRequest).lawyerId  = payload.sub;
  (req as LawyerRequest).adminRole = adminRole;

  next();
}

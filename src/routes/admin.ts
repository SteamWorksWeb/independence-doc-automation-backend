// =============================================================================
// THE INDEPENDENCE LAW FIRM — ADMIN ROUTER
// src/routes/admin.ts
//
// Mounted at: /api/v1/admin  (see server.ts)
//
// Routes:
//   GET /api/v1/admin/clients — Fetch all clients (lawyer-only)
//
// Security model:
//   - Protected by requireLawyerJwt middleware.
//   - Only JWTs with role: 'lawyer' are accepted; all others receive 403.
//   - Password hashes are NEVER returned — fields are explicitly selected.
//   - The intakeProfile is included so the dashboard can flag whether a
//     client has started or completed the DOJ questionnaire.
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

// ── Prisma client singleton ───────────────────────────────────────────────────
let _prisma: PrismaClient | null = null;

function getPrisma(): PrismaClient {
  if (!_prisma) {
    const pool    = new Pool({ connectionString: process.env.DATABASE_URL as string });
    const adapter = new PrismaPg(pool);
    _prisma = new PrismaClient({ adapter });
  }
  return _prisma;
}

// ── Extend Express Request to carry the authenticated lawyerId ────────────────
export interface LawyerRequest extends Request {
  lawyerId: string;
}

interface LawyerJwtPayload {
  sub:  string;   // lawyerId
  role: string;   // must be 'lawyer'
  iat?: number;
  exp?: number;
}

// =============================================================================
// MIDDLEWARE: requireLawyerJwt
//
// Verifies the incoming Bearer JWT and asserts role === 'lawyer'.
// Attaches lawyerId (payload.sub) to the request for downstream use.
//
// On failure:
//   401 — Missing, malformed, or expired token
//   403 — Valid token but role is not 'lawyer'
// =============================================================================

function requireLawyerJwt(
  req:  Request,
  res:  Response,
  next: NextFunction
): void {
  const authHeader = req.headers['authorization'];

  // ── Missing or malformed header ─────────────────────────────────────────────
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const token = authHeader.slice('Bearer '.length).trim();

  if (!token) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // ── Verify JWT signature ──────────────────────────────────────────────────
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('[admin] JWT_SECRET is not configured');
    res.status(500).json({ error: 'Server configuration error' });
    return;
  }

  let payload: LawyerJwtPayload;
  try {
    payload = jwt.verify(token, jwtSecret) as LawyerJwtPayload;
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // ── Role assertion — only lawyer tokens may access admin routes ──────────
  if (payload.role !== 'lawyer') {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  // ── Attach lawyerId for downstream handlers ───────────────────────────────
  (req as LawyerRequest).lawyerId = payload.sub;

  next();
}

// ── Router ───────────────────────────────────────────────────────────────────
const router = Router();

// Apply the lawyer JWT guard to every route in this router.
router.use(requireLawyerJwt);

// =============================================================================
// GET /api/v1/admin/clients
//
// Returns the full client roster for the authenticated lawyer's dashboard.
// Password hashes are explicitly excluded via Prisma `select`.
// The intakeProfile relation is included to surface intake completion status.
//
// Responses:
//   200  { clients: Client[] }
//         — Array of client records with intake profile (may be null if the
//           client has not yet started the intake questionnaire)
//   401  { error: string }   — Missing or invalid JWT
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.get(
  '/clients',
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma  = getPrisma();

      const clients = await prisma.client.findMany({
        select: {
          id:          true,
          email:       true,
          isVerified:  true,
          createdAt:   true,
          // Include the full intakeProfile so the dashboard can determine
          // whether the client has started or completed the DOJ questionnaire.
          intakeProfile: true,
        },
        orderBy: { createdAt: 'desc' },
      });

      res.status(200).json({ clients });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/clients/:id
//
// Returns the complete 360° profile for a single client, including every field
// of their DOJ intake questionnaire (intakeProfile relation).
//
// Path param:
//   :id — the client's UUID (from the roster table)
//
// Responses:
//   200  { client: Client & { intakeProfile: IntakeProfile | null } }
//         — Full client record. intakeProfile is null if the client has not
//           yet begun the intake questionnaire.
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   404  { error: string }   — No client found for the given id
//   500  { error: string }   — Global error handler
// =============================================================================

router.get(
  '/clients/:id',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      // String() cast: Express types params as string | string[]; Prisma
      // where clause requires a plain string. The cast is safe because
      // Express always resolves named route params to a single string value.
      const clientId = String(req.params.id);

      const client = await prisma.client.findUnique({
        where: { id: clientId },
        select: {
          id:         true,
          email:      true,
          isVerified: true,
          createdAt:  true,
          // Include the full intakeProfile — every DOJ questionnaire field
          // is returned so the frontend tabbed interface can display them
          // without a second round-trip.
          intakeProfile: true,
        },
      });

      if (!client) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      res.status(200).json({ client });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

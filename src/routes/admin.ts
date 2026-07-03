// =============================================================================
// THE INDEPENDENCE LAW FIRM — ADMIN ROUTER
// src/routes/admin.ts
//
// Mounted at: /api/v1/admin  (see server.ts)
//
// Routes:
//   GET    /api/v1/admin/clients              — Fetch all clients (lawyer-only)
//   GET    /api/v1/admin/clients/:id          — Fetch single client detail
//   GET    /api/v1/admin/clients/:id/eligibility — Brunner eligibility analysis
//   POST   /api/v1/admin/invites              — Create client invitation
//   GET    /api/v1/admin/invites              — List pending invitations
//   DELETE /api/v1/admin/invites/:id          — Revoke a pending invitation
// Security model:
//   - Protected by requireLawyerJwt middleware.
//   - Only JWTs with role: 'lawyer' are accepted; all others receive 403.
//   - Password hashes are NEVER returned — fields are explicitly selected.
//   - The intakeProfile is included so the dashboard can flag whether a
//     client has started or completed the DOJ questionnaire.
// =============================================================================

import crypto from 'crypto';
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

// =============================================================================
// GET /api/v1/admin/clients/:id/eligibility
//
// Runs the Brunner Test undue-hardship algorithm against a client's DOJ
// Intake Profile and returns a scored eligibility analysis.
//
// The Brunner Test (11 U.S.C. § 523(a)(8)) has two prongs relevant to the
// "14% eligibility" pre-screening:
//
//   Prong 1 — Minimal Standard of Living (Poverty)
//     Checks whether disposable income after essential expenses leaves the
//     debtor unable to maintain even a minimal standard of living.
//     Threshold: disposableIncome <= $150/mo  (buffer for incidentals).
//
//   Prong 2 — Persistence (Good Faith Future Prospect)
//     Checks whether the hardship is expected to persist for a significant
//     portion of the repayment period.
//     Met IF: hasDisability === true  OR  unemployed5of10 === true.
//
//   Overall Score:
//     Both prongs met  → HIGH_PROBABILITY
//     One prong met    → MEDIUM_PROBABILITY
//     Neither met      → LOW_PROBABILITY
//
// Path param:
//   :id — the client's UUID
//
// Responses:
//   200  { client_id, analysis: { totalExpenses, disposableIncome,
//           isProng1Met, isProng2Met, overallScore } }
//   401  { error: string }   — Missing or invalid JWT
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   404  { error: string }   — No client found for the given id
//   422  { error: string }   — Client has no intake profile yet
//   500  { error: string }   — Global error handler
// =============================================================================

router.get(
  '/clients/:id/eligibility',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);

      // ── Fetch client with intake profile ──────────────────────────────────
      const client = await prisma.client.findUnique({
        where: { id: clientId },
        include: { intakeProfile: true },
      });

      if (!client) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      const profile = client.intakeProfile;

      if (!profile) {
        res.status(422).json({
          error: 'Client has not yet completed an intake profile. Eligibility cannot be determined.',
        });
        return;
      }

      // ── Brunner Algorithm ─────────────────────────────────────────────────

      // Helper: treat null/undefined expense fields as $0 (partial saves are
      // supported; missing fields mean the expense does not apply).
      const toNum = (v: number | null | undefined): number => v ?? 0;

      // Prong 1 — Poverty / Minimal Standard of Living
      const totalExpenses: number =
        toNum(profile.expFood)         +
        toNum(profile.expHousekeeping) +
        toNum(profile.expApparel)      +
        toNum(profile.expPersonalCare) +
        toNum(profile.expHousing)      +
        toNum(profile.expUtilities)    +
        toNum(profile.expTransportGas) +
        toNum(profile.expCarInsurance);

      const disposableIncome: number = toNum(profile.monthlyIncome) - totalExpenses;

      // $150/mo buffer: even a debtor with modest surplus cannot maintain a
      // minimal standard of living when their margin is this thin.
      const isProng1Met: boolean = disposableIncome <= 150;

      // Prong 2 — Persistence of Hardship
      const isProng2Met: boolean =
        profile.hasDisability === true ||
        profile.unemployed5of10 === true;

      // ── Overall Score ─────────────────────────────────────────────────────
      const prongsMetCount = (isProng1Met ? 1 : 0) + (isProng2Met ? 1 : 0);

      const overallScore =
        prongsMetCount === 2 ? 'HIGH_PROBABILITY'   :
        prongsMetCount === 1 ? 'MEDIUM_PROBABILITY' :
                               'LOW_PROBABILITY';

      // ── Response ──────────────────────────────────────────────────────────
      res.status(200).json({
        client_id: clientId,
        analysis: {
          totalExpenses,
          disposableIncome,
          isProng1Met,
          isProng2Met,
          overallScore,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/admin/invites
//
// Creates a secure invitation for a client to register. Part of the "Velvet
// Rope" system — no open public registration. Only authenticated lawyers can
// invite clients.
//
// Flow:
//   1. Lawyer provides the client's email address
//   2. Backend generates a 32-byte crypto-random token (256 bits of entropy)
//   3. Saves an Invitation record with a 7-day expiry window
//   4. Logs the invite link to the console (email sending is mocked for now)
//   5. Returns the token in the response for frontend testing
//
// Request body (JSON):
//   {
//     email: string  — Client email to invite  (required)
//   }
//
// Responses:
//   201  { invitation: { id, email, token, expiresAt } }  — Invite created
//   400  { error: string }   — Missing or invalid email
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.post(
  '/invites',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email } = req.body as { email?: string };

      // ── Validate email presence ───────────────────────────────────────────
      if (!email?.trim()) {
        res.status(400).json({ error: 'Email address is required' });
        return;
      }

      // ── Validate email format ─────────────────────────────────────────────
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email.trim())) {
        res.status(400).json({ error: 'Invalid email address format' });
        return;
      }

      const normalizedEmail = email.trim().toLowerCase();

      // ── Generate secure token ─────────────────────────────────────────────
      //   32 bytes → 64-char hex string → 256 bits of entropy.
      //   Stored directly in the DB (not hashed) because the token is
      //   single-use and short-lived (7 days). The invite link embeds
      //   this token as a query parameter.
      const token = crypto.randomBytes(32).toString('hex');

      // ── Set expiration: 7 days from now ───────────────────────────────────
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      // ── Persist invitation ────────────────────────────────────────────────
      const prisma     = getPrisma();
      const invitation = await prisma.invitation.create({
        data: {
          email: normalizedEmail,
          token,
          expiresAt,
        },
        select: {
          id:        true,
          email:     true,
          token:     true,
          expiresAt: true,
          createdAt: true,
        },
      });

      // ── Mock email: log invite link to console ────────────────────────────
      const inviteLink = `https://independence-doc-automation.vercel.app/login?token=${token}`;
      console.log(`[admin] 📧 INVITE LINK for ${normalizedEmail}:`);
      console.log(`[admin]    ${inviteLink}`);

      // ── Return invitation (including token for frontend testing) ─────────
      res.status(201).json({
        invitation,
        inviteLink,
      });

    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/invites
//
// Returns all pending (unused) client invitations, ordered newest-first.
// This lets the admin dashboard display outstanding invitations so the lawyer
// can spot typos, resend links, or revoke invitations that are no longer needed.
//
// Responses:
//   200  { invitations: Invitation[] }  — Array of pending invites
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.get(
  '/invites',
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma = getPrisma();

      const invitations = await prisma.invitation.findMany({
        where: { isUsed: false },
        orderBy: { createdAt: 'desc' },
        select: {
          id:        true,
          email:     true,
          token:     true,
          expiresAt: true,
          createdAt: true,
        },
      });

      res.status(200).json({ invitations });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// DELETE /api/v1/admin/invites/:id
//
// Revokes a pending client invitation. Instead of hard-deleting the record
// (which would lose audit history), we instantly invalidate it by:
//   1. Setting expiresAt to the current timestamp (immediately expired)
//   2. Setting isUsed to true (prevents the registration endpoint from
//      accepting the token even if it hasn't technically expired)
//
// This ensures that any outstanding invite link becomes permanently unusable
// while preserving the invitation record for audit/compliance purposes.
//
// Path param:
//   :id — the invitation's UUID
//
// Responses:
//   200  { message: string }   — Invitation successfully revoked
//   404  { error: string }     — No invitation found for the given id
//   401  { error: string }     — Missing or invalid JWT (handled by router.use)
//   403  { error: string }     — Valid JWT but role !== 'lawyer'
//   500  { error: string }     — Global error handler
// =============================================================================

router.delete(
  '/invites/:id',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma       = getPrisma();
      const invitationId = String(req.params.id);

      // ── Verify the invitation exists ──────────────────────────────────────
      const existing = await prisma.invitation.findUnique({
        where: { id: invitationId },
      });

      if (!existing) {
        res.status(404).json({ error: 'Invitation not found.' });
        return;
      }

      // ── Instantly invalidate — soft revoke ────────────────────────────────
      await prisma.invitation.update({
        where: { id: invitationId },
        data: {
          expiresAt: new Date(),   // immediately expired
          isUsed:    true,         // blocks registration flow
        },
      });

      console.log(`[admin] 🚫 Invitation ${invitationId} for ${existing.email} revoked.`);

      res.status(200).json({ message: 'Invitation revoked successfully.' });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

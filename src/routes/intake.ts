// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENT INTAKE ROUTER
// src/routes/intake.ts
//
// Mounted at: /api/v1/intake  (see server.ts)
//
// Routes:
//   POST /api/v1/intake      — Create or update the authenticated client's intake profile
//   GET  /api/v1/intake      — Retrieve the authenticated client's intake profile
//
// Security model:
//   - All routes require a valid Client JWT (requireClientJwt middleware).
//   - The clientId is extracted from the verified JWT — never trusted from the body.
//   - Upsert pattern: safe to call repeatedly as the client completes each step.
//
// Data model:
//   IntakeProfile has a 1-to-1 relationship with Client.
//   All fields are optional — supports partial saves (multi-step form progress).
//   isCompleted: true signals the intake is fully submitted.
// =============================================================================

import { Router, Request as ExpressRequest, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import { requireClientJwt, ClientRequest } from '../middleware/clientJwt';

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

const router = Router();

// =============================================================================
// POST /api/v1/intake
//
// Creates or updates the IntakeProfile for the authenticated client.
// Uses an upsert so the frontend can call this on every step save without
// worrying about whether the profile already exists.
//
// Request body (all fields optional — partial save supported):
//   {
//     phone?:            string
//     address?:          string
//     employmentStatus?: string   — "employed" | "self-employed" | "unemployed" | "retired" | "other"
//     monthlyIncome?:    number
//     totalDebt?:        number
//     studentLoanDebt?:  number
//     loanTypes?:        string   — "Federal" | "Private" | "Both"
//     hardshipNotes?:    string
//     isCompleted?:      boolean  — true when the client submits the final step
//   }
//
// Responses:
//   200  { intakeProfile }        — Upserted successfully
//   400  { error: string }        — Validation error
//   401  { error: 'Unauthorized'} — Missing or invalid client JWT
//   500  { error: string }        — Unexpected server error
// =============================================================================

router.post(
  '/',
  requireClientJwt,
  async (req: ExpressRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as unknown as ClientRequest).clientId;

      const {
        phone,
        address,
        employmentStatus,
        monthlyIncome,
        totalDebt,
        studentLoanDebt,
        loanTypes,
        hardshipNotes,
        isCompleted,
      } = req.body as {
        phone?:            string;
        address?:          string;
        employmentStatus?: string;
        monthlyIncome?:    number;
        totalDebt?:        number;
        studentLoanDebt?:  number;
        loanTypes?:        string;
        hardshipNotes?:    string;
        isCompleted?:      boolean;
      };

      // ── Validate numeric fields ────────────────────────────────────────────
      if (monthlyIncome !== undefined && (typeof monthlyIncome !== 'number' || monthlyIncome < 0)) {
        res.status(400).json({ error: 'monthlyIncome must be a non-negative number' });
        return;
      }
      if (totalDebt !== undefined && (typeof totalDebt !== 'number' || totalDebt < 0)) {
        res.status(400).json({ error: 'totalDebt must be a non-negative number' });
        return;
      }
      if (studentLoanDebt !== undefined && (typeof studentLoanDebt !== 'number' || studentLoanDebt < 0)) {
        res.status(400).json({ error: 'studentLoanDebt must be a non-negative number' });
        return;
      }

      // ── Build update payload (only include defined fields) ─────────────────
      // This allows partial saves — undefined fields are not overwritten.
      const data: Record<string, unknown> = {};
      if (phone            !== undefined) data.phone            = phone;
      if (address          !== undefined) data.address          = address;
      if (employmentStatus !== undefined) data.employmentStatus = employmentStatus;
      if (monthlyIncome    !== undefined) data.monthlyIncome    = monthlyIncome;
      if (totalDebt        !== undefined) data.totalDebt        = totalDebt;
      if (studentLoanDebt  !== undefined) data.studentLoanDebt  = studentLoanDebt;
      if (loanTypes        !== undefined) data.loanTypes        = loanTypes;
      if (hardshipNotes    !== undefined) data.hardshipNotes    = hardshipNotes;
      if (isCompleted      !== undefined) data.isCompleted      = isCompleted;

      // ── Upsert intake profile ──────────────────────────────────────────────
      const prisma = getPrisma();
      const intakeProfile = await prisma.intakeProfile.upsert({
        where:  { clientId },
        create: { clientId, ...data },
        update: data,
      });

      res.status(200).json({ intakeProfile });

    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/intake
//
// Retrieves the authenticated client's current intake profile.
// Returns null if no profile has been started yet.
//
// Responses:
//   200  { intakeProfile }         — Profile found (or null if not started)
//   401  { error: 'Unauthorized' } — Missing or invalid client JWT
//   500  { error: string }         — Unexpected server error
// =============================================================================

router.get(
  '/',
  requireClientJwt,
  async (req: ExpressRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as unknown as ClientRequest).clientId;

      const prisma = getPrisma();
      const intakeProfile = await prisma.intakeProfile.findUnique({
        where: { clientId },
      });

      // Return null if not yet started — frontend uses this to determine
      // whether to show the intake flow or the dashboard
      res.status(200).json({ intakeProfile });

    } catch (err) {
      next(err);
    }
  }
);

export default router;

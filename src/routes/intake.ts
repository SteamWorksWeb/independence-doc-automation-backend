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
    const pool    = new Pool({
      connectionString: process.env.DATABASE_URL as string,
      ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
    });
    const adapter = new PrismaPg(pool);
    _prisma = new PrismaClient({ adapter });
  }
  return _prisma;
}

const router = Router();

// ── Intake payload type ───────────────────────────────────────────────────────
interface IntakePayload {
  // Personal & Household
  dob?:           string;
  ssn?:           string;
  county?:        string;
  phone?:         string;
  address?:       string;
  householdSize?: number;

  // Health & Employment
  hasDisability?:   boolean;
  isEmployed?:      boolean;
  unemployed5of10?: boolean;
  monthlyIncome?:   number;

  // Assets
  housingStatus?:   string;
  hasCar?:          boolean;
  hasRetirement?:   boolean;
  expectingRefund?: boolean;

  // Monthly Expenses
  expFood?:         number;
  expHousekeeping?: number;
  expApparel?:      number;
  expPersonalCare?: number;
  expHousing?:      number;
  expUtilities?:    number;
  expTransportGas?: number;
  expCarInsurance?: number;

  // Education & Debt
  totalDebt?:       number;
  studentLoanDebt?: number;
  schoolsHistory?:  string;

  // Case narrative
  hardshipNotes?:   string;
  unmetBasicNeeds?: string;

  // Completion
  isCompleted?: boolean;
}

// ── Helper: strip undefined fields for partial upsert ─────────────────────────
function definedOnly(payload: IntakePayload): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(payload).filter(([, v]) => v !== undefined)
  );
}

// =============================================================================
// POST /api/v1/intake
//
// Creates or updates the IntakeProfile for the authenticated client.
// Uses an upsert — safe to call on every wizard step save.
//
// Responses:
//   200  { intakeProfile }         — Upserted successfully
//   400  { error: string }         — Validation error
//   401  { error: 'Unauthorized' } — Missing or invalid client JWT
//   500  { error: string }         — Unexpected server error
// =============================================================================

router.post(
  '/',
  requireClientJwt,
  async (req: ExpressRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as unknown as ClientRequest).clientId;
      const body = req.body as IntakePayload;

      // ── Validate numeric fields ────────────────────────────────────────────
      const numericFields = [
        'monthlyIncome', 'expFood', 'expHousekeeping', 'expApparel',
        'expPersonalCare', 'expHousing', 'expUtilities', 'expTransportGas',
        'expCarInsurance', 'totalDebt', 'studentLoanDebt',
      ] as const;

      for (const field of numericFields) {
        const val = body[field];
        if (val !== undefined && (typeof val !== 'number' || val < 0)) {
          res.status(400).json({ error: `${field} must be a non-negative number` });
          return;
        }
      }

      if (
        body.householdSize !== undefined &&
        (typeof body.householdSize !== 'number' || body.householdSize < 0)
      ) {
        res.status(400).json({ error: 'householdSize must be a non-negative integer' });
        return;
      }

      // ── Build data payload — only include defined fields ───────────────────
      const data = definedOnly(body);

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

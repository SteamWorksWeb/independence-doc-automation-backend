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
import { PrismaClient, DischargeSnapshot } from '@prisma/client';
import { requireClientJwt, ClientRequest } from '../middleware/clientJwt';
import { evaluateExpenses, IrsExpenseKey } from '../services/irsStandards';
import { calculateDischargeProbability } from '../utils/dischargeAnalyzer';

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

interface CompleteIntakePayload {
  firstName?: string;
  lastName?: string;
  phone?: string;
  militaryBranch?: string;
  militaryStartDate?: string;
  militaryEndDate?: string;
  dischargeCharacterization?: string;
  hasDisability?: unknown;
  isEmployed?: unknown;
  unemployedLongTerm?: unknown;
  ownsVehicle?: unknown;
  appliedForIDR?: unknown;
  madePriorPayments?: unknown;
  contactedServicer?: unknown;
  rentExpense?: unknown;
  medicalExpense?: unknown;
  utilitiesExpense?: unknown;
  homeMaintenanceExpense?: unknown;
  carInsuranceExpense?: unknown;
  gasExpense?: unknown;
}

type ExpensePayload = Record<IrsExpenseKey, number>;

const EXPENSE_FIELDS: IrsExpenseKey[] = [
  'rentExpense',
  'medicalExpense',
  'utilitiesExpense',
  'homeMaintenanceExpense',
  'carInsuranceExpense',
  'gasExpense',
];

// ── Helper: strip undefined fields for partial upsert ─────────────────────────
function definedOnly(payload: IntakePayload): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(payload).filter(([, v]) => v !== undefined)
  );
}

function parseExpenseAmount(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isFinite(value) && value >= 0 ? value : null;
  }

  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
  }

  return null;
}

function parseOptionalBoolean(value: unknown): boolean | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'boolean') return value;

  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', 'yes', '1'].includes(normalized)) return true;
    if (['false', 'no', '0'].includes(normalized)) return false;
  }

  return null;
}

function parseOptionalDate(value: unknown): Date | null {
  if (value === undefined || value === null || value === '') return null;

  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date;
}

function trimmedOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== ''
    ? value.trim()
    : undefined;
}

const REQUIRED_COMPLETION_FIELDS = [
  'phone',
  'dob',
  'county',
  'address',
  'housingStatus',
  'schoolsHistory',
  'hardshipNotes',
  'unmetBasicNeeds',
] as const;

const REQUIRED_COMPLETION_NUMBERS = [
  'householdSize',
  'monthlyIncome',
  'totalDebt',
  'studentLoanDebt',
] as const;

function isBlank(value: unknown): boolean {
  return (
    value === null ||
    value === undefined ||
    (typeof value === 'string' && value.trim() === '')
  );
}

function hasFirstAndLastName(name?: string | null): boolean {
  const parts = (name ?? '').trim().split(/\s+/).filter(Boolean);
  return parts.length >= 2;
}

function isCompleteIntakePayload(
  profile: Record<string, unknown>,
  clientName?: string | null
): boolean {
  if (!hasFirstAndLastName(clientName)) return false;

  for (const field of REQUIRED_COMPLETION_FIELDS) {
    if (isBlank(profile[field])) return false;
  }

  for (const field of REQUIRED_COMPLETION_NUMBERS) {
    const value = profile[field];
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      return false;
    }
  }

  return typeof profile.householdSize === 'number' && profile.householdSize > 0;
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

      if (body.isCompleted === true) {
        const [existingProfile, client] = await Promise.all([
          prisma.intakeProfile.findUnique({ where: { clientId } }),
          prisma.client.findUnique({
            where:  { id: clientId },
            select: { name: true },
          }),
        ]);

        const mergedProfile = {
          ...(existingProfile ?? {}),
          ...data,
        };

        if (!isCompleteIntakePayload(mergedProfile, client?.name)) {
          data.isCompleted = false;
        }
      }

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
// POST /api/v1/intake/complete
//
// Final client-facing intake submission. Saves borrower identity updates,
// military and financial snapshot fields, IRS expense document flags, and moves
// the borrower into the Pre-Filing pipeline state.
// =============================================================================

router.post(
  '/complete',
  requireClientJwt,
  async (req: ExpressRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as unknown as ClientRequest).clientId;
      const body = req.body as CompleteIntakePayload;

      const firstName = trimmedOrUndefined(body.firstName);
      const lastName = trimmedOrUndefined(body.lastName);
      const phone = trimmedOrUndefined(body.phone);

      if (!firstName) {
        res.status(400).json({ error: 'firstName is required' });
        return;
      }

      if (!lastName) {
        res.status(400).json({ error: 'lastName is required' });
        return;
      }

      if (!phone) {
        res.status(400).json({ error: 'phone is required' });
        return;
      }

      const expenses = {} as ExpensePayload;
      for (const field of EXPENSE_FIELDS) {
        const amount = parseExpenseAmount(body[field]);

        if (amount === null) {
          res.status(400).json({ error: `${field} must be a non-negative number` });
          return;
        }

        expenses[field] = amount;
      }

      const hasDisability = parseOptionalBoolean(body.hasDisability);
      const isEmployed = parseOptionalBoolean(body.isEmployed);
      const unemployedLongTerm = parseOptionalBoolean(body.unemployedLongTerm);
      const ownsVehicle = parseOptionalBoolean(body.ownsVehicle);
      const appliedForIDR = parseOptionalBoolean(body.appliedForIDR);
      const madePriorPayments = parseOptionalBoolean(body.madePriorPayments);
      const contactedServicer = parseOptionalBoolean(body.contactedServicer);
      const militaryStartDate = parseOptionalDate(body.militaryStartDate);
      const militaryEndDate = parseOptionalDate(body.militaryEndDate);

      const booleanFields = [
        ['hasDisability', body.hasDisability, hasDisability],
        ['isEmployed', body.isEmployed, isEmployed],
        ['unemployedLongTerm', body.unemployedLongTerm, unemployedLongTerm],
        ['ownsVehicle', body.ownsVehicle, ownsVehicle],
      ] as const;

      for (const [field, raw, parsed] of booleanFields) {
        if (raw === undefined || raw === null || raw === '') {
          res.status(400).json({ error: `${field} is required` });
          return;
        }

        if (parsed === null) {
          res.status(400).json({ error: `${field} must be a boolean` });
          return;
        }
      }

      if (body.militaryStartDate && !militaryStartDate) {
        res.status(400).json({ error: 'militaryStartDate must be a valid date' });
        return;
      }

      if (body.militaryEndDate && !militaryEndDate) {
        res.status(400).json({ error: 'militaryEndDate must be a valid date' });
        return;
      }

      const flaggedDocuments = evaluateExpenses(expenses);
      const prisma = getPrisma();
      const fullName = `${firstName} ${lastName}`;

      const result = await prisma.$transaction(async (tx) => {
        const client = await tx.client.findUnique({
          where: { id: clientId },
          select: { id: true },
        });

        if (!client) return null;

        const latestSnapshot = await tx.dischargeSnapshot.findFirst({
          where: { clientId },
          orderBy: { createdAt: 'desc' },
        });

        await tx.client.update({
          where: { id: clientId },
          data: {
            name: fullName,
            phone,
            status: 'Pre-Filing',
            intakeStatus: 'Complete',
          },
        });

        await tx.intakeProfile.upsert({
          where: { clientId },
          create: {
            clientId,
            phone,
            hasDisability: hasDisability ?? false,
            isEmployed: isEmployed ?? false,
            unemployed5of10: unemployedLongTerm ?? false,
            hasCar: ownsVehicle ?? false,
            isCompleted: true,
          },
          update: {
            phone,
            ...(hasDisability !== null ? { hasDisability } : {}),
            ...(isEmployed !== null ? { isEmployed } : {}),
            ...(unemployedLongTerm !== null ? { unemployed5of10: unemployedLongTerm } : {}),
            ...(ownsVehicle !== null ? { hasCar: ownsVehicle } : {}),
            isCompleted: true,
          },
        });

        const snapshotData = {
          militaryBranch: trimmedOrUndefined(body.militaryBranch),
          militaryStartDate: militaryStartDate ?? undefined,
          militaryEndDate: militaryEndDate ?? undefined,
          dischargeCharacterization: trimmedOrUndefined(body.dischargeCharacterization),
          hasDisability: hasDisability ?? undefined,
          isEmployed: isEmployed ?? undefined,
          unemployed5PlusYears: unemployedLongTerm ?? undefined,
          ownsVehicle: ownsVehicle ?? undefined,
          appliedForIDR: appliedForIDR ?? undefined,
          madePriorPayments: madePriorPayments ?? undefined,
          contactedServicer: contactedServicer ?? undefined,
          rentExpense: expenses.rentExpense,
          medicalExpense: expenses.medicalExpense,
          utilitiesExpense: expenses.utilitiesExpense,
          homeMaintenanceExpense: expenses.homeMaintenanceExpense,
          carInsuranceExpense: expenses.carInsuranceExpense,
          gasExpense: expenses.gasExpense,
          housingExpenses: expenses.rentExpense + expenses.utilitiesExpense + expenses.homeMaintenanceExpense,
          transportationExpenses: expenses.carInsuranceExpense + expenses.gasExpense,
          flaggedDocuments,
        };
        const analysisSnapshot = latestSnapshot
          ? { ...latestSnapshot, ...snapshotData }
          : {
              ...snapshotData,
              appliedForIDR: appliedForIDR ?? false,
              madePriorPayments: madePriorPayments ?? false,
              contactedServicer: contactedServicer ?? false,
            };
        const analysis = calculateDischargeProbability(analysisSnapshot as DischargeSnapshot);

        const snapshot = latestSnapshot
          ? await tx.dischargeSnapshot.update({
              where: { id: latestSnapshot.id },
              data: {
                ...snapshotData,
                isDischargeable: analysis.isDischargeable,
                status: analysis.status,
              },
            })
          : await tx.dischargeSnapshot.create({
              data: {
                clientId,
                hasFederalLoans: 'unsure',
                ...snapshotData,
                isDischargeable: analysis.isDischargeable,
                status: analysis.status,
              },
            });

        return { snapshotId: snapshot.id };
      });

      if (!result) {
        res.status(404).json({ error: 'Borrower not found' });
        return;
      }

      res.status(200).json({
        success: true,
        flaggedDocuments,
        snapshotId: result.snapshotId,
      });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/intake/expenses
//
// Saves IRS-threshold expense values to the authenticated client's latest
// discharge snapshot and returns the document proofs required by the evaluator.
// =============================================================================

router.post(
  '/expenses',
  requireClientJwt,
  async (req: ExpressRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as unknown as ClientRequest).clientId;
      const body = req.body as Partial<Record<IrsExpenseKey, unknown>>;
      const expenses = {} as ExpensePayload;

      for (const field of EXPENSE_FIELDS) {
        const amount = parseExpenseAmount(body[field]);

        if (amount === null) {
          res.status(400).json({ error: `${field} must be a non-negative number` });
          return;
        }

        expenses[field] = amount;
      }

      const flaggedDocuments = evaluateExpenses(expenses);
      const prisma = getPrisma();

      const latestSnapshot = await prisma.dischargeSnapshot.findFirst({
        where: { clientId },
        orderBy: { createdAt: 'desc' },
      });

      const snapshotData = {
        rentExpense: expenses.rentExpense,
        medicalExpense: expenses.medicalExpense,
        utilitiesExpense: expenses.utilitiesExpense,
        homeMaintenanceExpense: expenses.homeMaintenanceExpense,
        carInsuranceExpense: expenses.carInsuranceExpense,
        gasExpense: expenses.gasExpense,
        housingExpenses: expenses.rentExpense + expenses.utilitiesExpense + expenses.homeMaintenanceExpense,
        transportationExpenses: expenses.carInsuranceExpense + expenses.gasExpense,
        flaggedDocuments,
      };
      const analysisSnapshot = latestSnapshot
        ? { ...latestSnapshot, ...snapshotData }
        : snapshotData;
      const analysis = calculateDischargeProbability(analysisSnapshot as DischargeSnapshot);

      const snapshot = latestSnapshot
        ? await prisma.dischargeSnapshot.update({
            where: { id: latestSnapshot.id },
            data: {
              ...snapshotData,
              isDischargeable: analysis.isDischargeable,
              status: analysis.status,
            },
          })
        : await prisma.dischargeSnapshot.create({
            data: {
              clientId,
              hasFederalLoans: 'unsure',
              ...snapshotData,
              isDischargeable: analysis.isDischargeable,
              status: analysis.status,
            },
          });

      res.status(200).json({
        flaggedDocuments,
        snapshotId: snapshot.id,
      });
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

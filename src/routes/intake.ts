// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENT INTAKE ROUTER
// src/routes/intake.ts
//
// Mounted at: /api/v1/intake  (see server.ts)
//
// Routes:
//   POST /api/v1/intake          — Create or update the authenticated client's intake profile
//   POST /api/v1/intake/snapshot — Client wizard final submission — creates DischargeSnapshot
//   POST /api/v1/intake/complete — Legacy final submission (military/expense fields)
//   POST /api/v1/intake/expenses — Update IRS expense fields on latest snapshot
//   GET  /api/v1/intake          — Retrieve the authenticated client's intake profile
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
  householdSize?: unknown;

  // Health & Employment
  hasDisability?:   unknown;
  isEmployed?:      unknown;
  unemployed5of10?: unknown;
  monthlyIncome?:   unknown;

  // Assets
  housingStatus?:   string;
  hasCar?:          unknown;
  hasRetirement?:   unknown;
  expectingRefund?: unknown;

  // Monthly Expenses
  expFood?:         unknown;
  expHousekeeping?: unknown;
  expApparel?:      unknown;
  expPersonalCare?: unknown;
  expHousing?:      unknown;
  expUtilities?:    unknown;
  expTransportGas?: unknown;
  expCarInsurance?: unknown;

  // Education & Debt
  totalDebt?:       unknown;
  studentLoanDebt?: unknown;
  schoolsHistory?:  string;

  // Case narrative
  hardshipNotes?:   string;
  unmetBasicNeeds?: string;

  // Completion
  isCompleted?: unknown;
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
const INTAKE_TEXT_FIELDS = [
  'dob',
  'ssn',
  'county',
  'phone',
  'address',
  'housingStatus',
  'schoolsHistory',
  'hardshipNotes',
  'unmetBasicNeeds',
] as const;

const INTAKE_NUMBER_FIELDS = [
  'monthlyIncome',
  'expFood',
  'expHousekeeping',
  'expApparel',
  'expPersonalCare',
  'expHousing',
  'expUtilities',
  'expTransportGas',
  'expCarInsurance',
  'totalDebt',
  'studentLoanDebt',
] as const;

const INTAKE_BOOLEAN_FIELDS = [
  'hasDisability',
  'isEmployed',
  'unemployed5of10',
  'hasCar',
  'hasRetirement',
  'expectingRefund',
] as const;

function parseOptionalNonNegativeNumber(value: unknown): number | undefined | null {
  if (value === undefined || value === null || value === '') return undefined;

  if (typeof value === 'number') {
    return Number.isFinite(value) && value >= 0 ? value : null;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed === '') return undefined;

    const parsed = Number(trimmed);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
  }

  return null;
}

function parseOptionalNonNegativeInt(value: unknown): number | undefined | null {
  const parsed = parseOptionalNonNegativeNumber(value);
  if (parsed === undefined || parsed === null) return parsed;
  return Number.isInteger(parsed) ? parsed : null;
}

function buildIntakeProfileData(body: IntakePayload): {
  data: Record<string, unknown>;
  errors: string[];
} {
  const data: Record<string, unknown> = {};
  const errors: string[] = [];

  for (const field of INTAKE_TEXT_FIELDS) {
    if (body[field] !== undefined) {
      data[field] = typeof body[field] === 'string' ? body[field].trim() : body[field];
    }
  }

  const householdSize = parseOptionalNonNegativeInt(body.householdSize);
  if (householdSize === null) {
    errors.push('householdSize must be a non-negative integer');
  } else if (householdSize !== undefined) {
    data.householdSize = householdSize;
  }

  for (const field of INTAKE_NUMBER_FIELDS) {
    const parsed = parseOptionalNonNegativeNumber(body[field]);
    if (parsed === null) {
      errors.push(`${field} must be a non-negative number`);
    } else if (parsed !== undefined) {
      data[field] = parsed;
    }
  }

  for (const field of INTAKE_BOOLEAN_FIELDS) {
    const parsed = parseOptionalBoolean(body[field]);
    if (parsed === null && body[field] !== undefined && body[field] !== '') {
      errors.push(`${field} must be a boolean`);
    } else if (parsed !== null) {
      data[field] = parsed;
    }
  }

  if (body.isCompleted !== undefined) {
    data.isCompleted = body.isCompleted === true || body.isCompleted === 'true';
  }

  return { data, errors };
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
      const { data, errors } = buildIntakeProfileData(body);

      if (errors.length > 0) {
        res.status(400).json({ error: errors[0] });
        return;
      }

      // ── Verify the client exists before attempting the upsert ─────────────
      // If the JWT is valid but references a client that no longer exists in the
      // DB (e.g. account was deleted), the upsert will throw a FK violation
      // (PrismaClientKnownRequestError P2003) which produces an opaque 500.
      // Return a 404 with a clear message instead.
      const prisma = getPrisma();

      const clientExists = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!clientExists) {
        console.warn(`[intake] POST /: clientId ${clientId} not found — JWT may reference a deleted account`);
        res.status(404).json({
          error: 'Your account could not be found. Please contact your legal team for a new invitation.',
        });
        return;
      }

      // ── Upsert intake profile ──────────────────────────────────────────────
      if (data.isCompleted === true) {
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

      if (typeof data.phone === 'string') {
        await prisma.client.update({
          where: { id: clientId },
          data:  { phone: data.phone },
        });
      }

      res.status(200).json({ intakeProfile });

    } catch (err) {
      // ── Surface Prisma validation errors as 400 ───────────────────────────
      const errName = (err as Error)?.constructor?.name ?? '';
      if (
        errName === 'PrismaClientValidationError' ||
        errName === 'PrismaClientKnownRequestError'
      ) {
        console.error('[intake] POST /: Prisma error:', err);
        res.status(400).json({
          error: 'Unable to save intake data. Please check your entries and try again.',
          detail: (err as Error).message,
        });
        return;
      }
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


// =============================================================================
// POST /api/v1/intake/snapshot
//
// Client-wizard final submission endpoint.
//
// Accepts the full DischargeSnapshot payload (mirroring the admin wizard) and:
//   1. Parses all fields defensively (booleans, numbers, dates)
//   2. Runs the discharge probability engine on the assembled data
//   3. Creates a new DischargeSnapshot row linked to the authenticated client
//   4. Marks Client.intakeStatus = 'Complete' in the same transaction
//   5. Returns { success: true, snapshot }
//
// Security model:
//   - requireClientJwt asserts a valid client Bearer token
//   - clientId is extracted from the verified JWT — never trusted from the body
//
// Responses:
//   200  { success: true, snapshot }  — Created successfully
//   400  { error: string }            — Validation error
//   401  { error: 'Unauthorized' }    — Missing or invalid client JWT
//   404  { error: 'Client not found' } — JWT subject doesn't match any client row
//   500  { error: string }            — Unexpected server error
// =============================================================================

interface SnapshotPayload {
  // Step 1 — identity (used to update Client.name / phone if provided)
  firstName?:   string;
  lastName?:    string;
  phone?:       string;
  email?:       string;

  // Step 2 — loans
  hasFederalLoans?: string; // "Yes" | "No" | "I don't know"  → normalised below

  // Step 3 — balance & household
  principalBalance?:   unknown;
  outstandingBalance?: unknown; // legacy alias for principalBalance
  householdSize?:      unknown; // number

  // Step 4 — income
  monthlyGrossIncome?: unknown;
  monthlyTakeHomePay?: unknown;

  // Step 5 — expenses
  additionalIncome?:        unknown;
  additionalMonthlyIncome?: unknown; // legacy alias for additionalIncome
  housingExpenses?:         unknown;
  transportationExpenses?:  unknown;
  dependentCareExpenses?:   unknown;

  // Step 6 — employment & health
  isEmployed?:             unknown;
  currentlyEmployed?:      unknown; // legacy alias for isEmployed
  workInFieldOfStudy?:     unknown;
  unemployed5PlusYears?:   unknown;
  unemployed5Years?:       unknown; // legacy alias for unemployed5PlusYears
  hasDisability?:          unknown;

  // Step 7 — education & age
  didGraduate?:        unknown;
  schoolClosed?:       unknown;
  lastAttendedSchool?: unknown; // date string
  is65OrOlder?:        unknown;

  // Good faith flags
  appliedForIDR?:      unknown;
  madePriorPayments?:  unknown;
  contactedServicer?:  unknown;
}

/** Normalise the hasFederalLoans block-button value to the DB enum string */
function normaliseFederalLoans(raw: string | undefined): 'yes' | 'no' | 'unsure' {
  if (!raw) return 'unsure';
  const lower = raw.trim().toLowerCase();
  if (lower === 'yes') return 'yes';
  if (lower === 'no')  return 'no';
  return 'unsure'; // "I don't know" or anything else
}

function firstDefined<T>(...values: T[]): T | undefined {
  return values.find((value) => value !== undefined && value !== null && value !== '');
}

router.post(
  '/snapshot',
  requireClientJwt,
  async (req: ExpressRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as unknown as ClientRequest).clientId;
      const body     = req.body as SnapshotPayload;

      // ── 1. Require hasFederalLoans ─────────────────────────────────────────
      if (!body.hasFederalLoans) {
        res.status(400).json({ error: 'hasFederalLoans is required' });
        return;
      }
      const hasFederalLoans = normaliseFederalLoans(body.hasFederalLoans);

      // ── 2. Parse numeric fields ────────────────────────────────────────────
      const principalBalance     = parseExpenseAmount(firstDefined(body.principalBalance, body.outstandingBalance));
      const householdSizeRaw     = parseExpenseAmount(body.householdSize);
      const monthlyGrossIncome   = parseExpenseAmount(body.monthlyGrossIncome);
      const monthlyTakeHomePay   = parseExpenseAmount(body.monthlyTakeHomePay);
      const additionalIncome     = parseExpenseAmount(firstDefined(body.additionalIncome, body.additionalMonthlyIncome));
      const housingExpenses      = parseExpenseAmount(body.housingExpenses);
      const transportationExpenses = parseExpenseAmount(body.transportationExpenses);
      const dependentCareExpenses  = parseExpenseAmount(body.dependentCareExpenses);

      // householdSize: coerce to integer (the schema uses Int?)
      const householdSize =
        householdSizeRaw !== null ? Math.round(householdSizeRaw) : null;

      // ── 3. Parse boolean fields ────────────────────────────────────────────
      const isEmployed          = parseOptionalBoolean(firstDefined(body.isEmployed, body.currentlyEmployed));
      const workInFieldOfStudy  = parseOptionalBoolean(body.workInFieldOfStudy);
      const unemployed5PlusYears = parseOptionalBoolean(firstDefined(body.unemployed5PlusYears, body.unemployed5Years));
      const hasDisability       = parseOptionalBoolean(body.hasDisability);
      const didGraduate         = parseOptionalBoolean(body.didGraduate);
      const schoolClosed        = parseOptionalBoolean(body.schoolClosed);
      const is65OrOlder         = parseOptionalBoolean(body.is65OrOlder);
      const appliedForIDR       = parseOptionalBoolean(body.appliedForIDR);
      const madePriorPayments   = parseOptionalBoolean(body.madePriorPayments);
      const contactedServicer   = parseOptionalBoolean(body.contactedServicer);

      // ── 4. Parse date field ────────────────────────────────────────────────
      const lastAttendedSchool = parseOptionalDate(body.lastAttendedSchool);

      // ── 5. Identity fields (optional — update client name/phone if given) ──
      const firstName = trimmedOrUndefined(body.firstName);
      const lastName  = trimmedOrUndefined(body.lastName);
      const phone     = trimmedOrUndefined(body.phone);

      // ── 6. Assemble snapshot data ─────────────────────────────────────────
      const snapshotData = {
        hasFederalLoans,
        ...(principalBalance      !== null ? { principalBalance }      : {}),
        ...(householdSize         !== null ? { householdSize }         : {}),
        ...(monthlyGrossIncome    !== null ? { monthlyGrossIncome }    : {}),
        ...(monthlyTakeHomePay    !== null ? { monthlyTakeHomePay }    : {}),
        ...(additionalIncome      !== null ? { additionalIncome }      : {}),
        ...(housingExpenses       !== null ? { housingExpenses }       : {}),
        ...(transportationExpenses !== null ? { transportationExpenses } : {}),
        ...(dependentCareExpenses  !== null ? { dependentCareExpenses }  : {}),
        ...(isEmployed            !== null ? { isEmployed }            : {}),
        ...(workInFieldOfStudy    !== null ? { workInFieldOfStudy }    : {}),
        ...(unemployed5PlusYears  !== null ? { unemployed5PlusYears }  : {}),
        ...(hasDisability         !== null ? { hasDisability }         : {}),
        ...(didGraduate           !== null ? { didGraduate }           : {}),
        ...(schoolClosed          !== null ? { schoolClosed }          : {}),
        ...(is65OrOlder           !== null ? { is65OrOlder }           : {}),
        ...(lastAttendedSchool              ? { lastAttendedSchool }    : {}),
        ...(appliedForIDR         !== null ? { appliedForIDR }         : {}),
        ...(madePriorPayments     !== null ? { madePriorPayments }     : {}),
        ...(contactedServicer     !== null ? { contactedServicer }     : {}),
      };

      // ── 7. Run discharge probability engine ───────────────────────────────
      //    Cast to DischargeSnapshot so the analyser can type-check against it.
      //    Fields not in this submission default to null/false in the engine.
      const analysis = calculateDischargeProbability({
        ...snapshotData,
        // Supply required non-nullable defaults for the analyser type contract
        id:        '',
        clientId,
        createdAt: new Date(),
        updatedAt: new Date(),
        // Fields not set by the wizard default to null / false
        rentExpense:            null,
        medicalExpense:         null,
        utilitiesExpense:       null,
        homeMaintenanceExpense: null,
        carInsuranceExpense:    null,
        gasExpense:             null,
        flaggedDocuments:       null,
        ownsVehicle:            null,
        militaryBranch:         null,
        militaryStartDate:      null,
        militaryEndDate:        null,
        dischargeCharacterization: null,
        appliedForIDR:          appliedForIDR ?? false,
        madePriorPayments:      madePriorPayments ?? false,
        contactedServicer:      contactedServicer ?? false,
        isDischargeable:        null,
      } as DischargeSnapshot);

      // ── 8. Persist inside a transaction ───────────────────────────────────
      const prisma = getPrisma();

      const result = await prisma.$transaction(async (tx) => {
        // Verify the client exists by clientId from JWT
        let client = await tx.client.findUnique({
          where:  { id: clientId },
          select: { id: true },
        });

        // ── Fallback: if JWT clientId has no matching row, try email ────────────
        // This handles stale borrower_session cookies where the original client
        // was deleted and re-created (e.g. re-invited) with a new UUID.
        const emailFromBody = typeof body.email === 'string' ? body.email.trim().toLowerCase() : undefined;
        if (!client && emailFromBody) {
          console.warn(
            `[intake/snapshot] clientId ${clientId} not found — falling back to email lookup: ${emailFromBody}`
          );
          const byEmail = await tx.client.findFirst({
            where:  { email: emailFromBody },
            select: { id: true },
          });
          if (byEmail) {
            client = byEmail;
          }
        }

        if (!client) return null;

        const resolvedClientId = client.id;
        // Update client identity (name, phone) and mark intake complete
        const nameUpdate: Record<string, string> = {};
        if (firstName && lastName) nameUpdate.name = `${firstName} ${lastName}`;
        else if (firstName)         nameUpdate.name = firstName;

        await tx.client.update({
          where: { id: resolvedClientId },
          data: {
            ...nameUpdate,
            ...(phone ? { phone } : {}),
            intakeStatus: 'Complete',
          },
        });

        // Create the DischargeSnapshot
        const snapshot = await tx.dischargeSnapshot.create({
          data: {
            clientId: resolvedClientId,
            ...snapshotData,
            isDischargeable: analysis.isDischargeable,
            status:          analysis.status,
          },
        });

        return snapshot;
      });

      if (!result) {
        res.status(404).json({ error: 'Client not found' });
        return;
      }

      res.status(200).json({ success: true, snapshot: result });

    } catch (err) {
      next(err);
    }
  }
);

export default router;

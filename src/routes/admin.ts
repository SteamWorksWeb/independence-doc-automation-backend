// =============================================================================
// THE INDEPENDENCE LAW FIRM — ADMIN ROUTER
// src/routes/admin.ts
//
// Mounted at: /api/v1/admin  (see server.ts)
//
// Routes:
//   GET    /api/v1/admin/clients              — Fetch all clients (lawyer-only)
//   GET    /api/v1/admin/clients/:id          — Fetch single client detail
//   GET    /api/v1/admin/clients/:id/profile  — Fetch unified 360-degree case profile
//   GET    /api/v1/admin/clients/:id/eligibility — Point-based eligibility score
//   PATCH  /api/v1/admin/clients/:id/assign   — Update staff assignment
//   PATCH  /api/v1/admin/clients/:id/status   — Update client pipeline status
//   GET    /api/v1/admin/clients/:id/messages  — Fetch conversation thread
//   POST   /api/v1/admin/clients/:id/messages  — Send a message as LAWYER
//   GET    /api/v1/admin/clients/:id/documents — Fetch document archive
//   POST   /api/v1/admin/clients/:id/documents — Register a document record
//   GET    /api/v1/admin/cases/:id            — Fetch single case (client + documents + intake)
//   GET    /api/v1/admin/documents            — Fetch ALL documents (global archive, newest first)
//   POST   /api/v1/admin/invites              — Create client invitation
//   GET    /api/v1/admin/invites              — List pending invitations
//   DELETE /api/v1/admin/invites/:id          — Revoke a pending invitation
//   POST   /api/v1/admin/discharge-snapshots  — Submit discharge wizard payload (upsert client + create snapshot)
//   DELETE /api/v1/admin/discharge-snapshots/:id — Permanently delete a snapshot and its parent client record
//   PATCH  /api/v1/admin/discharge-snapshots/:id/status — Update the pipeline status of a Lead Intake
//   GET    /api/v1/admin/leads                — Canonical alias: returns same LeadIntake list as GET /discharge-snapshots
//   POST   /api/v1/admin/leads/invite          — Invite a lead into the intake pipeline


// Security model:
//   - Protected by requireLawyerJwt middleware.
//   - Only JWTs with role: 'lawyer' are accepted; all others receive 403.
//   - Password hashes are NEVER returned — fields are explicitly selected.
//   - The intakeProfile is included so the dashboard can flag whether a
//     client has started or completed the DOJ questionnaire.
//   - Scoring logic lives exclusively in src/services/eligibilityEngine.ts.
// =============================================================================

import crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import {
  evaluateClient,
  ClientNotFoundError,
  IntakeProfileMissingError,
} from '../services/eligibilityEngine';
import { sendInviteEmail, sendBorrowerInviteEmail } from '../utils/email';

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

type CaseProfileSource = 'client' | 'lead';
type CaseProfileRecord = Record<string, unknown> & {
  id: string;
  name?: string | null;
  email?: string | null;
  phone?: string | null;
  status?: string | null;
  intakeStatus?: string | null;
  isVerified?: boolean | null;
  isArchived?: boolean | null;
  assignedToId?: string | null;
  assigneeName?: string | null;
  lawyerId?: string | null;
  createdAt?: Date | string | null;
  updatedAt?: Date | string | null;
  intakeProfile?: unknown;
  leadIntakes?: unknown;
  documents?: unknown;
};

type PrismaWithOptionalBorrower = PrismaClient & {
  borrower?: {
    findUnique(args: unknown): Promise<CaseProfileRecord | null>;
  };
};

const profileDocumentSelect = {
  id:           true,
  fileName:     true,
  fileUrl:      true,
  documentType: true,
  mimeType:     true,
  sizeBytes:    true,
  uploadedBy:   true,
  clientId:     true,
  lawyerId:     true,
  uploadedAt:   true,
  createdAt:    true,
} as const;

const clientProfileSelect = {
  id:             true,
  name:           true,
  email:          true,
  phone:          true,
  status:         true,
  intakeStatus:   true,
  isVerified:     true,
  isArchived:     true,
  assignedToId:   true,
  assigneeName:   true,
  lawyerId:       true,
  createdAt:      true,
  updatedAt:      true,
  intakeProfile:  true,
  leadIntakes: {
    orderBy: { createdAt: 'desc' },
  },
  documents: {
    orderBy: { createdAt: 'desc' },
    select:  profileDocumentSelect,
  },
} as const;

function buildDocumentSelect(prisma: PrismaClient): Record<string, true> | typeof profileDocumentSelect {
  const documentFields = getPrismaModelFields(prisma, 'Document');
  if (documentFields.size === 0) return profileDocumentSelect;

  const selectedFields = [
    'id',
    'fileName',
    'fileUrl',
    'documentType',
    'mimeType',
    'sizeBytes',
    'uploadedBy',
    'clientId',
    'leadId',
    'lawyerId',
    'uploadedAt',
    'createdAt',
  ];

  return Object.fromEntries(
    selectedFields
      .filter((field) => documentFields.has(field))
      .map((field) => [field, true])
  );
}

function getPrismaModelFields(prisma: PrismaClient, modelName: string): Set<string> {
  const models = (prisma as unknown as {
    _runtimeDataModel?: {
      models?: Record<string, { fields?: Array<{ name: string }> }>;
    };
  })._runtimeDataModel?.models;

  return new Set(models?.[modelName]?.fields?.map((field) => field.name) ?? []);
}

function hasModelField(prisma: PrismaClient, modelName: string, fieldName: string): boolean {
  const fields = getPrismaModelFields(prisma, modelName);
  return fields.size === 0 || fields.has(fieldName);
}

function buildLeadProfileSelect(prisma: PrismaClient): Record<string, unknown> | undefined {
  const leadFields = getPrismaModelFields(prisma, 'Lead');
  if (leadFields.size === 0) return undefined;

  const scalarFields = [
    'id',
    'name',
    'fullName',
    'firstName',
    'lastName',
    'email',
    'phone',
    'status',
    'intakeStatus',
    'isVerified',
    'isArchived',
    'assignedToId',
    'assigneeName',
    'lawyerId',
    'clientId',
    'createdAt',
    'updatedAt',
  ];

  const select: Record<string, unknown> = Object.fromEntries(
    scalarFields
      .filter((field) => leadFields.has(field))
      .map((field) => [field, true])
  );

  if (leadFields.has('intakeProfile')) {
    select['intakeProfile'] = true;
  }
  if (leadFields.has('leadIntakes')) {
    select['leadIntakes'] = { orderBy: { createdAt: 'desc' } };
  }
  if (leadFields.has('documents')) {
    select['documents'] = {
      orderBy: { createdAt: 'desc' },
      select:  buildDocumentSelect(prisma),
    };
  }

  return Object.keys(select).length ? select : undefined;
}

async function attachLeadProfileRelations(
  prisma: PrismaClient,
  lead: CaseProfileRecord
): Promise<CaseProfileRecord> {
  const relationId = String(lead.clientId ?? lead.id);
  const enriched: CaseProfileRecord = { ...lead };

  if (enriched.intakeProfile === undefined) {
    if (hasModelField(prisma, 'IntakeProfile', 'clientId')) {
      enriched.intakeProfile = await prisma.intakeProfile.findUnique({
        where: { clientId: relationId },
      });
    } else if (hasModelField(prisma, 'IntakeProfile', 'leadId')) {
      enriched.intakeProfile = await prisma.intakeProfile.findFirst({
        where: { leadId: relationId },
      } as never);
    }
  }

  if (enriched.leadIntakes === undefined) {
    const intakeOwnerField = hasModelField(prisma, 'LeadIntake', 'clientId')
      ? 'clientId'
      : 'leadId';

    enriched.leadIntakes = await prisma.leadIntake.findMany({
      where:   { [intakeOwnerField]: relationId },
      orderBy: { createdAt: 'desc' },
    } as never);
  }

  if (enriched.documents === undefined) {
    const documentOwnerField = hasModelField(prisma, 'Document', 'clientId')
      ? 'clientId'
      : 'leadId';

    enriched.documents = await prisma.document.findMany({
      where:   { [documentOwnerField]: relationId },
      orderBy: { createdAt: 'desc' },
      select:  buildDocumentSelect(prisma),
    } as never);
  }

  return enriched;
}

async function findLeadProfile(
  prisma: PrismaClient,
  id: string
): Promise<CaseProfileRecord | null> {
  const leadDelegate = (prisma as PrismaWithOptionalBorrower).borrower;
  if (!leadDelegate) return null;

  const select = buildLeadProfileSelect(prisma);
  const lead = await leadDelegate.findUnique({
    where: { id },
    ...(select ? { select } : {}),
  });

  if (!lead) return null;
  return attachLeadProfileRelations(prisma, lead);
}

function normalizeCaseProfile(
  record: CaseProfileRecord,
  sourceType: CaseProfileSource
): CaseProfileRecord & { sourceType: CaseProfileSource; firstName: string; lastName: string } {
  const fallbackName = [record.firstName, record.lastName]
    .filter((part): part is string => typeof part === 'string' && part.trim() !== '')
    .join(' ');
  const name = record.name ?? record.fullName ?? fallbackName;
  const leadIntakes = Array.isArray(record.leadIntakes)
    ? record.leadIntakes
    : [];
  const documents = Array.isArray(record.documents)
    ? record.documents
    : [];

  return withNameParts({
    ...record,
    name:               typeof name === 'string' ? name : '',
    sourceType,
    status:             record.status ?? 'Pre-Filing',
    intakeStatus:       record.intakeStatus ?? (record.intakeProfile ? 'Complete' : 'Incomplete'),
    isVerified:         record.isVerified ?? false,
    isArchived:         record.isArchived ?? false,
    assignedToId:       record.assignedToId ?? null,
    assigneeName:       record.assigneeName ?? null,
    lawyerId:           record.lawyerId ?? null,
    intakeProfile:      record.intakeProfile ?? null,
    leadIntakes,
    documents,
  });
}

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
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma  = getPrisma();
      const archiveFilter = String(
        req.query.archived ?? req.query.filter ?? ''
      ).trim().toLowerCase();
      const includeArchived =
        String(req.query.includeArchived ?? '').trim().toLowerCase() === 'true' ||
        archiveFilter === 'all';
      const where =
        includeArchived
          ? undefined
          : archiveFilter === 'archived' || archiveFilter === 'true'
          ? { isArchived: true }
          : { isArchived: false };

      const clients = await prisma.client.findMany({
        where,
        select: {
          id:          true,
          name:        true,
          email:       true,
          status:      true,
          isVerified:  true,
          isArchived:  true,
          createdAt:   true,
          // Include the full intakeProfile so the dashboard can determine
          // whether the client has started or completed the DOJ questionnaire.
          intakeProfile: true,
        },
        orderBy: { createdAt: 'desc' },
      });

      res.status(200).json({ clients: clients.map(withNameParts) });
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
          name:       true,
          email:      true,
          status:     true,
          isVerified: true,
          isArchived: true,
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

      res.status(200).json({ client: withNameParts(client) });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/clients/:id/profile
//
// Returns the unified 360-degree case profile for the Admin Dashboard:
// borrower/client identity, assignment fields, intake profile, discharge
// snapshots, and uploaded documents in one response.
// =============================================================================

router.get(
  '/clients/:id/profile',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);

      console.log("[DEBUG] Fetching 360 Profile for ID:", req.params.id);

      const client = await prisma.client.findUnique({
        where: { id: clientId },
        select: clientProfileSelect,
      });
      const profile = client
        ? normalizeCaseProfile(client, 'client')
        : await findLeadProfile(prisma, clientId).then((lead) =>
            lead ? normalizeCaseProfile(lead, 'lead') : null
          );

      if (!profile) {
        console.log("[DEBUG] 360 Profile Not Found in DB for ID:", req.params.id);
        res.status(404).json({ error: 'Client or lead not found.' });
        return;
      }

      res.status(200).json({ client: profile });
    } catch (error) {
      console.error("[DEBUG] Prisma Error fetching profile:", error);
      next(error);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/clients/:id/eligibility
//
// Delegates to the EligibilityEngine service (src/services/eligibilityEngine.ts)
// which runs the v1 point-based pre-screener and returns a structured result.
//
// Algorithm summary (full logic lives in the service):
//   Base 50. Income <3k → +20, Income >5k → -20.
//   Disability → +15. Unemployed → +15.
//   Owns car → -5. Expecting refund → -5. Clamped to [0, 100].
//
// Path param:
//   :id — the client's UUID
//
// Responses:
//   200  { client_id, eligibility: { score, status, reasons } }
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
      const clientId = String(req.params.id);

      // ── Delegate to the EligibilityEngine service ─────────────────────────
      const result = await evaluateClient(clientId);

      // ── Return structured result ───────────────────────────────────────────
      res.status(200).json({
        client_id: clientId,
        eligibility: result,
      });
    } catch (err) {
      // ── Map typed service errors to HTTP status codes ──────────────────────
      if (err instanceof ClientNotFoundError) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }
      if (err instanceof IntakeProfileMissingError) {
        res.status(422).json({
          error: 'Client has not yet completed an intake profile. Eligibility cannot be determined.',
        });
        return;
      }
      next(err);
    }
  }
);

// =============================================================================
// PATCH /api/v1/admin/clients/:id/status
//
// Moves a client through the admin pipeline by updating their status.
// The frontend renders the filing status UI; this endpoint is the mechanism
// that actually persists each transition.
//
// Allowed status values (exact strings):
//   "Pre-Filing"   - Client is active before case filing
//   "Filed"        - Client case has been filed
//   "Wait to File" - Client is delayed by the 10-year rule
//   "Discharged"   - Client case has been successfully completed
//
// Path param:
//   :id — the client's UUID
//
// Request body (JSON):
//   { status: string }  - must be one of the allowed values
//
// Responses:
//   200  { client: Client }  — Updated client record
//   400  { error: string }   — Invalid or missing status value
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   404  { error: string }   — No client found for the given id
//   500  { error: string }   — Global error handler
// =============================================================================

const ALLOWED_STATUSES = [
  'Pre-Filing',
  'Filed',
  'Wait to File',
  'Discharged',
] as const;

function getNameParts(name?: string | null): { firstName: string; lastName: string } {
  const parts = (name ?? '').trim().split(/\s+/).filter(Boolean);
  return {
    firstName: parts[0] ?? '',
    lastName:  parts.slice(1).join(' '),
  };
}

function withNameParts<T extends { name?: string | null }>(
  client: T
): T & { firstName: string; lastName: string } {
  return {
    ...client,
    ...getNameParts(client.name),
  };
}

function parseOptionalAssignmentField(value: unknown): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== 'string') return undefined;

  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

// =============================================================================
// PATCH /api/v1/admin/clients/:id/assign
//
// Updates the lightweight staff assignment fields on the borrower/client record.
// Accepts null or an empty string to clear either assignment value.
// =============================================================================

router.patch(
  '/clients/:id/assign',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);
      const body = req.body as {
        assignedToId?: unknown;
        assigneeName?: unknown;
      };

      const assignedToId = parseOptionalAssignmentField(body.assignedToId);
      const assigneeName = parseOptionalAssignmentField(body.assigneeName);

      if (
        (body.assignedToId !== undefined && assignedToId === undefined) ||
        (body.assigneeName !== undefined && assigneeName === undefined)
      ) {
        res.status(400).json({
          error: 'assignedToId and assigneeName must be strings, null, or omitted.',
        });
        return;
      }

      if (assignedToId === undefined && assigneeName === undefined) {
        res.status(400).json({
          error: 'At least one assignment field is required.',
        });
        return;
      }

      const existing = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!existing) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      const updatedClient = await prisma.client.update({
        where: { id: clientId },
        data: {
          assignedToId,
          assigneeName,
        },
        select: {
          id:           true,
          name:         true,
          email:        true,
          status:       true,
          intakeStatus: true,
          isVerified:   true,
          isArchived:   true,
          assignedToId: true,
          assigneeName: true,
          createdAt:    true,
          updatedAt:    true,
        },
      });

      console.log(`[admin] Client ${clientId} assignment updated`);

      res.status(200).json({ client: withNameParts(updatedClient) });
    } catch (err) {
      next(err);
    }
  }
);

router.patch(
  '/clients/:id/status',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);
      const { status } = req.body as { status?: string };

      // ── Validate status value ───────────────────────────────────────────────
      if (!status || !ALLOWED_STATUSES.includes(status as typeof ALLOWED_STATUSES[number])) {
        res.status(400).json({
          error: `Invalid status. Must be one of: ${ALLOWED_STATUSES.join(', ')}`,
        });
        return;
      }

      // ── Verify the client exists ────────────────────────────────────────────
      const existing = await prisma.client.findUnique({
        where: { id: clientId },
      });

      if (!existing) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Update status ───────────────────────────────────────────────────────
      const updatedClient = await prisma.client.update({
        where: { id: clientId },
        data:  { status },
        select: {
          id:         true,
          name:       true,
          email:      true,
          status:     true,
          isVerified: true,
          isArchived: true,
          createdAt:  true,
          intakeProfile: true,
        },
      });

      console.log(`[admin] 📋 Client ${clientId} status updated to "${status}"`);

      res.status(200).json({ client: withNameParts(updatedClient) });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// PATCH /api/v1/admin/clients/:id/archive
//
// Soft-deletes a client by marking it archived. Archived clients are excluded
// from GET /api/v1/admin/clients unless an archived/all filter is requested.
// =============================================================================

router.patch(
  '/clients/:id/archive',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);

      const existing = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!existing) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      const archivedClient = await prisma.client.update({
        where: { id: clientId },
        data:  { isArchived: true },
        select: {
          id:         true,
          name:       true,
          email:      true,
          status:     true,
          isVerified: true,
          isArchived: true,
          createdAt:  true,
          intakeProfile: true,
        },
      });

      console.log(`[admin] Client ${clientId} archived`);

      res.status(200).json({ client: withNameParts(archivedClient) });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// DELETE /api/v1/admin/clients/:id
//
// Permanently deletes a client and associated intake/snapshot/document/thread
// records. Child records are removed first so the delete works even if older DB
// constraints were created before cascade settings were added.
// =============================================================================

router.delete(
  '/clients/:id',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);

      const existing = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true, email: true },
      });

      if (!existing) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      await prisma.$transaction([
        prisma.leadIntake.deleteMany({ where: { clientId } }),
        prisma.intakeProfile.deleteMany({ where: { clientId } }),
        prisma.document.deleteMany({ where: { clientId } }),
        prisma.conversation.deleteMany({ where: { leadId: clientId } }),
        prisma.client.delete({ where: { id: clientId } }),
      ]);

      console.log(`[admin] Client ${clientId} (${existing.email}) permanently deleted`);

      res.status(200).json({ message: 'Client permanently deleted' });
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
//   4. Sends a branded invitation email via Resend to the client
//   5. Returns the invitation record in the response
//
// Request body (JSON):
//   {
//     email: string  — Client email to invite  (required)
//   }
//
// Responses:
//   201  { invitation: { id, email, token, expiresAt } }  — Invite created + email sent
//   400  { error: string }   — Missing or invalid email
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.post(
  '/invites',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const lawyerId = (req as LawyerRequest).lawyerId;
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
          email:    normalizedEmail,
          token,
          expiresAt,
          lawyerId,
        },
        select: {
          id:        true,
          email:     true,
          token:     true,
          expiresAt: true,
          createdAt: true,
        },
      });

      // ── Build invite link and dispatch email via Resend ───────────────────────────
      const inviteLink = `https://independence-doc-automation.vercel.app/login?token=${token}`;

      await sendInviteEmail(normalizedEmail, inviteLink);

      console.log(`[admin] ✅ Invite email dispatched to ${normalizedEmail}`);

      // ── Return invitation record ──────────────────────────────────────────────────────
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

// =============================================================================
// GET /api/v1/admin/clients/:id/messages
//
// Fetches the full conversation thread for a specific client, ordered
// chronologically (oldest first) so the frontend can render top-to-bottom.
// Routes through the Conversation model (leadId → Conversation → messages).
//
// Path param:
//   :id — the client's UUID
//
// Responses:
//   200  { messages: Message[] }   — Array of messages (may be empty)
//   401  { error: string }         — Missing or invalid JWT
//   403  { error: string }         — Valid JWT but role !== 'lawyer'
//   404  { error: string }         — No client found for the given id
//   500  { error: string }         — Global error handler
// =============================================================================

router.get(
  '/clients/:id/messages',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);

      // ── Verify the client exists ──────────────────────────────────────────
      const clientExists = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!clientExists) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Fetch messages through the Conversation thread ────────────────────
      // The Conversation record may not exist yet (thread is created lazily).
      const conversation = await prisma.conversation.findUnique({
        where: { leadId: clientId },
        include: {
          messages: {
            where:   { deletedAt: null },
            orderBy: { createdAt: 'asc' },
            select: {
              id:          true,
              body:        true,
              senderType:  true,
              senderUserId: true,
              visibility:  true,
              createdAt:   true,
            },
          },
        },
      });

      const messages = conversation?.messages ?? [];

      res.status(200).json({ messages });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/admin/clients/:id/messages
//
// Creates a new message in the client's conversation thread, sent by the
// authenticated lawyer. senderType is hardcoded to STAFF; senderUserId is
// extracted from the JWT payload (req.lawyerId set by requireLawyerJwt).
//
// Lazily creates the Conversation record (leadId → client) if it does
// not yet exist so the first staff message bootstraps the thread.
//
// Path param:
//   :id — the client's UUID
//
// Request body (JSON):
//   { content: string }  — The message text (required, non-empty)
//
// Responses:
//   201  { message: Message }  — Newly created message record
//   400  { error: string }     — Missing or empty content
//   401  { error: string }     — Missing or invalid JWT
//   403  { error: string }     — Valid JWT but role !== 'lawyer'
//   404  { error: string }     — No client found for the given id
//   500  { error: string }     — Global error handler
// =============================================================================

router.post(
  '/clients/:id/messages',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);
      const lawyerId = (req as LawyerRequest).lawyerId;
      const { content } = req.body as { content?: string };

      // ── Validate content ──────────────────────────────────────────────────
      if (!content?.trim()) {
        res.status(400).json({ error: 'Message content is required.' });
        return;
      }

      // ── Verify the client exists ──────────────────────────────────────────
      const clientExists = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!clientExists) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Lazily upsert Conversation — first staff message creates the thread
      const conversation = await prisma.conversation.upsert({
        where:  { leadId: clientId },
        create: { leadId: clientId, assignedToId: lawyerId },
        update: { updatedAt: new Date() },
        select: { id: true },
      });

      // ── Create the message ────────────────────────────────────────────────
      //   senderType is always STAFF on this admin-only route.
      //   createdAt is server-side (Prisma default — not from request body).
      const newMessage = await prisma.message.create({
        data: {
          conversationId: conversation.id,
          body:           content.trim(),
          senderType:     'STAFF',
          senderUserId:   lawyerId,
          visibility:     'CLIENT_VISIBLE',
        },
        select: {
          id:           true,
          body:         true,
          senderType:   true,
          senderUserId: true,
          visibility:   true,
          createdAt:    true,
        },
      });

      console.log(
        `[admin] 💬 Lawyer ${lawyerId} sent message to client ${clientId} (msg ${newMessage.id})`
      );

      res.status(201).json({ message: newMessage });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/clients/:id/documents
//
// Returns all document records in a client's case archive, ordered newest-
// first. No binary data is returned — only metadata (fileName, fileUrl,
// mimeType, sizeBytes, uploadedBy, createdAt).
//
// Path param:
//   :id — the client's UUID
//
// Responses:
//   200  { documents: Document[] }  — Array (may be empty)
//   401  { error: string }          — Missing or invalid JWT
//   403  { error: string }          — Valid JWT but role !== 'lawyer'
//   404  { error: string }          — No client found for the given id
//   500  { error: string }          — Global error handler
// =============================================================================

router.get(
  '/clients/:id/documents',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);

      // ── Verify client exists ───────────────────────────────────────────────
      const clientExists = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!clientExists) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Fetch documents, newest first ──────────────────────────────────────────
      const documents = await prisma.document.findMany({
        where:   { clientId },
        orderBy: { createdAt: 'desc' },
        select: {
          id:         true,
          fileName:   true,
          fileUrl:    true,
          mimeType:   true,
          sizeBytes:  true,
          uploadedBy: true,
          lawyerId:   true,
          clientId:   true,
          createdAt:  true,
        },
      });

      res.status(200).json({ documents });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/admin/clients/:id/documents
//
// Registers a new document record in the client's case archive.
// The actual file binary is stored externally (S3 / future CDN); this
// endpoint only persists the metadata and URL pointer.
//
// Path param:
//   :id — the client's UUID
//
// Request body (JSON):
//   {
//     fileName:  string  — original filename (required)
//     fileUrl:   string  — URL to the stored file (required)
//     mimeType:  string  — MIME type (required)
//     sizeBytes: number  — file size in bytes (required, positive integer)
//   }
//
// Responses:
//   201  { document: Document }  — Newly created document record
//   400  { error: string }       — Missing or invalid body fields
//   401  { error: string }       — Missing or invalid JWT
//   403  { error: string }       — Valid JWT but role !== 'lawyer'
//   404  { error: string }       — No client found for the given id
//   500  { error: string }       — Global error handler
// =============================================================================

router.post(
  '/clients/:id/documents',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const clientId = String(req.params.id);
      const lawyerId = (req as LawyerRequest).lawyerId;

      const {
        fileName,
        fileUrl,
        mimeType,
        sizeBytes,
      } = req.body as {
        fileName?:  string;
        fileUrl?:   string;
        mimeType?:  string;
        sizeBytes?: number;
      };

      // ── Validate required fields ────────────────────────────────────────────
      if (!fileName?.trim()) {
        res.status(400).json({ error: 'fileName is required.' });
        return;
      }
      if (!fileUrl?.trim()) {
        res.status(400).json({ error: 'fileUrl is required.' });
        return;
      }
      if (!mimeType?.trim()) {
        res.status(400).json({ error: 'mimeType is required.' });
        return;
      }
      if (typeof sizeBytes !== 'number' || !Number.isInteger(sizeBytes) || sizeBytes < 0) {
        res.status(400).json({ error: 'sizeBytes must be a non-negative integer.' });
        return;
      }

      // ── Verify client exists ───────────────────────────────────────────────
      const clientExists = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!clientExists) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Create the document record ────────────────────────────────────────────
      const newDocument = await prisma.document.create({
        data: {
          fileName:   fileName.trim(),
          fileUrl:    fileUrl.trim(),
          mimeType:   mimeType.trim(),
          sizeBytes,
          uploadedBy: 'LAWYER',   // hardcoded — this endpoint is lawyer-only
          clientId,
          lawyerId,
        },
        select: {
          id:         true,
          fileName:   true,
          fileUrl:    true,
          mimeType:   true,
          sizeBytes:  true,
          uploadedBy: true,
          lawyerId:   true,
          clientId:   true,
          createdAt:  true,
        },
      });

      console.log(
        `[admin] 📄 Lawyer ${lawyerId} uploaded document "${fileName}" for client ${clientId} (doc ${newDocument.id})`
      );

      res.status(201).json({ document: newDocument });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/cases/:id
//
// Fetches a single case record by its ID for the War Room / Case Detail page.
//
// In this schema, a "case" is represented by the Client record — the client IS
// the case. This endpoint surfaces the client's identity fields alongside their
// complete document archive and intake profile so the frontend War Room can
// populate in a single request, with no additional round-trips.
//
// Included relations:
//   - documents    — all case files uploaded by the lawyer or the client,
//                    ordered newest-first (matches the document archive UI)
//   - intakeProfile — the DOJ intake questionnaire answers; null if the client
//                     has not yet started the intake flow
//
// Path param:
//   :id — the case/client UUID
//
// Responses:
//   200  { case: { id, name, email, status, isVerified, createdAt,
//                  intakeProfile, documents } }
//         — Full case record with related client info and document archive.
//           `intakeProfile` is null if intake has not been started.
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   404  { error: string }   — No case found for the given id
//   500  { error: string }   — Global error handler
// =============================================================================

router.get(
  '/cases/:id',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma  = getPrisma();
      // String() cast: Express types params as string | string[]; Prisma
      // where clause requires a plain string. Safe because Express always
      // resolves named route params to a single string value.
      const caseId  = String(req.params.id);

      // A "case" in this system is the Client record. We fetch the client by
      // its UUID and include both relations the War Room UI needs:
      //   • documents    — the case file archive (newest first)
      //   • intakeProfile — DOJ questionnaire answers (null if not started)
      // Password hash is explicitly excluded — only safe fields are selected.
      const caseRecord = await prisma.client.findUnique({
        where: { id: caseId },
        select: {
          id:         true,
          name:       true,
          email:      true,
          status:     true,
          isVerified: true,
          createdAt:  true,
          // Include the full intake questionnaire so the War Room tabbed view
          // can display DOJ form data without a second request.
          intakeProfile: true,
          // Include all attached documents, newest first.
          documents: {
            orderBy: { createdAt: 'desc' },
            select: {
              id:         true,
              fileName:   true,
              fileUrl:    true,
              mimeType:   true,
              sizeBytes:  true,
              uploadedBy: true,
              lawyerId:   true,
              clientId:   true,
              createdAt:  true,
            },
          },
        },
      });

      if (!caseRecord) {
        res.status(404).json({ error: 'Case not found.' });
        return;
      }

      console.log(`[admin] 📂 Fetched case details for case/client ${caseId}`);

      res.status(200).json({ case: caseRecord });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/documents
//
// Global document archive — returns every Document record across all clients,
// ordered newest-first. Designed for the firm-wide Documents Archive page.
//
// Each document includes the associated client's `id` and `name` so the
// frontend can link back to the correct client profile without a secondary
// lookup. No private client fields (email, passwordHash, etc.) are exposed.
//
// Responses:
//   200  { documents: (Document & { client: { id, name } })[] }
//         — Flat array of all document records with embedded client stub.
//           Array is empty when no documents have been uploaded yet.
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.get(
  '/documents',
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma = getPrisma();

      const documents = await prisma.document.findMany({
        orderBy: { createdAt: 'desc' },
        include: {
          client: {
            select: {
              id:   true,
              name: true,
            },
          },
        },
      });

      console.log(`[admin] 🗂️  Fetched global document archive (${documents.length} records)`);

      res.status(200).json({ documents });
    } catch (err) {
      next(err);
    }
  }
);


// =============================================================================
// GET /api/v1/admin/discharge-snapshots
//
// Returns all LeadIntake records across every client, ordered newest-
// first (updatedAt DESC). Designed for the admin Lead Intake table that
// replaces hardcoded mock data on the frontend.
//
// Each snapshot includes the full `client` relation so the frontend can display
// the borrower's name (sourced from client.name) without a secondary lookup.
//
// Responses:
//   200  { snapshots: (LeadIntake & { client: Client })[] }
//         â€” Flat array of all snapshot records with embedded client object.
//           Array is empty when no snapshots have been submitted yet.
//   401  { error: string }   â€” Missing or invalid JWT (handled by router.use)
//   403  { error: string }   â€” Valid JWT but role !== 'lawyer'
//   500  { error: string }   â€” Global error handler
// =============================================================================

router.get(
  '/discharge-snapshots',
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma = getPrisma();

      const snapshots = await prisma.leadIntake.findMany({
        orderBy: { updatedAt: 'desc' },
        include: {
          // Include the client record so the frontend table can render the borrower
          // name (client.name), phone, and contact info alongside each snapshot row.
          // intakeProfile is included so the phone number field (stored on the
          // intake questionnaire) travels to the frontend UI — the "Phone Number
          // Ghost Fix".
          client: {
            select: {
              id: true,
              name: true,
              email: true,
              phone: true,
              status: true,
              createdAt: true,
              intakeProfile: true,
            },
          },
        },
      });

      console.log(`[admin] ðŸ“‹ Fetched ${snapshots.length} Lead Intake(s)`);

      res.status(200).json({ snapshots });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/admin/leads
//
// Canonical alias for GET /discharge-snapshots.
//
// The frontend proxy (src/app/api/admin/leads/route.ts) and several page
// components call /api/v1/admin/leads to fetch the Lead Intake pipeline list.
// This route delegates to the same Prisma query as /discharge-snapshots so
// both URLs return identical payloads — no data duplication.
//
// Responses:
//   200  { snapshots: (LeadIntake & { client: Client })[] }
//         — Same shape as GET /discharge-snapshots.
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.get(
  '/leads',
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma = getPrisma();

      const snapshots = await prisma.leadIntake.findMany({
        orderBy: { updatedAt: 'desc' },
        include: {
          client: {
            select: {
              id:            true,
              name:          true,
              email:         true,
              phone:         true,
              status:        true,
              createdAt:     true,
              intakeProfile: true,
            },
          },
        },
      });

      console.log(`[admin] 📋 GET /leads — Fetched ${snapshots.length} Lead Intake(s)`);

      res.status(200).json({ snapshots });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/admin/discharge-snapshots
//
// Creates a LeadIntake linked to an existing or newly-upserted Client.
//
// The 7-step discharge wizard collects two categories of data:
//   1. Basic client identity (firstName, lastName, email, phone)
//   2. Financial / demographic snapshot fields
//
// Strategy — upsert then create:
//   • We look up the client by email. If they already exist we update their
//     name; if not, we create them. Prisma upsert handles both.
//   • After the upsert we create the LeadIntake connected to that
//     client via clientId.
//
// Note on lawyerId:
//   Client.lawyerId is required by the schema. The authenticated lawyer's ID
//   (extracted from the JWT by requireLawyerJwt) is used when creating a new
//   client. If the client already exists their lawyerId is unchanged.
//
// Request body (JSON):
//   {
//     firstName:               string   — required
//     lastName:                string   — required
//     email:                   string   — required (upsert key)
//     phone?:                  string
//
//     hasFederalLoans:         string   — required ("yes" | "no" | "unsure")
//     principalBalance?:       number
//     householdSize?:          number
//     monthlyGrossIncome?:     number
//     monthlyTakeHomePay?:     number
//     additionalIncome?:       number
//     housingExpenses?:        number
//     transportationExpenses?: number
//     dependentCareExpenses?:  number
//     isEmployed?:             boolean
//     workInFieldOfStudy?:     boolean
//     unemployed5PlusYears?:   boolean
//     hasDisability?:          boolean
//     didGraduate?:            boolean
//     schoolClosed?:           boolean
//     is65OrOlder?:            boolean
//     lastAttendedSchool?:     string   — ISO 8601 date string
//   }
//
// Responses:
//   201  { client, leadIntake }  — Created
//   400  { error: string }    — Missing required field
//   401  { error: string }    — Missing or invalid JWT
//   403  { error: string }    — Valid JWT but role !== 'lawyer'
//   409  { error: string }    — A client with this email already exists
//   500  { error: string }    — Global error handler
// =============================================================================

router.post(
  '/discharge-snapshots',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma   = getPrisma();
      const lawyerId = (req as LawyerRequest).lawyerId;

      // â”€â”€ Destructure payload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      const {
        firstName,
        lastName,
        email,
        phone,
        hasFederalLoans,
        principalBalance,
        householdSize,
        monthlyGrossIncome,
        monthlyTakeHomePay,
        additionalIncome,
        housingExpenses,
        transportationExpenses,
        dependentCareExpenses,
        isEmployed,
        workInFieldOfStudy,
        unemployed5PlusYears,
        hasDisability,
        didGraduate,
        schoolClosed,
        is65OrOlder,
        lastAttendedSchool,
      } = req.body as {
        firstName?:              string;
        lastName?:               string;
        email?:                  string;
        phone?:                  string;
        hasFederalLoans?:        string;
        principalBalance?:       number;
        householdSize?:          number;
        monthlyGrossIncome?:     number;
        monthlyTakeHomePay?:     number;
        additionalIncome?:       number;
        housingExpenses?:        number;
        transportationExpenses?: number;
        dependentCareExpenses?:  number;
        isEmployed?:             boolean;
        workInFieldOfStudy?:     boolean;
        unemployed5PlusYears?:   boolean;
        hasDisability?:          boolean;
        didGraduate?:            boolean;
        schoolClosed?:           boolean;
        is65OrOlder?:            boolean;
        lastAttendedSchool?:     string;
      };

      // ————————————————————————————————————————————————————————————————————————————
      if (!firstName?.trim()) {
        res.status(400).json({ error: 'firstName is required.' });
        return;
      }
      if (!lastName?.trim()) {
        res.status(400).json({ error: 'lastName is required.' });
        return;
      }
      if (!email?.trim()) {
        res.status(400).json({ error: 'email is required.' });
        return;
      }
      if (!hasFederalLoans?.trim()) {
        res.status(400).json({ error: 'hasFederalLoans is required.' });
        return;
      }

      const normalizedEmail = email.trim().toLowerCase();
      const fullName        = `${firstName.trim()} ${lastName.trim()}`;

      // â”€â”€ Strict type coercion helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      // The frontend wizard may send numbers as numeric strings (e.g. "1200.50")
      // or booleans as "Yes"/"No" dropdown strings. Prisma will throw on type
      // mismatches, so we coerce everything explicitly here.

      /**
       * Safely parse a value to Float.
       * Returns null if the value is absent, an empty string, or NaN.
       */
      function toFloat(val: unknown): number | null {
        if (val === undefined || val === null || val === '') return null;
        const n = parseFloat(String(val));
        return isNaN(n) ? null : n;
      }

      /**
       * Safely parse a value to Int.
       * Returns null if the value is absent, an empty string, or NaN.
       */
      function toInt(val: unknown): number | null {
        if (val === undefined || val === null || val === '') return null;
        const n = parseInt(String(val), 10);
        return isNaN(n) ? null : n;
      }

      /**
       * Coerce a value to Boolean.
       * Accepts: true/false (native), "Yes"/"No" (dropdown strings),
       *          "true"/"false" (JSON-serialised strings).
       * Returns null if the value is absent or unrecognised.
       */
      function toBool(val: unknown): boolean | null {
        if (val === undefined || val === null || val === '') return null;
        if (typeof val === 'boolean') return val;
        const s = String(val).toLowerCase().trim();
        if (s === 'yes' || s === 'true')  return true;
        if (s === 'no'  || s === 'false') return false;
        return null;
      }

      /**
       * Safely parse a date string to a Date object.
       * Returns null if the value is absent or produces an invalid Date.
       */
      function toDate(val: unknown): Date | null {
        if (val === undefined || val === null || val === '') return null;
        const d = new Date(String(val));
        return isNaN(d.getTime()) ? null : d;
      }
      // -- Pre-flight: duplicate email check ---------------------------------
      // Reject submissions where the email already belongs to an existing
      // client. This prevents the wizard from silently overwriting client data
      // when the same borrower is entered a second time. Callers receive a
      // 409 Conflict so the frontend can surface a clear error to the lawyer.
      const existingClient = await prisma.client.findUnique({
        where:  { email: normalizedEmail },
        select: { id: true },
      });

      if (existingClient) {
        res.status(409).json({ error: 'A borrower with this email already exists.' });
        return;
      }

      // -- Create Client -------------------------------------------------------
      // Email confirmed unique above; create the new client record outright.
      // passwordHash is intentionally empty -- this client is created by the
      // lawyer via the wizard, not through the client self-registration portal.
      const client = await prisma.client.create({
        data: {
          name:         fullName,
          email:        normalizedEmail,
          phone:        phone?.trim(),
          passwordHash: '',
          status:       'Pre-Filing',
          lawyerId,
        },
        select: {
          id:        true,
          name:      true,
          email:     true,
          phone:     true,
          status:    true,
          createdAt: true,
        },
      });

      // â”€â”€ Create LeadIntake â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      // All optional numeric fields are coerced through toFloat()/toInt() so
      // that empty strings and undefined values become null rather than NaN.
      // All boolean fields are coerced through toBool() so that "Yes"/"No"
      // dropdown strings are converted to proper Prisma Boolean values.
      const leadIntake = await prisma.leadIntake.create({
        data: {
          clientId:               client.id,
          hasFederalLoans:        hasFederalLoans.trim(),
          principalBalance:       toFloat(principalBalance)       ?? undefined,
          householdSize:          toInt(householdSize)            ?? undefined,
          monthlyGrossIncome:     toFloat(monthlyGrossIncome)     ?? undefined,
          monthlyTakeHomePay:     toFloat(monthlyTakeHomePay)     ?? undefined,
          additionalIncome:       toFloat(additionalIncome)       ?? undefined,
          housingExpenses:        toFloat(housingExpenses)        ?? undefined,
          transportationExpenses: toFloat(transportationExpenses) ?? undefined,
          dependentCareExpenses:  toFloat(dependentCareExpenses)  ?? undefined,
          isEmployed:             toBool(isEmployed)              ?? undefined,
          workInFieldOfStudy:     toBool(workInFieldOfStudy)      ?? undefined,
          unemployed5PlusYears:   toBool(unemployed5PlusYears)    ?? undefined,
          hasDisability:          toBool(hasDisability)           ?? undefined,
          didGraduate:            toBool(didGraduate)             ?? undefined,
          schoolClosed:           toBool(schoolClosed)            ?? undefined,
          is65OrOlder:            toBool(is65OrOlder)             ?? undefined,
          lastAttendedSchool:     toDate(lastAttendedSchool)      ?? undefined,
          // isDischargeable stays null; status stays "Incomplete" (schema defaults)
        },
      });

      console.log(
        `[admin] ðŸ“‹ LeadIntake ${leadIntake.id} created for client ${client.id} (${normalizedEmail})`
      );

      res.status(201).json({ client, leadIntake });
    } catch (err) {
      // â”€â”€ Aggressive error logging â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      // Log the full request body alongside the raw Prisma error so we can
      // diagnose type-mismatch or constraint violations without guessing.
      console.error("Prisma Error payload:", req.body, err);

      // â”€â”€ Return 400 for Prisma validation errors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      // PrismaClientValidationError indicates a type mismatch or missing required
      // field â€” this is a client-side data problem, not a server fault.
      const errName = (err as Error)?.constructor?.name ?? '';
      if (
        errName === 'PrismaClientValidationError' ||
        errName === 'PrismaClientKnownRequestError'
      ) {
        res.status(400).json({
          error: 'Validation error: invalid or missing fields in Lead Intake payload.',
          detail: (err as Error).message,
        });
        return;
      }

      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/admin/leads/invite
//
// Creates a secure invitation for a BORROWER (pre-client Lead) to begin the
// Lead Intake intake flow. This endpoint is intentionally isolated from
// POST /invites (the client portal invite) — they serve different onboarding
// journeys and must not be conflated.
//
// Flow:
//   1. Lawyer provides the borrower's email address
//   2. Backend generates a 32-byte crypto-random token (256 bits of entropy)
//   3. Saves an Invitation record with a 7-day expiry window (same model as
//      client invites — no schema change required)
//   4. Sends a borrower-specific email via Resend:
//        Subject: "Action Required: Complete Your Lead Intake Intake Questionnaire"
//        Body: Never uses the word "Client" — addresses the recipient as a borrower
//   5. Returns the invitation record in the response
//
// The invite link routes to /intake?token=<token> so the borrower lands directly
// in the intake setup flow before setting their password.
//
// Request body (JSON):
//   {
//     email: string  — Borrower email to invite  (required)
//   }
//
// Responses:
//   201  { invitation: { id, email, token, expiresAt }, intakeLink: string }
//   400  { error: string }   — Missing or invalid email
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.post(
  '/leads/invite',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const lawyerId = (req as LawyerRequest).lawyerId;
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
      //   single-use and short-lived (7 days). The intake link embeds
      //   this token as a query parameter.
      const token = crypto.randomBytes(32).toString('hex');

      // ── Set expiration: 7 days from now ───────────────────────────────────
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      // ── Persist invitation ────────────────────────────────────────────────
      const prisma      = getPrisma();
      const invitation  = await prisma.invitation.create({
        data: {
          email:    normalizedEmail,
          token,
          expiresAt,
          lawyerId,
        },
        select: {
          id:        true,
          email:     true,
          token:     true,
          expiresAt: true,
          createdAt: true,
        },
      });

      // ── Build borrower invite link ────────────────────────────────────────
      //   Sends the borrower directly into the intake setup flow.
      const frontendUrl  = process.env.FRONTEND_URL ?? 'https://independence-doc-automation.vercel.app';
      const intakeLink   = `${frontendUrl}/intake?token=${token}`;

      // ── Dispatch borrower-specific email via Resend ───────────────────────
      //   Uses sendBorrowerInviteEmail — entirely separate from sendInviteEmail.
      //   Subject line and body copy never use the word "Client".
      await sendBorrowerInviteEmail(normalizedEmail, intakeLink);

      console.log(`[admin] ✅ Borrower intake invitation dispatched to ${normalizedEmail}`);

      // ── Return invitation record ───────────────────────────────────────────
      res.status(201).json({
        invitation,
        intakeLink,
      });

    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// DELETE /api/v1/admin/discharge-snapshots/:id
//
// Permanently removes a LeadIntake and its associated parent Client
// record from the database. Because our architecture equates a Borrower with
// a Client, deleting only the snapshot would leave an orphaned Client row.
// A Prisma transaction is used to delete both atomically — either both
// records are removed or neither is.
//
// Path param:
//   :id — the LeadIntake UUID
//
// Delete order inside the transaction (respects FK constraints):
//   1. LeadIntake  (child — references clientId)
//   2. Client             (parent — id === leadIntake.clientId)
//
// Responses:
//   200  { message: 'Lead permanently deleted' }  — Both records removed
//   404  { error: string }   — No snapshot found for the given id
//   401  { error: string }   — Missing or invalid JWT (handled by router.use)
//   403  { error: string }   — Valid JWT but role !== 'lawyer'
//   500  { error: string }   — Global error handler
// =============================================================================

router.delete(
  '/discharge-snapshots/:id',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma     = getPrisma();
      const snapshotId = String(req.params.id);

      // ── Locate the snapshot to retrieve its parent clientId ─────────────────
      const leadIntake = await prisma.leadIntake.findUnique({
        where:  { id: snapshotId },
        select: { id: true, clientId: true },
      });

      if (!leadIntake) {
        res.status(404).json({ error: 'Lead intake record not found.' });
        return;
      }

      // ── Atomically delete snapshot + parent client ──────────────────────────
      // Order matters: delete the child (LeadIntake) first so the FK
      // constraint on clientId is cleared before we remove the parent (Client).
      await prisma.$transaction([
        prisma.leadIntake.delete({ where: { id: snapshotId } }),
        prisma.client.delete({ where: { id: leadIntake.clientId } }),
      ]);

      console.log(
        `[admin] 🗑️  LeadIntake ${snapshotId} and parent Client ${leadIntake.clientId} permanently deleted.`
      );

      res.status(200).json({ message: 'Lead permanently deleted' });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// PATCH /api/v1/admin/discharge-snapshots/:id/status
//
// Allows a lawyer to manually override the pipeline status of a Discharge
// Snapshot (e.g., marking it as 'Incomplete' or 'Archived') without modifying
// any other snapshot fields.
//
// Path param:
//   :id — the LeadIntake UUID
//
// Request body (JSON):
//   { status: string }  — required; the new pipeline status value
//
// Responses:
//   200  { snapshot: LeadIntake }  — Updated snapshot record
//   400  { error: string }               — Missing status field in body
//   401  { error: string }               — Missing or invalid JWT (handled by router.use)
//   403  { error: string }               — Valid JWT but role !== 'lawyer'
//   404  { error: string }               — No snapshot found for the given id
//   500  { error: string }               — Global error handler
// =============================================================================

router.patch(
  '/discharge-snapshots/:id/status',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma     = getPrisma();
      const snapshotId = String(req.params.id);
      const { status } = req.body as { status?: string };

      // ── Validate status presence ──────────────────────────────────────────
      if (!status || !String(status).trim()) {
        res.status(400).json({ error: 'status is required.' });
        return;
      }

      // ── Verify the snapshot exists ────────────────────────────────────────
      const existing = await prisma.leadIntake.findUnique({
        where:  { id: snapshotId },
        select: { id: true },
      });

      if (!existing) {
        res.status(404).json({ error: 'Lead Intake not found.' });
        return;
      }

      // ── Persist the status update ─────────────────────────────────────────
      const updatedSnapshot = await prisma.leadIntake.update({
        where: { id: snapshotId },
        data:  { status: String(status).trim() },
      });

      console.log(
        `[admin] 📋 LeadIntake ${snapshotId} status updated to "${status}"`
      );

      res.status(200).json({ snapshot: updatedSnapshot });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// PUT /api/v1/admin/discharge-snapshots/:id
//
// Updates an existing LeadIntake record with new wizard data.
//
// Path param:
//   :id — the LeadIntake UUID
//
// Responses:
//   200  { snapshot: LeadIntake }  — Updated snapshot record
//   400  { error: string }               — Missing fields or validation error
//   401  { error: string }               — Missing or invalid JWT
//   403  { error: string }               — Valid JWT but role !== 'lawyer'
//   404  { error: string }               — No snapshot found for the given id
//   500  { error: string }               — Global error handler
// =============================================================================

router.put(
  '/discharge-snapshots/:id',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma     = getPrisma();
      const snapshotId = String(req.params.id);

      const {
        hasFederalLoans,
        principalBalance,
        householdSize,
        monthlyGrossIncome,
        monthlyTakeHomePay,
        additionalIncome,
        housingExpenses,
        transportationExpenses,
        dependentCareExpenses,
        isEmployed,
        workInFieldOfStudy,
        unemployed5PlusYears,
        hasDisability,
        didGraduate,
        schoolClosed,
        is65OrOlder,
        lastAttendedSchool,
      } = req.body as {
        hasFederalLoans?:        string;
        principalBalance?:       number;
        householdSize?:          number;
        monthlyGrossIncome?:     number;
        monthlyTakeHomePay?:     number;
        additionalIncome?:       number;
        housingExpenses?:        number;
        transportationExpenses?: number;
        dependentCareExpenses?:  number;
        isEmployed?:             boolean;
        workInFieldOfStudy?:     boolean;
        unemployed5PlusYears?:   boolean;
        hasDisability?:          boolean;
        didGraduate?:            boolean;
        schoolClosed?:           boolean;
        is65OrOlder?:            boolean;
        lastAttendedSchool?:     string;
      };

      // ── Strict type coercion helpers ─────────────────────────────────────────
      function toFloat(val: unknown): number | null {
        if (val === undefined || val === null || val === '') return null;
        const n = parseFloat(String(val));
        return isNaN(n) ? null : n;
      }

      function toInt(val: unknown): number | null {
        if (val === undefined || val === null || val === '') return null;
        const n = parseInt(String(val), 10);
        return isNaN(n) ? null : n;
      }

      function toBool(val: unknown): boolean | null {
        if (val === undefined || val === null || val === '') return null;
        if (typeof val === 'boolean') return val;
        const s = String(val).toLowerCase().trim();
        if (s === 'yes' || s === 'true')  return true;
        if (s === 'no'  || s === 'false') return false;
        return null;
      }

      function toDate(val: unknown): Date | null {
        if (val === undefined || val === null || val === '') return null;
        const d = new Date(String(val));
        return isNaN(d.getTime()) ? null : d;
      }

      // ── Verify the snapshot exists ──────────────────────────────────────────
      const existing = await prisma.leadIntake.findUnique({
        where:  { id: snapshotId },
        select: { id: true },
      });

      if (!existing) {
        res.status(404).json({ error: 'Lead Intake not found.' });
        return;
      }

      // ── Persist the update ──────────────────────────────────────────────────
      const updatedSnapshot = await prisma.leadIntake.update({
        where: { id: snapshotId },
        data: {
          hasFederalLoans:        hasFederalLoans?.trim()         ?? undefined,
          principalBalance:       toFloat(principalBalance)       ?? undefined,
          householdSize:          toInt(householdSize)            ?? undefined,
          monthlyGrossIncome:     toFloat(monthlyGrossIncome)     ?? undefined,
          monthlyTakeHomePay:     toFloat(monthlyTakeHomePay)     ?? undefined,
          additionalIncome:       toFloat(additionalIncome)       ?? undefined,
          housingExpenses:        toFloat(housingExpenses)        ?? undefined,
          transportationExpenses: toFloat(transportationExpenses) ?? undefined,
          dependentCareExpenses:  toFloat(dependentCareExpenses)  ?? undefined,
          isEmployed:             toBool(isEmployed)              ?? undefined,
          workInFieldOfStudy:     toBool(workInFieldOfStudy)      ?? undefined,
          unemployed5PlusYears:   toBool(unemployed5PlusYears)    ?? undefined,
          hasDisability:          toBool(hasDisability)           ?? undefined,
          didGraduate:            toBool(didGraduate)             ?? undefined,
          schoolClosed:           toBool(schoolClosed)            ?? undefined,
          is65OrOlder:            toBool(is65OrOlder)             ?? undefined,
          lastAttendedSchool:     toDate(lastAttendedSchool)      ?? undefined,
        },
      });

      console.log(`[admin] 📋 LeadIntake ${snapshotId} updated via PUT`);

      res.status(200).json({ snapshot: updatedSnapshot });
    } catch (err) {
      const errName = (err as Error)?.constructor?.name ?? '';
      if (
        errName === 'PrismaClientValidationError' ||
        errName === 'PrismaClientKnownRequestError'
      ) {
        res.status(400).json({
          error: 'Validation error: invalid or missing fields in Lead Intake payload.',
          detail: (err as Error).message,
        });
        return;
      }
      next(err);
    }
  }
);

export default router;

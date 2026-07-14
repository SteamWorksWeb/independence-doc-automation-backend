// =============================================================================
// THE INDEPENDENCE LAW FIRM — ADMIN ROUTER
// src/routes/admin.ts
//
// Mounted at: /api/v1/admin  (see server.ts)
//
// Routes:
//   GET    /api/v1/admin/clients              — Fetch all clients (lawyer-only)
//   GET    /api/v1/admin/clients/:id          — Fetch single client detail
//   GET    /api/v1/admin/clients/:id/eligibility — Point-based eligibility score
//   PATCH  /api/v1/admin/clients/:id/status   — Update client pipeline status
//   GET    /api/v1/admin/clients/:id/messages  — Fetch conversation thread
//   POST   /api/v1/admin/clients/:id/messages  — Send a message as LAWYER
//   GET    /api/v1/admin/clients/:id/documents — Fetch document archive
//   POST   /api/v1/admin/clients/:id/documents — Register a document record
//   POST   /api/v1/admin/invites              — Create client invitation
//   GET    /api/v1/admin/invites              — List pending invitations
//   DELETE /api/v1/admin/invites/:id          — Revoke a pending invitation
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
          status:      true,
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
          status:     true,
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
// The frontend renders a 4-step pipeline UI; this endpoint is the mechanism
// that actually persists each transition.
//
// Allowed status values (exact strings):
//   "Intake Pending"   — Intake not yet reviewed
//   "Ready for Review" — Intake complete, awaiting lawyer review
//   "Approved"         — Case approved for filing
//   "Rejected"         — Case not accepted
//
// Path param:
//   :id — the client's UUID
//
// Request body (JSON):
//   { status: string }  — must be one of the four allowed values
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
  'Intake Pending',
  'Ready for Review',
  'Approved',
  'Rejected',
] as const;

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
          email:      true,
          status:     true,
          isVerified: true,
          createdAt:  true,
          intakeProfile: true,
        },
      });

      console.log(`[admin] 📋 Client ${clientId} status updated to "${status}"`);

      res.status(200).json({ client: updatedClient });
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

// =============================================================================
// GET /api/v1/admin/clients/:id/messages
//
// Fetches the full conversation thread for a specific client, ordered
// chronologically (oldest first) so the frontend can render top-to-bottom.
//
// Each message includes:
//   id, content, senderType ("LAWYER" | "CLIENT"), lawyerId (nullable),
//   clientId, createdAt.
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

      // ── Verify the client exists ────────────────────────────────────────────
      const clientExists = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!clientExists) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Fetch all messages for this client thread ─────────────────────────────
      const messages = await prisma.message.findMany({
        where:   { clientId },
        orderBy: { createdAt: 'asc' },
        select: {
          id:         true,
          content:    true,
          senderType: true,
          lawyerId:   true,
          clientId:   true,
          createdAt:  true,
        },
      });

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
// authenticated lawyer. senderType is hardcoded to "LAWYER"; lawyerId is
// extracted from the JWT payload (req.lawyerId set by requireLawyerJwt).
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
      // lawyerId is attached to the request by requireLawyerJwt (payload.sub)
      const lawyerId = (req as LawyerRequest).lawyerId;
      const { content } = req.body as { content?: string };

      // ── Validate content ──────────────────────────────────────────────────────
      if (!content?.trim()) {
        res.status(400).json({ error: 'Message content is required.' });
        return;
      }

      // ── Verify the client exists ────────────────────────────────────────────
      const clientExists = await prisma.client.findUnique({
        where:  { id: clientId },
        select: { id: true },
      });

      if (!clientExists) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Create the message ────────────────────────────────────────────────────
      const newMessage = await prisma.message.create({
        data: {
          content:    content.trim(),
          senderType: 'LAWYER',      // hardcoded — this endpoint is lawyer-only
          clientId,
          lawyerId,
        },
        select: {
          id:         true,
          content:    true,
          senderType: true,
          lawyerId:   true,
          clientId:   true,
          createdAt:  true,
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

export default router;

// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENT DOCUMENT ROUTES
// src/routes/clientDocuments.ts
//
// Mounted at: /api/v1/client/documents  (and legacy /api/client/documents)
//
// All routes require a valid Client JWT (requireClientJwt middleware).
// clientId is taken exclusively from the verified JWT payload — never from
// a URL parameter the client could spoof.
//
// Upload flow (presigned PUT — files never pass through this API):
//   1. POST /presigned-url   → backend returns { url, s3Key }
//   2. Client PUTs binary to `url` directly from the browser
//   3. POST /confirm         → backend saves Document row in DB
//
// Message attachment flow:
//   1. POST /presigned-url/attachment → { url, s3Key } (separate key namespace)
//   2. Client PUTs binary to S3
//   3. POST /confirm with optional messageId → Document saved + linked
//
// Routes:
//   GET  /required                   — List required document categories for this client
//   POST /presigned-url              — Generate presigned PUT URL for a document upload
//   POST /presigned-url/attachment   — Generate presigned PUT URL for a message attachment
//   POST /confirm                    — Confirm upload; persist Document record to DB
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import { randomUUID }                              from 'crypto';
import { Pool }                                    from 'pg';
import { PrismaPg }                               from '@prisma/adapter-pg';
import { PrismaClient }                           from '@prisma/client';
import {
  requireClientJwt,
  ClientRequest,
} from '../middleware/clientJwt';
import {
  generatePresignedPutUrl,
  buildS3Url,
} from '../utils/s3';

// ── Prisma singleton ──────────────────────────────────────────────────────────
let _prisma: PrismaClient | null = null;

function getPrisma(): PrismaClient {
  if (!_prisma) {
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL as string,
      ssl:
        process.env.NODE_ENV === 'production'
          ? { rejectUnauthorized: false }
          : false,
    });
    const adapter = new PrismaPg(pool);
    _prisma = new PrismaClient({ adapter });
  }
  return _prisma;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const DEFAULT_REQUIRED_DOCUMENTS = ['Government ID', 'Recent Paystubs'];

function normalizeRequiredDocuments(flaggedDocuments: unknown): string[] {
  if (!Array.isArray(flaggedDocuments)) {
    return DEFAULT_REQUIRED_DOCUMENTS;
  }

  const documents = flaggedDocuments
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);

  return documents.length > 0 ? documents : DEFAULT_REQUIRED_DOCUMENTS;
}

// Sanitise a client-supplied filename so it cannot escape the key namespace.
// Strips path separators; replaces spaces with underscores.
function sanitizeFileName(name: string): string {
  return name
    .replace(/[/\\]/g, '')   // strip path traversal chars
    .replace(/\s+/g, '_')    // spaces → underscores
    .slice(0, 200);          // cap length
}

// ── Router ────────────────────────────────────────────────────────────────────
const router = Router();

// Apply the client JWT guard to every route in this router.
router.use(requireClientJwt);

// =============================================================================
// GET /
//
// Returns all documents belonging to the authenticated client, ordered newest
// first. This is the primary listing endpoint used by the client document hub.
//
// ── SECURITY INVARIANTS ──────────────────────────────────────────────────────
//
//   Ownership — `clientId` comes exclusively from the verified JWT payload.
//     There is no URL parameter the client can manipulate to list another
//     client's documents. The Prisma `where` clause IS the ownership gate.
//
// Responses:
//   200  { documents: Document[] }
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'client'
//   500  { error: string }  — Global error handler
// =============================================================================
router.get(
  '/',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // clientId comes exclusively from the verified JWT — never from a URL param.
      const clientId = (req as ClientRequest).clientId;
      const prisma   = getPrisma();

      const documents = await prisma.document.findMany({
        where:   { clientId },
        orderBy: { createdAt: 'desc' },
        select: {
          id:           true,
          fileName:     true,
          fileUrl:      true,
          documentType: true,
          mimeType:     true,
          sizeBytes:    true,
          uploadedBy:   true,
          uploadedAt:   true,
          createdAt:    true,
        },
      });

      res.status(200).json({ documents });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /required
//
// Returns the list of document categories this client is required to upload,
// derived from the flaggedDocuments field of their latest DischargeSnapshot.
// Falls back to DEFAULT_REQUIRED_DOCUMENTS if no snapshot exists yet.
//
// Responses:
//   200  { requiredDocuments: string[] }
//   401  Unauthorized
// =============================================================================
router.get(
  '/required',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;
      const prisma   = getPrisma();

      const latestSnapshot = await prisma.dischargeSnapshot.findFirst({
        where:   { clientId },
        orderBy: { createdAt: 'desc' },
        select:  { flaggedDocuments: true },
      });

      res.status(200).json({
        requiredDocuments: normalizeRequiredDocuments(
          latestSnapshot?.flaggedDocuments
        ),
      });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /presigned-url
//
// Generates a time-limited presigned S3 PUT URL that allows the client's
// browser to upload a file directly to S3 without routing the binary through
// this API server.
//
// Request body (JSON):
//   {
//     fileName : string   — Original filename (e.g. "tax_return_2024.pdf")
//     fileType : string   — MIME type         (e.g. "application/pdf")
//   }
//
// Response:
//   201  { url: string, s3Key: string }
//        url    — Presigned PUT URL (valid for 5 minutes). PUT the file to this.
//        s3Key  — S3 object key. Pass back to POST /confirm after the upload.
//
//   400  { error: string }  — Missing / invalid body fields
//   401  Unauthorized
// =============================================================================
router.post(
  '/presigned-url',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;

      const { fileName, fileType } = req.body as {
        fileName?: string;
        fileType?: string;
      };

      if (!fileName?.trim()) {
        res.status(400).json({ error: 'fileName is required.' });
        return;
      }
      if (!fileType?.trim()) {
        res.status(400).json({ error: 'fileType is required.' });
        return;
      }

      const safe   = sanitizeFileName(fileName.trim());
      const s3Key  = `clients/${clientId}/documents/${randomUUID()}-${safe}`;
      const url    = await generatePresignedPutUrl(s3Key, fileType.trim());

      res.status(201).json({ url, s3Key });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /presigned-url/attachment
//
// Generates a presigned S3 PUT URL for a message-center file attachment.
// Stored under a separate key namespace (clients/{id}/messages/...) to keep
// document archive and messaging assets logically isolated in the bucket.
//
// The client should complete the upload and then call POST /confirm with the
// returned s3Key plus the optional messageId to associate the file with a
// message thread in the saved Document record.
//
// Request body (JSON):
//   {
//     fileName  : string    — Original filename
//     fileType  : string    — MIME type
//     messageId?: string    — Optional — conversation message ID to link to
//   }
//
// Response:
//   201  { url: string, s3Key: string }
//   400  { error: string }
//   401  Unauthorized
// =============================================================================
router.post(
  '/presigned-url/attachment',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;

      const { fileName, fileType, messageId } = req.body as {
        fileName?:  string;
        fileType?:  string;
        messageId?: string;
      };

      if (!fileName?.trim()) {
        res.status(400).json({ error: 'fileName is required.' });
        return;
      }
      if (!fileType?.trim()) {
        res.status(400).json({ error: 'fileType is required.' });
        return;
      }

      const safe      = sanitizeFileName(fileName.trim());
      const namespace = messageId?.trim() ?? 'general';
      const s3Key     = `clients/${clientId}/messages/${namespace}/${randomUUID()}-${safe}`;
      const url       = await generatePresignedPutUrl(s3Key, fileType.trim());

      res.status(201).json({ url, s3Key });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /confirm
//
// Called by the client after a successful direct-to-S3 PUT upload.
// Persists a Document record in the database linked to the authenticated client.
//
// Request body (JSON):
//   {
//     s3Key     : string    — Object key returned by POST /presigned-url
//     fileName  : string    — Human-readable filename for display
//     fileSize  : number    — File size in bytes (required — Document.sizeBytes is non-null)
//     fileType  : string    — MIME type (required — Document.mimeType is non-null)
//     category ?: string    — Document category (e.g. "Tax Returns"). Defaults to "Other".
//     messageId?: string    — Optional — links the document to a message thread
//   }
//
// Response:
//   201  { document: Document }
//   400  { error: string }  — Missing required fields
//   401  Unauthorized
// =============================================================================
router.post(
  '/confirm',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;
      const prisma   = getPrisma();

      const { s3Key, fileName, fileSize, fileType, category, messageId } =
        req.body as {
          s3Key?:     string;
          fileName?:  string;
          fileSize?:  number;
          fileType?:  string;
          category?:  string;
          messageId?: string;
        };

      // ── Validate required fields ────────────────────────────────────────────
      if (!s3Key?.trim()) {
        res.status(400).json({ error: 's3Key is required.' });
        return;
      }
      if (!fileName?.trim()) {
        res.status(400).json({ error: 'fileName is required.' });
        return;
      }
      if (typeof fileSize !== 'number' || fileSize < 0) {
        res.status(400).json({ error: 'fileSize must be a non-negative number (bytes).' });
        return;
      }
      if (!fileType?.trim()) {
        res.status(400).json({ error: 'fileType is required.' });
        return;
      }

      // ── Derive the permanent S3 URL from the key ───────────────────────────
      const fileUrl      = buildS3Url(s3Key.trim());
      const documentType = category?.trim() || 'Other';

      // ── Persist Document record ────────────────────────────────────────────
      const document = await prisma.document.create({
        data: {
          fileName:     fileName.trim(),
          fileUrl,
          documentType,
          mimeType:     fileType.trim(),
          sizeBytes:    Math.round(fileSize),
          uploadedBy:   'CLIENT',
          clientId,
        },
        select: {
          id:           true,
          clientId:     true,
          fileName:     true,
          fileUrl:      true,
          documentType: true,
          mimeType:     true,
          sizeBytes:    true,
          uploadedBy:   true,
          uploadedAt:   true,
          createdAt:    true,
        },
      });

      // ── Response — include messageId passthrough if provided ───────────────
      // The messageId is not stored on the Document model (no FK in schema),
      // but we echo it back so the frontend can link the document to the
      // message thread in its own state without a schema migration.
      res.status(201).json({
        document,
        ...(messageId?.trim() ? { messageId: messageId.trim() } : {}),
      });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

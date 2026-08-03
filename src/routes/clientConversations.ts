// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENT CONVERSATIONS ROUTER
// src/routes/clientConversations.ts
//
// Mounted at: /api/v1/client/conversations  (see server.ts)
//             /api/client/conversations      (legacy alias — same handler)
//
// Routes:
//   GET  /api/v1/client/conversations
//     — Returns the authenticated client's conversation(s).
//       Schema enforces 1-to-1 (borrowerId @unique) so this is at most one
//       thread, but we return it as an array for frontend compatibility with
//       the { conversations: [...] } contract.
//       Each entry includes the latest CLIENT_VISIBLE message for preview.
//
//   GET  /api/v1/client/conversations/:id/messages
//     — Returns all CLIENT_VISIBLE messages for the given conversation,
//       ordered chronologically.
//       SECURITY: verifies conversation.borrowerId === clientId before
//       returning any data — a client cannot read another client's thread
//       even if they know the conversation ID.
//
//   POST /api/v1/client/conversations/:id/messages
//     — Creates a new message sent by the authenticated client.
//       SECURITY: same ownership gate as GET /:id/messages.
//       senderType is forced to BORROWER; visibility to CLIENT_VISIBLE.
//       Accepts optional documentId to attach a previously-uploaded document.
//
// Security model:
//   - All routes require a valid Client JWT (role === 'client').
//   - clientId is taken exclusively from the verified JWT payload — never
//     from a URL parameter the client could spoof.
//   - Conversation ownership is verified at the DB level by asserting
//     conversation.borrowerId === clientId in every handler that takes :id.
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import { Pool }                                     from 'pg';
import { PrismaPg }                                from '@prisma/adapter-pg';
import { PrismaClient }                            from '@prisma/client';
import {
  requireClientJwt,
  ClientRequest,
} from '../middleware/clientJwt';

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

// ── Router ────────────────────────────────────────────────────────────────────
const router = Router();

// Apply the client JWT guard to every route in this router.
// requireClientJwt verifies the token, asserts role === 'client', and attaches
// clientId (payload.sub) to the request as (req as ClientRequest).clientId.
router.use(requireClientJwt);

// =============================================================================
// GET /api/v1/client/conversations
//
// Returns the authenticated client's conversation thread(s).
//
// Because the schema enforces 1-to-1 (borrowerId @unique) there is at most
// one conversation per client. We still return an array so the frontend
// Message Center can treat conversations generically.
//
// Each conversation in the response includes:
//   - id, status, createdAt, updatedAt
//   - latestMessage: the most recent CLIENT_VISIBLE, non-deleted message
//     (null if no such message exists yet)
//
// ── SECURITY INVARIANTS ───────────────────────────────────────────────────────
//
//   Scoping:
//     `borrowerId: clientId` in the Prisma where clause is the exclusive
//     ownership gate — there is no URL parameter to spoof.
//
//   D3 — visibility filter on latestMessage:
//     Only CLIENT_VISIBLE messages are surfaced for preview. INTERNAL staff
//     notes are never exposed to this endpoint.
//
//   D5 — soft-delete filter on latestMessage:
//     deletedAt: null excludes soft-deleted messages.
//
// Responses:
//   200  { conversations: ConversationSummary[] }
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'client'
//   500  { error: string }  — Global error handler
// =============================================================================

router.get(
  '/',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;
      const prisma   = getPrisma();

      // ── Fetch all conversations for this borrower ─────────────────────────
      // In practice there will be 0 or 1 due to the @unique constraint, but
      // we use findMany so the response shape is always an array.
      const conversations = await prisma.conversation.findMany({
        where:   { borrowerId: clientId },
        orderBy: { updatedAt: 'desc' },
        select: {
          id:        true,
          status:    true,
          createdAt: true,
          updatedAt: true,

          // ── Latest CLIENT_VISIBLE, non-deleted message for preview ─────────
          // D3: visibility filter — INTERNAL messages are never exposed
          // D5: deletedAt: null — soft-deleted messages excluded
          messages: {
            where: {
              visibility: 'CLIENT_VISIBLE',
              deletedAt:  null,
            },
            orderBy: { createdAt: 'desc' },
            take:    1,
            select: {
              id:         true,
              body:       true,
              senderType: true,
              createdAt:  true,
            },
          },
        },
      });

      const result = conversations.map((conv) => ({
        id:            conv.id,
        status:        conv.status,
        createdAt:     conv.createdAt,
        updatedAt:     conv.updatedAt,
        latestMessage: conv.messages[0] ?? null,
      }));

      res.status(200).json({ conversations: result });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/client/conversations/:id/messages
//
// Returns all CLIENT_VISIBLE messages in the specified conversation,
// ordered chronologically (oldest first).
//
// ── SECURITY INVARIANTS ───────────────────────────────────────────────────────
//
//   Ownership gate (CRITICAL):
//     Before returning any data we verify that conversation.borrowerId matches
//     the clientId from the JWT. If a client guesses another conversation's ID
//     they receive 403, not 404 — this avoids leaking the existence of other
//     threads via timing differences.
//
//   D3 — visibility filter:
//     Only CLIENT_VISIBLE messages are returned. INTERNAL staff notes are
//     excluded at the database level.
//
//   D5 — soft-delete filter:
//     deletedAt: null excludes soft-deleted messages.
//
// Responses:
//   200  { messages: Message[] }
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'client', or not owner
//   404  { error: string }  — Conversation not found
//   500  { error: string }  — Global error handler
// =============================================================================

router.get(
  '/:id/messages',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId       = (req as ClientRequest).clientId;
      const conversationId = String(req.params['id']);
      const prisma         = getPrisma();

      // ── Ownership check ───────────────────────────────────────────────────
      // Look up the conversation and verify the borrower owns it.
      // We return 403 on a mismatch rather than 404 to avoid leaking whether
      // other conversation IDs exist.
      const conversation = await prisma.conversation.findUnique({
        where:  { id: conversationId },
        select: { id: true, borrowerId: true },
      });

      if (!conversation) {
        res.status(404).json({ error: 'Conversation not found' });
        return;
      }

      if (conversation.borrowerId !== clientId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      // ── Fetch messages ────────────────────────────────────────────────────
      // D3: visibility: CLIENT_VISIBLE — INTERNAL staff notes never exposed
      // D5: deletedAt: null — soft-deleted messages excluded
      const messages = await prisma.message.findMany({
        where: {
          conversationId,
          visibility: 'CLIENT_VISIBLE',
          deletedAt:  null,
        },
        orderBy: { createdAt: 'asc' },
        select: {
          id:         true,
          body:       true,
          senderType: true,
          visibility: true,
          createdAt:  true,
          // documentId is included so the frontend can render attachments
          documentId: true,
        },
      });

      res.status(200).json({ messages });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/client/conversations/:id/messages
//
// Sends a new message from the authenticated client into the specified thread.
//
// ── FORCED SERVER-SIDE VALUES (D3, D4, D5) ───────────────────────────────────
//
//   senderType  → always 'BORROWER'       (D5 — never accepted from request body)
//   visibility  → always 'CLIENT_VISIBLE' (D3 — clients cannot post INTERNAL)
//   createdAt   → server-side default     (D5 — Prisma @default(now()))
//   status      → reset to 'OPEN'         (D4 — surfaces thread in staff inbox)
//
// Request body (JSON):
//   {
//     body:       string   — Message text (required, non-empty)
//     documentId: string?  — Optional: ID of a previously-uploaded Document
//                           record to attach to this message
//   }
//
// ── SECURITY INVARIANTS ───────────────────────────────────────────────────────
//
//   Same ownership gate as GET /:id/messages — 403 on mismatch, not 404.
//
//   If documentId is supplied we verify it belongs to this client before
//   linking it — a client cannot attach another client's document.
//
// Responses:
//   201  { message: Message }
//   400  { error: string }  — Missing or empty body
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'client', or not owner
//   404  { error: string }  — Conversation not found, or document not found
//   500  { error: string }  — Global error handler
// =============================================================================

router.post(
  '/:id/messages',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId       = (req as ClientRequest).clientId;
      const conversationId = String(req.params['id']);
      const prisma         = getPrisma();

      // ── Extract and validate request body ─────────────────────────────────
      const { body, documentId, attachmentId } = req.body as {
        body?:         string;
        documentId?:   string;
        attachmentId?: string; // alias accepted for S3 pipeline compatibility
      };

      if (!body?.trim()) {
        res.status(400).json({ error: 'body is required' });
        return;
      }

      // Resolve the document reference — accept either field name
      const resolvedDocumentId = documentId?.trim() || attachmentId?.trim() || undefined;

      // ── Ownership check ───────────────────────────────────────────────────
      const conversation = await prisma.conversation.findUnique({
        where:  { id: conversationId },
        select: { id: true, borrowerId: true },
      });

      if (!conversation) {
        res.status(404).json({ error: 'Conversation not found' });
        return;
      }

      if (conversation.borrowerId !== clientId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      // ── Optional: verify the attached document belongs to this client ─────
      if (resolvedDocumentId) {
        const doc = await prisma.document.findUnique({
          where:  { id: resolvedDocumentId },
          select: { id: true, clientId: true },
        });

        if (!doc) {
          res.status(404).json({ error: 'Attachment document not found' });
          return;
        }

        if (doc.clientId !== clientId) {
          res.status(403).json({ error: 'Forbidden: document does not belong to this client' });
          return;
        }
      }

      // ── Create the message + reset conversation status (atomic) ───────────
      //
      // Both writes are in a single $transaction so they either both succeed
      // or both roll back.
      //
      // D3: visibility → CLIENT_VISIBLE (never INTERNAL for client posts)
      // D5: senderType → BORROWER       (never accepted from request body)
      // D5: createdAt  → server-side    (Prisma @default(now()))
      // D4: status     → OPEN           (surfaces thread in staff triage inbox)
      const [message, _updatedConversation] = await prisma.$transaction([
        prisma.message.create({
          data: {
            conversationId,
            body:       body.trim(),
            senderType: 'BORROWER',         // D5 — forced server-side
            visibility: 'CLIENT_VISIBLE',   // D3 — clients never post INTERNAL
            ...(resolvedDocumentId ? { documentId: resolvedDocumentId } : {}),
            // createdAt omitted — Prisma uses @default(now())
            // deletedAt omitted — null by default
          },
          select: {
            id:         true,
            body:       true,
            senderType: true,
            visibility: true,
            createdAt:  true,
            documentId: true,
          },
        }),

        prisma.conversation.update({
          where: { id: conversationId },
          data:  {
            status:    'OPEN',       // D4 — re-surfaces thread in staff inbox
            updatedAt: new Date(),   // D5 — server-side timestamp
          },
          select: { id: true, status: true },
        }),
      ]);

      res.status(201).json({ message });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

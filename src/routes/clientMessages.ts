// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENT (BORROWER) MESSAGES ROUTER
// src/routes/clientMessages.ts
//
// Mounted at: /api/v1/client/messages  (see server.ts)
//
// Routes:
//   GET  /api/v1/client/messages
//     — Fetch the authenticated borrower's conversation thread.
//       D3 SECURITY: ONLY returns messages where visibility = CLIENT_VISIBLE.
//       INTERNAL staff notes are NEVER exposed to this endpoint.
//       D5: Soft-deleted messages (deletedAt != null) are excluded.
//
//   POST /api/v1/client/messages
//     — Send a new message as the authenticated borrower.
//       D3: visibility is forced to CLIENT_VISIBLE — never INTERNAL.
//       D5: senderType is forced to BORROWER; timestamps are server-side.
//       D4: Resets the Conversation status to OPEN so the thread surfaces
//           in the staff triage inbox immediately.
//
// Security model:
//   - All routes require a valid Client JWT (role === 'client').
//   - clientId is taken exclusively from the verified JWT payload (payload.sub).
//   - Borrowers can NEVER access another borrower's conversation.
//     The query always scopes to `borrowerId: clientId` — no URL param to spoof.
//
// Imports requireClientJwt from the shared middleware — no redefinition needed.
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import {
  requireClientJwt,
  ClientRequest,
} from '../middleware/clientJwt';

// ── Prisma client singleton ───────────────────────────────────────────────────
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

// ── Router ───────────────────────────────────────────────────────────────────
const router = Router();

// Apply the client JWT guard to every route in this router.
// requireClientJwt verifies the JWT, asserts role === 'client', and attaches
// clientId (payload.sub) to the request as (req as ClientRequest).clientId.
router.use(requireClientJwt);

// =============================================================================
// GET /api/v1/client/messages
//
// Returns the authenticated borrower's conversation thread.
//
// ── SECURITY INVARIANTS ──────────────────────────────────────────────────────
//
//   D3 — visibility filter:
//     The Prisma `where` clause explicitly includes `visibility: 'CLIENT_VISIBLE'`.
//     INTERNAL staff notes are filtered out at the database level — they never
//     travel over the wire to the client. This is not an application-layer
//     exclusion; it is baked into the query predicate.
//
//   D5 — soft-delete filter:
//     `deletedAt: null` excludes soft-deleted messages. Deleted messages are
//     retained in the database for audit purposes but are never returned here.
//
//   Conversation scoping:
//     The query uses `borrowerId: clientId` where clientId comes exclusively
//     from the verified JWT — there is no URL parameter the borrower can
//     manipulate to access another conversation.
//
// Responses:
//   200  { conversation: { id, status } | null,
//           messages: Message[] }
//         — conversation is null if no thread exists yet for this borrower.
//           messages is [] if the thread exists but has no visible messages.
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

      // ── Look up the borrower's conversation thread ────────────────────────
      //
      // `borrowerId: clientId` scopes the query strictly to this borrower.
      // No secondary ownership check needed — the where clause IS the ownership
      // check at the DB level.
      const conversation = await prisma.conversation.findUnique({
        where: { leadId: clientId },
        select: {
          id:     true,
          status: true,

          // ── D3: CLIENT_VISIBLE only ──────────────────────────────────────
          // ── D5: Exclude soft-deleted messages ───────────────────────────
          //
          // Both filters are in the Prisma where clause — never post-processed
          // in application code, so there is no risk of a filter being skipped.
          messages: {
            where: {
              visibility: 'CLIENT_VISIBLE',   // D3 — INTERNAL excluded at DB level
              deletedAt:  null,               // D5 — soft-deleted excluded
            },
            orderBy: { createdAt: 'asc' },
            select: {
              id:          true,
              body:        true,
              senderType:  true,
              // senderUserId intentionally omitted — borrowers do not need
              // to know which specific staff member sent a message.
              visibility:  true,
              createdAt:   true,
            },
          },
        },
      });

      if (!conversation) {
        // No thread exists yet — not an error, just an empty state.
        res.status(200).json({ conversation: null, messages: [] });
        return;
      }

      res.status(200).json({
        conversation: { id: conversation.id, status: conversation.status },
        messages:     conversation.messages,
      });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/client/messages
//
// Sends a new message from the authenticated borrower into their thread.
//
// ── FORCED SERVER-SIDE VALUES (D3, D4, D5) ───────────────────────────────────
//
//   senderType  → always 'BORROWER'       (D5 — never from request body)
//   visibility  → always 'CLIENT_VISIBLE' (D3 — borrowers cannot set INTERNAL)
//   createdAt   → server-side default     (D5 — never from request body)
//   status      → reset to 'OPEN'         (D4 — surfaces thread in staff inbox)
//
// Request body (JSON):
//   { body: string }  — Message text (required, non-empty)
//
// Responses:
//   201  { message: Message, conversation: { id, status } }
//   400  { error: string }  — Missing or empty body
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'client'
//   404  { error: string }  — No conversation found for this borrower
//   500  { error: string }  — Global error handler
// =============================================================================

router.post(
  '/',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;
      const prisma   = getPrisma();

      // ── Extract and validate request body ─────────────────────────────────
      const { body } = req.body as { body?: string };

      if (!body?.trim()) {
        res.status(400).json({ error: 'body is required' });
        return;
      }

      // ── Locate the borrower's conversation ────────────────────────────────
      //
      // A borrower can only ever post to their own conversation.
      // `borrowerId: clientId` is the exclusive ownership gate — there is
      // no ID in the URL that a borrower could swap to another user's thread.
      const conversation = await prisma.conversation.findUnique({
        where:  { leadId: clientId },
        select: { id: true },
      });

      if (!conversation) {
        // The thread doesn't exist yet. Staff must initiate it first.
        // Return 404 rather than auto-creating, to prevent borrowers from
        // generating unassigned ghost threads.
        res.status(404).json({ error: 'No active conversation found.' });
        return;
      }

      // ── Create the message + reset conversation status (atomic transaction)
      //
      // Both writes are executed in a single Prisma $transaction so they
      // either both succeed or both roll back — there is no state where a
      // message exists without the corresponding status reset, or vice versa.
      //
      // D3: visibility is always CLIENT_VISIBLE — borrowers cannot set INTERNAL.
      // D5: senderType is always BORROWER — never accepted from request body.
      // D5: createdAt is server-side (Prisma @default(now())) — not from body.
      // D4: status reset to OPEN surfaces the thread in the staff triage inbox.
      const [message, updatedConversation] = await prisma.$transaction([
        prisma.message.create({
          data: {
            conversationId: conversation.id,
            body:           body.trim(),
            senderType:     'BORROWER',         // D5 — forced server-side
            visibility:     'CLIENT_VISIBLE',   // D3 — borrowers never post INTERNAL
            // createdAt: omitted — Prisma uses @default(now())
            // deletedAt: omitted — null by default (not soft-deleted)
          },
          select: {
            id:         true,
            body:       true,
            senderType: true,
            visibility: true,
            createdAt:  true,
          },
        }),

        prisma.conversation.update({
          where: { id: conversation.id },
          data:  {
            status:    'OPEN',       // D4 — re-surfaces thread in staff inbox
            updatedAt: new Date(),   // D5 — server-side timestamp
          },
          select: { id: true, status: true },
        }),
      ]);

      res.status(201).json({ message, conversation: updatedConversation });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

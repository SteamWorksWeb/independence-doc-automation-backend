// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENT DASHBOARD SUMMARY ROUTER
// src/routes/clientDashboard.ts
//
// Mounted at: /api/v1/client/dashboard  (see server.ts)
//
// Routes:
//   GET /summary
//     — Returns a consolidated snapshot of the authenticated client's data
//       to hydrate the card-based Client Dashboard home screen in a single
//       round-trip.
//
// Security model:
//   - All routes require a valid Client JWT (requireClientJwt middleware).
//   - clientId is taken exclusively from the verified JWT payload (payload.sub).
//   - Clients can NEVER access another client's data — every Prisma query is
//     scoped to `clientId` from the token; no URL parameter is accepted.
//
// Payload shape:
//   {
//     clientProfile : { firstName, lastName, email, joinDate }
//     caseStatus    : string          // Client pipeline status
//     metrics       : {
//       unreadMessagesCount    : number
//       requiredDocumentsCount : number
//     }
//     recentActivity: {
//       messages  : Message[]   // 3 most recent CLIENT_VISIBLE, non-deleted
//       documents : Document[]  // 3 most recently uploaded documents
//     }
//   }
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import { Pool }                                     from 'pg';
import { PrismaPg }                                from '@prisma/adapter-pg';
import { PrismaClient }                            from '@prisma/client';
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Split a full name string into firstName / lastName.
 * Everything up to the first space is the first name; everything after is the
 * last name. If there is no space the entire string is the first name and
 * lastName is an empty string.
 */
function splitName(fullName: string): { firstName: string; lastName: string } {
  const spaceIndex = fullName.indexOf(' ');
  if (spaceIndex === -1) {
    return { firstName: fullName, lastName: '' };
  }
  return {
    firstName: fullName.slice(0, spaceIndex),
    lastName:  fullName.slice(spaceIndex + 1),
  };
}

/**
 * Derive the list of required document categories from the `flaggedDocuments`
 * JSON field of the most recent DischargeSnapshot.
 * Falls back to an empty array when no snapshot exists or the field is not
 * a non-empty string array.
 */
function normalizeRequiredDocuments(flaggedDocuments: unknown): string[] {
  if (!Array.isArray(flaggedDocuments)) return [];

  return flaggedDocuments
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
}

// ── Router ────────────────────────────────────────────────────────────────────
const router = Router();

// Apply the client JWT guard to every route in this router.
// requireClientJwt verifies the JWT, asserts role === 'client', and attaches
// clientId (payload.sub) to the request as (req as ClientRequest).clientId.
router.use(requireClientJwt);

// =============================================================================
// GET /summary
//
// Returns a consolidated JSON payload used to hydrate the client dashboard
// home screen. All data is fetched in parallel (Promise.all) to minimise
// latency.
//
// ── SECURITY INVARIANTS ──────────────────────────────────────────────────────
//
//   Ownership — every Prisma query is scoped to `clientId` from the JWT.
//     There is no URL parameter a client can manipulate to read another
//     client's data.
//
//   D3 — visibility filter on messages:
//     Only CLIENT_VISIBLE messages are counted or returned.
//     INTERNAL staff notes are excluded at the query predicate level.
//
//   D5 — soft-delete filter on messages:
//     `deletedAt: null` excludes soft-deleted messages.
//
//   Unread count — a message is "unread" if there is no MessageRead row
//     for (message.id, clientId). This is the same read-receipt model used
//     by the staff triage inbox.
//
// Responses:
//   200  { clientProfile, caseStatus, metrics, recentActivity }
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'client'
//   404  { error: string }  — Client record not found
//   500  { error: string }  — Global error handler
// =============================================================================

router.get(
  '/summary',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // clientId comes exclusively from the verified JWT — never from a URL param.
      const clientId = (req as ClientRequest).clientId;
      const prisma   = getPrisma();

      // ── Fetch all data in parallel ────────────────────────────────────────
      //
      // 1. clientRow        — identity, email, status, joinDate
      // 2. latestSnapshot   — flaggedDocuments for required-docs count
      // 3. conversationData — conversation thread with messages + reads
      // 4. recentDocuments  — 3 most recently uploaded documents
      //
      const [clientRow, latestSnapshot, conversationData, recentDocuments] =
        await Promise.all([

          // ── 1. Client identity & status ──────────────────────────────────
          prisma.client.findUnique({
            where:  { id: clientId },
            select: {
              name:      true,
              email:     true,
              status:    true,
              createdAt: true,
            },
          }),

          // ── 2. Latest DischargeSnapshot — required document categories ───
          prisma.dischargeSnapshot.findFirst({
            where:   { clientId },
            orderBy: { createdAt: 'desc' },
            select:  { flaggedDocuments: true },
          }),

          // ── 3. Conversation thread — messages for unread count + recent ──
          //
          //   We load CLIENT_VISIBLE, non-deleted messages and their read
          //   receipts so we can compute the unread count in application code
          //   (counting messages where no MessageRead row exists for clientId).
          //
          //   We load all messages here rather than adding a second query so
          //   both the count and the "recent 3" share the same DB call.
          //
          prisma.conversation.findUnique({
            where:  { borrowerId: clientId },
            select: {
              messages: {
                where: {
                  visibility: 'CLIENT_VISIBLE',   // D3 — INTERNAL excluded
                  deletedAt:  null,               // D5 — soft-deleted excluded
                },
                orderBy: { createdAt: 'desc' },   // newest first for slicing
                select: {
                  id:         true,
                  body:       true,
                  senderType: true,
                  createdAt:  true,
                  reads: {
                    where: { userId: clientId },
                    select: { readAt: true },
                  },
                },
              },
            },
          }),

          // ── 4. 3 most recently uploaded documents ────────────────────────
          prisma.document.findMany({
            where:   { clientId },
            orderBy: { createdAt: 'desc' },
            take:    3,
            select: {
              id:           true,
              fileName:     true,
              documentType: true,
              mimeType:     true,
              sizeBytes:    true,
              uploadedBy:   true,
              uploadedAt:   true,
              createdAt:    true,
            },
          }),
        ]);

      // ── Client not found ──────────────────────────────────────────────────
      if (!clientRow) {
        res.status(404).json({ error: 'Client not found.' });
        return;
      }

      // ── Derive clientProfile ──────────────────────────────────────────────
      const { firstName, lastName } = splitName(clientRow.name);
      const clientProfile = {
        firstName,
        lastName,
        email:    clientRow.email,
        joinDate: clientRow.createdAt,
      };

      // ── Derive caseStatus ─────────────────────────────────────────────────
      const caseStatus = clientRow.status;

      // ── Derive metrics ────────────────────────────────────────────────────
      const allMessages = conversationData?.messages ?? [];

      // Unread = messages with no MessageRead row for this clientId.
      const unreadMessagesCount = allMessages.filter(
        (msg) => msg.reads.length === 0
      ).length;

      // Required documents = categories from the latest snapshot.
      const requiredDocuments    = normalizeRequiredDocuments(latestSnapshot?.flaggedDocuments);
      const requiredDocumentsCount = requiredDocuments.length;

      // ── Derive recentActivity ─────────────────────────────────────────────
      //
      // Messages are already ordered newest-first — take the top 3 and strip
      // the internal `reads` array before sending to the client.
      const recentMessages = allMessages.slice(0, 3).map(({ reads: _reads, ...msg }) => msg);

      // ── Assemble and return the payload ───────────────────────────────────
      res.status(200).json({
        clientProfile,
        caseStatus,
        metrics: {
          unreadMessagesCount,
          requiredDocumentsCount,
        },
        recentActivity: {
          messages:  recentMessages,
          documents: recentDocuments,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

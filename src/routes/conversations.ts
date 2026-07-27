// =============================================================================
// THE INDEPENDENCE LAW FIRM — STAFF CONVERSATIONS ROUTER
// src/routes/conversations.ts
//
// Mounted at: /api/v1/conversations  (see server.ts)
//
// Routes:
//   GET  /api/v1/conversations
//     — List all conversation threads with status, assignedToId,
//       last-activity timestamp, and unread count for the requesting
//       staff member.
//
//   GET  /api/v1/conversations/:id/messages
//     — Fetch the full thread (all visibility levels — INTERNAL included).
//       CRITICAL: Creates a ConversationAccessLog record on every call.
//
//   POST /api/v1/conversations/:id/messages
//     — Send a new message as the authenticated staff member.
//       senderType is forced to STAFF; senderUserId is taken from the JWT.
//       createdAt is always server-side — never accepted from the request body.
//
// Security model:
//   - All routes require a valid Lawyer JWT (role === 'lawyer').
//   - All routes pass through canAccessConversation after JWT verification.
//   - canAccessConversation is the single, centralized authorization gate
//     for this router. Future per-conversation ACL logic lives here.
//
// Constraints (D2, D5):
//   D2: canAccessConversation is applied to every handler before any DB call.
//   D5: Timestamps are server-side only; createdAt/updatedAt never come from
//       the request body.
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

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

// ── Extend Express Request to carry the authenticated lawyerId ────────────────
export interface LawyerRequest extends Request {
  lawyerId: string;
}

interface LawyerJwtPayload {
  sub: string;   // lawyerId
  role: string;  // must be 'lawyer'
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
  req: Request,
  res: Response,
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
    console.error('[conversations] JWT_SECRET is not configured');
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

  // ── Role assertion — only staff tokens may access conversation routes ──────
  if (payload.role !== 'lawyer') {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  // ── Attach lawyerId for downstream handlers ───────────────────────────────
  (req as LawyerRequest).lawyerId = payload.sub;

  next();
}

// =============================================================================
// MIDDLEWARE: canAccessConversation
//
// Centralized authorization gate for all staff conversation routes (D2).
// Must run after requireLawyerJwt so req.lawyerId is guaranteed to be set.
//
// Currently validates:
//   - A valid lawyerId is present on the request (confirming staff identity).
//
// Future extension points (add logic here, not in individual handlers):
//   - Check conversation.assignedToId === lawyerId for restricted threads.
//   - Enforce role tiers (ADMIN | ATTORNEY | PARALEGAL) when multi-role lands.
//   - Audit-log access attempts including failures.
//
// On failure:
//   403 — Staff identity could not be confirmed
// =============================================================================

function canAccessConversation(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const lawyerReq = req as LawyerRequest;

  // requireLawyerJwt always sets lawyerId on success. This guard is the
  // single, explicit authorization checkpoint — centralize all future ACL
  // logic here rather than scattering checks across individual handlers.
  if (!lawyerReq.lawyerId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  next();
}

// ── Router ───────────────────────────────────────────────────────────────────
const router = Router();

// Apply JWT guard to every route in this router.
router.use(requireLawyerJwt);

// =============================================================================
// GET /api/v1/conversations
//
// Returns conversation threads for the staff dashboard.
//
// Query params:
//   borrowerId  (optional) — When supplied, returns ONLY the conversation(s)
//               that belong to the borrower with this id. When omitted, all
//               conversations are returned (existing behaviour).
//
// Each record includes:
//   - id, status, assignedToId, createdAt, updatedAt
//   - borrower: { id, name, email }
//   - lastActivityAt: createdAt of the most recent message in the thread
//                     (falls back to conversation.createdAt if no messages yet)
//   - unreadCount: messages in this thread that have no MessageRead record
//                  for the requesting staff member (excludes soft-deleted msgs)
//
// Responses:
//   200  { conversations: ConversationSummary[] }
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'lawyer'
//   500  { error: string }  — Global error handler
// =============================================================================

router.get(
  '/',
  canAccessConversation,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const lawyerId   = (req as LawyerRequest).lawyerId;
      const prisma     = getPrisma();

      // ── Optional borrower filter ─────────────────────────────────────────
      // If the caller passes ?borrowerId=<id> we scope the query to that
      // borrower only. An absent or empty value returns all conversations.
      const rawBorrowerId = req.query['borrowerId'];
      const borrowerId    =
        typeof rawBorrowerId === 'string' && rawBorrowerId.trim() !== ''
          ? rawBorrowerId.trim()
          : undefined;

      const conversations = await prisma.conversation.findMany({
        orderBy: { updatedAt: 'desc' },
        ...(borrowerId ? { where: { borrowerId } } : {}),
        select: {
          id:           true,
          status:       true,
          assignedToId: true,
          createdAt:    true,
          updatedAt:    true,

          // Borrower identity for the thread list row
          borrower: {
            select: { id: true, name: true, email: true },
          },

          // Most recent message — used for lastActivityAt
          messages: {
            where:   { deletedAt: null },
            orderBy: { createdAt: 'desc' },
            take:    1,
            select:  { createdAt: true },
          },

          // Unread count: messages with no read receipt for this staff member.
          // Soft-deleted messages are excluded from the unread badge.
          _count: {
            select: {
              messages: {
                where: {
                  deletedAt: null,
                  reads: {
                    none: { userId: lawyerId },
                  },
                },
              },
            },
          },
        },
      });

      const result = conversations.map((conv) => ({
        id:             conv.id,
        status:         conv.status,
        assignedToId:   conv.assignedToId,
        borrower:       conv.borrower,
        lastActivityAt: conv.messages[0]?.createdAt ?? conv.createdAt,
        unreadCount:    conv._count.messages,
        createdAt:      conv.createdAt,
        updatedAt:      conv.updatedAt,
      }));

      res.status(200).json({ conversations: result });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/conversations/:id/messages
//
// Fetches the full message thread for a conversation.
// Staff see ALL messages including INTERNAL visibility notes.
//
// CRITICAL (D2): Creates a ConversationAccessLog record on every successful
// call, recording which staff member viewed the thread and when.
//
// Messages are:
//   - Ordered chronologically (createdAt ASC)
//   - Soft-deleted messages (deletedAt != null) are excluded from the payload
//   - Each message includes its reads[] so the UI can show read receipts
//
// Path params:
//   :id  — Conversation id
//
// Responses:
//   200  { conversation: { ...fields, messages: Message[] } }
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'lawyer'
//   404  { error: string }  — Conversation not found
//   500  { error: string }  — Global error handler
// =============================================================================

router.get(
  '/:id/messages',
  canAccessConversation,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const lawyerId = (req as LawyerRequest).lawyerId;
      const id       = String(req.params['id']);
      const prisma   = getPrisma();

      // ── Fetch conversation + thread ──────────────────────────────────────
      const conversation = await prisma.conversation.findUnique({
        where: { id },
        include: {
          borrower: {
            select: { id: true, name: true, email: true },
          },
          messages: {
            where:   { deletedAt: null },
            orderBy: { createdAt: 'asc' },
            include: {
              // Include read receipts so the UI can render per-user read state
              reads: {
                select: { userId: true, readAt: true },
              },
            },
          },
        },
      });

      if (!conversation) {
        res.status(404).json({ error: 'Conversation not found' });
        return;
      }

      // ── CRITICAL: Log this staff member's view (D2) ──────────────────────
      //
      // This INSERT is intentionally fire-and-forget relative to the response
      // but we still await it so errors surface through next(err) and are
      // never silently swallowed.
      await prisma.conversationAccessLog.create({
        data: {
          conversationId: id,
          userId:         lawyerId,
          // viewedAt defaults to now() — server-side timestamp (D5)
        },
      });

      res.status(200).json({ conversation });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/conversations/:id/messages
//
// Sends a new message from the authenticated staff member into a thread.
//
// Forced server-side (D5, D2 constraints):
//   senderType   → always 'STAFF'
//   senderUserId → always the lawyerId from the verified JWT
//   createdAt    → always server-side default — never from the request body
//
// Request body (JSON):
//   {
//     body:       string   — Message content (required)
//     visibility: string   — 'CLIENT_VISIBLE' | 'INTERNAL'  (optional,
//                            defaults to 'CLIENT_VISIBLE' if omitted/invalid)
//   }
//
// Path params:
//   :id  — Conversation id
//
// Responses:
//   201  { message: Message }
//   400  { error: string }  — Missing or empty body
//   401  { error: string }  — Missing or invalid JWT
//   403  { error: string }  — Valid JWT but role !== 'lawyer'
//   404  { error: string }  — Conversation not found
//   500  { error: string }  — Global error handler
// =============================================================================

router.post(
  '/:id/messages',
  canAccessConversation,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const lawyerId = (req as LawyerRequest).lawyerId;
      const id       = String(req.params['id']);
      const prisma   = getPrisma();

      // ── Extract and validate request body ────────────────────────────────
      const { body, visibility } = req.body as {
        body?:       string;
        visibility?: string;
      };

      if (!body?.trim()) {
        res.status(400).json({ error: 'body is required' });
        return;
      }

      // Validate visibility — fall back to CLIENT_VISIBLE for unknown values
      const VALID_VISIBILITIES = ['CLIENT_VISIBLE', 'INTERNAL'] as const;
      type Visibility = (typeof VALID_VISIBILITIES)[number];
      const resolvedVisibility: Visibility =
        VALID_VISIBILITIES.includes(visibility as Visibility)
          ? (visibility as Visibility)
          : 'CLIENT_VISIBLE';

      // ── Verify the conversation exists ───────────────────────────────────
      const conversation = await prisma.conversation.findUnique({
        where:  { id },
        select: { id: true },
      });

      if (!conversation) {
        res.status(404).json({ error: 'Conversation not found' });
        return;
      }

      // ── Create the message ───────────────────────────────────────────────
      //
      // D5: senderType is ALWAYS forced to 'STAFF'.
      // D5: senderUserId is ALWAYS the JWT-authenticated lawyer's ID.
      // D5: createdAt is server-side — Prisma default(now()); never from body.
      const message = await prisma.message.create({
        data: {
          conversationId: id,
          senderType:     'STAFF',
          senderUserId:   lawyerId,
          body:           body.trim(),
          visibility:     resolvedVisibility,
          // createdAt omitted — Prisma uses @default(now())
          // deletedAt omitted — null by default (not soft-deleted)
        },
      });

      // ── Touch the conversation so it rises to the top of the list ────────
      await prisma.conversation.update({
        where: { id },
        data:  { updatedAt: new Date() },
      });

      res.status(201).json({ message });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/conversations/:id/read
//
// Marks all messages in a conversation as read for the requesting staff member.
//
// For each non-deleted message in the thread this route inserts a MessageRead
// record keyed on (messageId, userId). skipDuplicates: true prevents a PK
// conflict when the staff member has already read some or all messages —
// this endpoint is fully idempotent.
//
// Path params:
//   :id  — Conversation id
//
// Responses:
//   200  { markedRead: number }  — Count of newly inserted read receipts
//   401  { error: string }       — Missing or invalid JWT
//   403  { error: string }       — Valid JWT but role !== 'lawyer'
//   404  { error: string }       — Conversation not found
//   500  { error: string }       — Global error handler
// =============================================================================

router.post(
  '/:id/read',
  canAccessConversation,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const lawyerId = (req as LawyerRequest).lawyerId;
      const id       = String(req.params['id']);
      const prisma   = getPrisma();

      // ── Verify the conversation exists ───────────────────────────────────
      const conversation = await prisma.conversation.findUnique({
        where:  { id },
        select: { id: true },
      });

      if (!conversation) {
        res.status(404).json({ error: 'Conversation not found' });
        return;
      }

      // ── Fetch all non-deleted message IDs in this conversation ───────────
      const messages = await prisma.message.findMany({
        where:  { conversationId: id, deletedAt: null },
        select: { id: true },
      });

      // ── Bulk-insert read receipts; skipDuplicates prevents PK conflicts ──
      //
      // MessageRead has a composite PK of (messageId, userId). If any record
      // already exists for this (message, lawyer) pair it is silently skipped —
      // never throws, never double-inserts (D4).
      const result = await prisma.messageRead.createMany({
        data: messages.map((msg) => ({
          messageId: msg.id,
          userId:    lawyerId,
          // readAt omitted — Prisma uses @default(now())
        })),
        skipDuplicates: true,
      });

      res.status(200).json({ markedRead: result.count });
    } catch (err) {
      next(err);
    }
  }
);

export default router;


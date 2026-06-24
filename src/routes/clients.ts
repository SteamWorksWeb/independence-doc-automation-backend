// =============================================================================
// THE INDEPENDENCE LAW FIRM — CLIENTS ROUTER
// src/routes/clients.ts
//
// Mounted at: /api/v1/clients  (see server.ts)
//
// Routes:
//   POST /api/v1/clients   — Register a new client record
//                            (guarded by requireBearerToken)
//
// Prisma integration is scaffolded but intentionally left inactive until
// the database migration is reviewed and approved. The placeholder comment
// marks exactly where the Prisma call will be inserted.
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import { requireBearerToken } from '../middleware/auth';

const router = Router();

// ── POST /api/v1/clients ──────────────────────────────────────────────────────
//
//   Creates a new client record.
//
//   Request body (JSON):
//     {
//       name:     string  — Client full name          (required)
//       email:    string  — Client email address       (required, must be unique)
//       password: string  — Plain-text password        (required, will be hashed)
//       lawyerId: string  — UUID of assigning lawyer   (required)
//     }
//
//   Responses:
//     201  { id, name, email, lawyerId, createdAt }   — Client created
//     400  { error: string }                           — Validation failure
//     409  { error: string }                           — Email already registered
//     500  { error: 'Internal server error' }          — Caught by global handler
//
router.post(
  '/',
  requireBearerToken,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { name, email, password, lawyerId } = req.body as {
        name?: string;
        email?: string;
        password?: string;
        lawyerId?: string;
      };

      // ── Input validation ───────────────────────────────────────────────────
      const missing: string[] = [];
      if (!name?.trim())     missing.push('name');
      if (!email?.trim())    missing.push('email');
      if (!password)         missing.push('password');
      if (!lawyerId?.trim()) missing.push('lawyerId');

      if (missing.length > 0) {
        res.status(400).json({
          error: `Missing required fields: ${missing.join(', ')}`,
        });
        return;
      }

      // ── Email format check ─────────────────────────────────────────────────
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email as string)) {
        res.status(400).json({ error: 'Invalid email address format' });
        return;
      }

      // ── TODO: Prisma integration (pending migration approval) ──────────────
      //
      //   Step 1 — Hash the password with bcrypt (cost 12)
      //     import bcrypt from 'bcrypt';
      //     const passwordHash = await bcrypt.hash(password, 12);
      //
      //   Step 2 — Generate a verification token
      //     const rawToken = crypto.randomUUID();
      //     const verificationToken = crypto
      //       .createHmac('sha256', process.env.JWT_SECRET as string)
      //       .update(rawToken)
      //       .digest('hex');
      //     const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
      //
      //   Step 3 — Persist via Prisma
      //     import { prisma } from '../lib/prisma';
      //     const client = await prisma.client.create({
      //       data: {
      //         name:                name.trim(),
      //         email:               email.trim().toLowerCase(),
      //         passwordHash,
      //         lawyerId:            lawyerId.trim(),
      //         verificationToken,
      //         verificationExpires,
      //       },
      //       select: { id: true, name: true, email: true, lawyerId: true, createdAt: true },
      //     });
      //
      //   Step 4 — Catch Prisma unique-constraint violation (P2002)
      //     if (err?.code === 'P2002') {
      //       return res.status(409).json({ error: 'Email already registered' });
      //     }
      //
      //   Step 5 — Send verification email (SES / Resend)
      //   Step 6 — return res.status(201).json(client);
      //
      // ─────────────────────────────────────────────────────────────────────────

      // Scaffold response until Prisma is wired in
      res.status(501).json({
        message: 'POST /clients scaffold is ready — Prisma integration pending migration approval.',
        received: { name, email, lawyerId },
      });
    } catch (err) {
      // Forward any unexpected errors to the global error handler in server.ts
      next(err);
    }
  }
);

export default router;

// =============================================================================
// THE INDEPENDENCE LAW FIRM — LAWYER AUTH ROUTER
// src/routes/auth.ts
//
// Mounted at: /api/auth  (see server.ts)
//
// Routes:
//   POST /api/auth/login   — Lawyer login → returns JWT (public)
//
// Security model:
//   - Lawyers are internal firm staff seeded directly into the DB.
//   - No public registration — Lawyer accounts are created via seed scripts.
//   - Password is bcrypt-hashed (cost 12) — never stored plain-text.
//   - On success, issues a signed JWT with the lawyer's ID as `sub`.
//   - Generic 401 responses — no enumeration signal (same message for
//     missing user vs wrong password).
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

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

// =============================================================================
// POST /api/auth/login
//
// Authenticates a Lawyer by email + password and issues a signed JWT.
// This route is PUBLIC — no Bearer token required.
//
// Request body (JSON):
//   {
//     email:    string  — Lawyer email address  (required)
//     password: string  — Lawyer password       (required)
//   }
//
// Responses:
//   200  { token: string, lawyer: { id, name, email } }
//         — Authentication successful; JWT valid for JWT_EXPIRES_IN (default 7d)
//   400  { error: string }   — Missing required fields
//   401  { error: string }   — Invalid email or password (intentionally vague)
//   500  { error: string }   — Global error handler
// =============================================================================

router.post(
  '/login',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email, password } = req.body as {
        email?: string;
        password?: string;
      };

      // ── Field presence validation ──────────────────────────────────────────
      if (!email?.trim() || !password) {
        res.status(400).json({ error: 'Email and password are required' });
        return;
      }

      // ── Look up lawyer by email ────────────────────────────────────────────
      const prisma = getPrisma();
      const lawyer = await prisma.lawyer.findUnique({
        where: { email: email.trim().toLowerCase() },
        select: {
          id:           true,
          name:         true,
          email:        true,
          passwordHash: true,
        },
      });

      // ── Lawyer not found — generic 401 (no enumeration signal) ────────────
      if (!lawyer) {
        res.status(401).json({ error: 'Invalid email or password' });
        return;
      }

      // ── Password check ────────────────────────────────────────────────────
      const passwordMatch = await bcrypt.compare(password, lawyer.passwordHash);
      if (!passwordMatch) {
        res.status(401).json({ error: 'Invalid email or password' });
        return;
      }

      // ── Issue JWT ──────────────────────────────────────────────────────────
      //
      //   Payload: { sub: lawyerId, role: 'lawyer' }
      //   The `role` claim lets the frontend distinguish Lawyer JWTs from
      //   Client JWTs without an extra API call.
      //
      const jwtSecret = process.env.JWT_SECRET as string;
      const expiresIn = (process.env.JWT_EXPIRES_IN ?? '7d') as jwt.SignOptions['expiresIn'];

      const token = jwt.sign(
        { sub: lawyer.id, role: 'lawyer' },
        jwtSecret,
        { expiresIn },
      );

      // ── Return token + safe lawyer profile ────────────────────────────────
      res.status(200).json({
        token,
        lawyer: {
          id:    lawyer.id,
          name:  lawyer.name,
          email: lawyer.email,
        },
      });

    } catch (err) {
      next(err);
    }
  }
);

export default router;

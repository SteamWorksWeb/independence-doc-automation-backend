// =============================================================================
// THE INDEPENDENCE LAW FIRM — AUTH ROUTER
// src/routes/auth.ts
//
// Mounted at: /api/auth  AND  /api/v1/auth  (see server.ts)
//
// Routes:
//   POST /api/v1/auth/login          — Lawyer login → returns JWT (public)
//   POST /api/v1/auth/accept-invite  — Consume invite token, set password,
//                                      create Client account, issue JWT cookie
//   POST /api/v1/auth/intake/setup-password
//                                    - Consume borrower intake token, set
//                                      password, issue client JWT
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
        { sub: lawyer.id, email: lawyer.email, role: 'lawyer' },
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

// =============================================================================
// POST /api/v1/auth/accept-invite
//
// Consumes a single-use client invitation token, creates the client account,
// hashes the supplied password, and issues a `client_token` HttpOnly cookie
// so the client is immediately logged in — no separate login step required.
//
// This is the "Velvet Rope" account-activation endpoint. The flow is:
//   1. Lawyer invites a client → Invitation row created with a secure token
//   2. Client receives email → clicks link → frontend shows password setup UI
//   3. Frontend POSTs { token, password } to this endpoint
//   4. We validate the token, create the Client record, and log them in
//
// Request body (JSON):
//   {
//     token:    string  — 64-char hex invite token from the email link (required)
//     password: string  — Desired account password, min 8 chars           (required)
//   }
//
// Token validation rules (any failure → 400):
//   - token must exist in the Invitation table
//   - invitation must not have been used (isUsed === false)
//   - invitation must not be expired (expiresAt > now)
//
// On success:
//   - Client record is created with email + lawyerId from the Invitation row
//   - Invitation is marked isUsed: true (single-use enforcement)
//   - Client JWT is issued and written as an HttpOnly cookie named `client_token`
//   - Cookie mirrors JWT_EXPIRES_IN (default 7d)
//
// Why isVerified = true on creation?
//   The invitation email IS the identity verification step. The client proved
//   access to the inbox by clicking the link. No additional email loop needed.
//
// Why derive name from email?
//   The invite flow captures only a password — no name field. We derive a
//   human-readable display name from the email prefix. The client can update
//   it from their profile later.
//
// Responses:
//   200  { client: { id, name, email, lawyerId } }
//         — Account created, JWT cookie set; client is now logged in
//   400  { error: string }   — Missing fields, invalid/expired/used token
//   409  { error: string }   — Email already has an account (duplicate registration)
//   500  { error: string }   — Global error handler
// =============================================================================

/** 7 days in seconds — mirrors frontend loginClient.ts COOKIE_MAX_AGE */
const CLIENT_COOKIE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;

router.post(
  '/accept-invite',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { token, password } = req.body as {
        token?: string;
        password?: string;
      };

      // ── Field presence validation ──────────────────────────────────────────
      if (!token?.trim()) {
        res.status(400).json({ error: 'Invitation token is required.' });
        return;
      }
      if (!password || password.length < 8) {
        res.status(400).json({ error: 'Password must be at least 8 characters.' });
        return;
      }

      const prisma = getPrisma();

      // ── Look up the invitation by token ────────────────────────────────────
      const invitation = await prisma.invitation.findUnique({
        where: { token: token.trim() },
        select: {
          id:        true,
          email:     true,
          lawyerId:  true,
          isUsed:    true,
          expiresAt: true,
        },
      });

      // ── Token not found ────────────────────────────────────────────────────
      if (!invitation) {
        res.status(400).json({ error: 'Invalid or expired invitation token.' });
        return;
      }

      // ── Token already used ─────────────────────────────────────────────────
      if (invitation.isUsed) {
        res.status(400).json({
          error: 'This invitation has already been used. Please contact your attorney for a new one.',
        });
        return;
      }

      // ── Token expired ──────────────────────────────────────────────────────
      if (new Date() > new Date(invitation.expiresAt)) {
        res.status(400).json({
          error: 'This invitation link has expired. Please contact your attorney for a new one.',
        });
        return;
      }

      // ── Hash the password ──────────────────────────────────────────────────
      //   bcrypt cost factor 12 — matches existing registration flow in clients.ts
      const passwordHash = await bcrypt.hash(password, 12);

      // ── Derive a display name from the email address ───────────────────────
      //   The invite flow only collects a password; we use the email prefix as
      //   a temporary name. The client can update it later from their profile.
      const derivedName = (invitation.email
        .split('@')[0]
        .replace(/[._-]/g, ' ')
        .replace(/\b\w/g, (c: string) => c.toUpperCase())
        .trim()) || invitation.email;

      // ── Create the Client account ──────────────────────────────────────────
      //   isVerified = true: the invite link IS the identity verification step.
      //   No separate email-verification loop is needed for the invite flow.
      let client: { id: string; name: string; email: string; lawyerId: string };
      try {
        client = await prisma.client.create({
          data: {
            name:         derivedName,
            email:        invitation.email,
            passwordHash,
            isVerified:   true,
            status:       'Pre-Filing',
            lawyerId:     invitation.lawyerId,
          },
          select: {
            id:       true,
            name:     true,
            email:    true,
            lawyerId: true,
          },
        });
      } catch (err) {
        // ── P2002 — email already registered ─────────────────────────────────
        if (
          err !== null &&
          typeof err === 'object' &&
          'code' in err &&
          (err as { code: string }).code === 'P2002'
        ) {
          res.status(409).json({
            error: 'An account with this email address already exists. Please log in instead.',
          });
          return;
        }
        throw err;
      }

      // ── Mark invitation as used (single-use enforcement) ──────────────────
      await prisma.invitation.update({
        where: { id: invitation.id },
        data:  { isUsed: true },
      });

      console.log(
        `[auth] ✅ accept-invite: Account created for ${client.email} (clientId: ${client.id})`
      );

      // ── Issue Client JWT ────────────────────────────────────────────────────────────
      //   Payload: { sub: clientId, role: 'client' }
      //   role: 'client' is required by requireClientJwt middleware so that
      //   lawyer JWTs cannot be used to access client routes.
      const jwtSecret = process.env.JWT_SECRET as string;
      const expiresIn = (process.env.JWT_EXPIRES_IN ?? '7d') as jwt.SignOptions['expiresIn'];

      const clientJwt = jwt.sign(
        { sub: client.id, role: 'client' },
        jwtSecret,
        { expiresIn },
      );

      // ── Write JWT as HttpOnly cookie ───────────────────────────────────────
      //   Cookie name `client_token` matches the reader in the Next.js
      //   middleware and the loginClient.ts server action.
      //   httpOnly: true  — JS cannot access the token (XSS protection)
      //   secure: true    — HTTPS-only in production
      //   sameSite: 'lax' — allows navigation from email links
      const isProduction = process.env.NODE_ENV === 'production';
      res.cookie('client_token', clientJwt, {
        httpOnly: true,
        secure:   isProduction,
        sameSite: 'lax',
        path:     '/',
        maxAge:   CLIENT_COOKIE_MAX_AGE_SECONDS * 1000, // Express uses milliseconds
      });

      // ── Return 200 with safe client profile ───────────────────────────────
      res.status(200).json({
        client: {
          id:       client.id,
          name:     client.name,
          email:    client.email,
          lawyerId: client.lawyerId,
        },
      });

    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// GET /api/v1/auth/invite/verify?token=XYZ
//
// Pre-registration token validation. The frontend calls this when the
// borrower lands on the invite link to confirm the token is still valid
// before showing the password-setup form.
//
// Query parameters:
//   token: string  — The invite token from the email link (required)
//
// Validation rules (any failure → 400):
//   - Token must exist in the Invitation table
//   - Invitation must not be expired (expiresAt > now)
//   - Invitation must not have been used (isUsed === false)
//
// On success:
//   Returns the borrower's name + email so the registration form can
//   greet them personally and pre-fill the email field.
//
// Responses:
//   200  { valid: true, email, firstName, lastName }
//   400  { valid: false, error: string }
// =============================================================================

router.get(
  '/invite/verify',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = req.query.token as string | undefined;

      // ── Token presence check ──────────────────────────────────────────────
      if (!token?.trim()) {
        res.status(400).json({ valid: false, error: 'Token is required.' });
        return;
      }

      const prisma = getPrisma();

      // ── Look up the invitation by token ────────────────────────────────────
      const invitation = await prisma.invitation.findUnique({
        where: { token: token.trim() },
        select: {
          id:        true,
          email:     true,
          isUsed:    true,
          expiresAt: true,
        },
      });

      // ── Token not found ────────────────────────────────────────────────────
      if (!invitation) {
        res.status(400).json({
          valid: false,
          error: 'Invalid invitation token.',
        });
        return;
      }

      // ── Token already used ─────────────────────────────────────────────────
      if (invitation.isUsed) {
        res.status(400).json({
          valid: false,
          error: 'This invitation has already been used.',
        });
        return;
      }

      // ── Token expired ──────────────────────────────────────────────────────
      if (new Date() > new Date(invitation.expiresAt)) {
        res.status(400).json({
          valid: false,
          error: 'This invitation has expired. Please contact your attorney for a new one.',
        });
        return;
      }

      // ── Look up the associated borrower by email ───────────────────────────
      //    The Client record may already exist (pre-created by admin) or may
      //    not yet exist (pure invite flow). We attempt to find the client to
      //    return their name for a personalized greeting.
      const client = await prisma.client.findUnique({
        where: { email: invitation.email },
        select: { name: true, email: true },
      });

      // ── Derive firstName / lastName from the client's name ─────────────────
      //    If no client record exists yet, derive from the email prefix.
      let firstName: string;
      let lastName: string;

      if (client?.name) {
        const parts = client.name.trim().split(/\s+/);
        firstName = parts[0] ?? '';
        lastName  = parts.slice(1).join(' ') || '';
      } else {
        // Derive from email prefix (e.g., "jane.smith" → "Jane", "Smith")
        const prefix = invitation.email.split('@')[0].replace(/[._-]/g, ' ').trim();
        const parts  = prefix.split(/\s+/);
        firstName = parts[0]?.replace(/^\w/, (c: string) => c.toUpperCase()) ?? '';
        lastName  = parts.slice(1).map((p: string) => p.replace(/^\w/, (c: string) => c.toUpperCase())).join(' ');
      }

      // ── Return valid response ──────────────────────────────────────────────
      res.status(200).json({
        valid:     true,
        email:     invitation.email,
        firstName,
        lastName,
      });

    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/auth/invite/register
//
// Consumes an invitation token and registers the borrower by setting their
// password. This is the "set your password" step of the invite flow.
//
// Request body (JSON):
//   {
//     token:    string  — The invite token from the email link (required)
//     password: string  — Desired account password, min 8 chars (required)
//   }
//
// Flow:
//   1. Validate token (exists, not used, not expired)
//   2. Hash the password with bcrypt (cost 12)
//   3. Find or create the Client record:
//      - If Client exists (pre-created by admin): update passwordHash, set isVerified = true
//      - If Client doesn't exist: create with derived name from email
//   4. Mark the invitation as used (single-use enforcement)
//   5. Issue a signed JWT and set HttpOnly cookie
//
// Responses:
//   200  { token: string, client: { id, name, email, lawyerId } }
//   400  { error: string }   — Missing fields, invalid/expired/used token
//   500  { error: string }   — Global error handler
// =============================================================================

router.post(
  '/invite/register',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { token, password } = req.body as {
        token?: string;
        password?: string;
      };

      // ── Field presence validation ──────────────────────────────────────────
      if (!token?.trim()) {
        res.status(400).json({ error: 'Invitation token is required.' });
        return;
      }
      if (!password || password.length < 8) {
        res.status(400).json({ error: 'Password must be at least 8 characters.' });
        return;
      }

      const prisma = getPrisma();

      // ── Look up the invitation by token ────────────────────────────────────
      const invitation = await prisma.invitation.findUnique({
        where: { token: token.trim() },
        select: {
          id:        true,
          email:     true,
          lawyerId:  true,
          isUsed:    true,
          expiresAt: true,
        },
      });

      // ── Token not found ────────────────────────────────────────────────────
      if (!invitation) {
        res.status(400).json({ error: 'Invalid or expired invitation token.' });
        return;
      }

      // ── Token already used ─────────────────────────────────────────────────
      if (invitation.isUsed) {
        res.status(400).json({
          error: 'This invitation has already been used. Please contact your attorney for a new one.',
        });
        return;
      }

      // ── Token expired ──────────────────────────────────────────────────────
      if (new Date() > new Date(invitation.expiresAt)) {
        res.status(400).json({
          error: 'This invitation link has expired. Please contact your attorney for a new one.',
        });
        return;
      }

      // ── Hash the password ──────────────────────────────────────────────────
      const passwordHash = await bcrypt.hash(password, 12);

      // ── Find or create the Client record ───────────────────────────────────
      //    If the admin pre-created a Client record for this email, we update
      //    it with the real password and mark as verified (isRegistered).
      //    If no Client exists, we create one (matches the accept-invite flow).
      let client: { id: string; name: string; email: string; lawyerId: string };

      const existingClient = await prisma.client.findUnique({
        where: { email: invitation.email },
        select: { id: true, name: true, email: true, lawyerId: true, status: true },
      });

      if (existingClient) {
        // ── Update existing client — set password + mark registered ─────────
        client = await prisma.client.update({
          where: { id: existingClient.id },
          data: {
            passwordHash,
            isVerified: true,    // isVerified = true acts as "isRegistered"
            status: existingClient.status === 'Filed' ? 'Filed' : 'Pre-Filing',
          },
          select: {
            id:       true,
            name:     true,
            email:    true,
            lawyerId: true,
          },
        });
      } else {
        // ── Create new client from invitation ────────────────────────────────
        const derivedName = (invitation.email
          .split('@')[0]
          .replace(/[._-]/g, ' ')
          .replace(/\b\w/g, (c: string) => c.toUpperCase())
          .trim()) || invitation.email;

        client = await prisma.client.create({
          data: {
            name:         derivedName,
            email:        invitation.email,
            passwordHash,
            isVerified:   true,
            status:       'Pre-Filing',
            lawyerId:     invitation.lawyerId,
          },
          select: {
            id:       true,
            name:     true,
            email:    true,
            lawyerId: true,
          },
        });
      }

      // ── Mark invitation as used (single-use enforcement) ──────────────────
      await prisma.invitation.update({
        where: { id: invitation.id },
        data:  { isUsed: true },
      });

      console.log(
        `[auth] ✅ invite/register: Borrower registered — ${client.email} (clientId: ${client.id})`
      );

      // ── Issue Client JWT ──────────────────────────────────────────────────
      const jwtSecret = process.env.JWT_SECRET as string;
      const expiresIn = (process.env.JWT_EXPIRES_IN ?? '7d') as jwt.SignOptions['expiresIn'];

      const clientJwt = jwt.sign(
        { sub: client.id, role: 'client' },
        jwtSecret,
        { expiresIn },
      );

      // ── Write JWT as HttpOnly cookie ───────────────────────────────────────
      const isProduction = process.env.NODE_ENV === 'production';
      res.cookie('client_token', clientJwt, {
        httpOnly: true,
        secure:   isProduction,
        sameSite: 'lax',
        path:     '/',
        maxAge:   CLIENT_COOKIE_MAX_AGE_SECONDS * 1000,
      });

      // ── Return token + safe client profile ─────────────────────────────────
      res.status(200).json({
        token: clientJwt,
        client: {
          id:       client.id,
          name:     client.name,
          email:    client.email,
          lawyerId: client.lawyerId,
        },
      });

    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/auth/intake/setup-password
//
// Consumes a borrower intake invitation token, sets the borrower's permanent
// password, marks the invite as used, and returns a client-scoped JWT so the
// borrower can continue directly into the onboarding wizard.
//
// Request body (JSON):
//   {
//     token:    string  - Invite token from the intake email (required)
//     password: string  - Desired account password, min 8 chars (required)
//   }
//
// Responses:
//   200  { token, borrower_session, client }
//   400  { error } - Missing fields or invalid/expired/used token
// =============================================================================

router.post(
  '/intake/setup-password',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const invalidTokenError = 'INVALID_INTAKE_SETUP_TOKEN';

    try {
      const { token, password } = req.body as {
        token?: string;
        password?: string;
      };

      if (!token?.trim()) {
        res.status(400).json({ error: 'Invitation token is required.' });
        return;
      }

      if (!password || password.length < 8) {
        res.status(400).json({ error: 'Password must be at least 8 characters.' });
        return;
      }

      const prisma = getPrisma();
      const normalizedToken = token.trim();
      const now = new Date();
      const passwordHash = await bcrypt.hash(password, 12);

      const client = await prisma.$transaction(async (tx) => {
        const invitation = await tx.invitation.findUnique({
          where: { token: normalizedToken },
          select: {
            id:        true,
            email:     true,
            lawyerId:  true,
            isUsed:    true,
            expiresAt: true,
          },
        });

        if (
          !invitation ||
          invitation.isUsed ||
          invitation.expiresAt.getTime() <= now.getTime()
        ) {
          throw new Error(invalidTokenError);
        }

        const existingClient = await tx.client.findUnique({
          where: { email: invitation.email },
          select: { id: true, status: true },
        });

        const savedClient = existingClient
          ? await tx.client.update({
              where: { id: existingClient.id },
              data: {
                passwordHash,
                isVerified:          true,
                status: existingClient.status === 'Filed' ? 'Filed' : 'Pre-Filing',
                verificationToken:   null,
                verificationExpires: null,
              },
              select: {
                id:       true,
                name:     true,
                email:    true,
                lawyerId: true,
              },
            })
          : await tx.client.create({
              data: {
                name: (invitation.email
                  .split('@')[0]
                  .replace(/[._-]/g, ' ')
                  .replace(/\b\w/g, (c: string) => c.toUpperCase())
                  .trim()) || invitation.email,
                email:        invitation.email,
                passwordHash,
                isVerified:   true,
                status:       'Pre-Filing',
                lawyerId:     invitation.lawyerId,
              },
              select: {
                id:       true,
                name:     true,
                email:    true,
                lawyerId: true,
              },
            });

        const consumed = await tx.invitation.updateMany({
          where: {
            id:        invitation.id,
            isUsed:    false,
            expiresAt: { gt: now },
          },
          data: { isUsed: true },
        });

        if (consumed.count !== 1) {
          throw new Error(invalidTokenError);
        }

        return savedClient;
      });

      const jwtSecret = process.env.JWT_SECRET as string;
      const expiresIn = (process.env.JWT_EXPIRES_IN ?? '7d') as jwt.SignOptions['expiresIn'];
      const clientJwt = jwt.sign(
        { sub: client.id, role: 'client' },
        jwtSecret,
        { expiresIn },
      );

      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure:   isProduction,
        sameSite: 'lax' as const,
        path:     '/',
        maxAge:   CLIENT_COOKIE_MAX_AGE_SECONDS * 1000,
      };

      res.cookie('borrower_session', clientJwt, cookieOptions);
      res.cookie('client_token', clientJwt, cookieOptions);

      console.log(
        `[auth] intake/setup-password: Borrower password set for ${client.email} (clientId: ${client.id})`
      );

      res.status(200).json({
        token: clientJwt,
        borrower_session: clientJwt,
        client: {
          id:       client.id,
          name:     client.name,
          email:    client.email,
          lawyerId: client.lawyerId,
        },
      });
    } catch (err) {
      if (err instanceof Error && err.message === invalidTokenError) {
        res.status(400).json({ error: 'Invalid or expired invitation token.' });
        return;
      }

      next(err);
    }
  }
);

export default router;

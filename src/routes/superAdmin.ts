// =============================================================================
// THE INDEPENDENCE LAW FIRM — SUPER ADMIN ROUTER
// src/routes/superAdmin.ts
//
// Mounted at: /api/v1/super-admin  (see server.ts)
//
// All routes in this file are protected by requireSuperAdmin.
// Only lawyers with adminRole === 'SUPER_ADMIN' may access these endpoints.
//
// Routes:
//   GET  /api/v1/super-admin/staff         — List all internal staff members
//   POST /api/v1/super-admin/staff/invite  — Create a new staff (Lawyer) account
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient, AdminRole } from '@prisma/client';
import { requireSuperAdmin, LawyerRequest } from '../middleware/adminAuth';

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

// ── Router ────────────────────────────────────────────────────────────────────

const router = Router();

// Apply the super-admin RBAC guard to every route in this router.
router.use(requireSuperAdmin);

// =============================================================================
// GET /api/v1/super-admin/staff
//
// Returns a list of all internal staff members (Lawyer table rows).
// Password hashes are NEVER included in the response.
//
// Responses:
//   200  { staff: Array<{ id, name, email, role, createdAt }> }
//   401  — Missing / invalid JWT
//   403  — Valid JWT but not SUPER_ADMIN
//   500  — Internal server error
// =============================================================================

router.get(
  '/staff',
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const prisma = getPrisma();

      const staff = await prisma.lawyer.findMany({
        select: {
          id:        true,
          name:      true,
          email:     true,
          role:      true,
          createdAt: true,
        },
        orderBy: { createdAt: 'asc' },
      });

      res.status(200).json({ staff });
    } catch (err) {
      next(err);
    }
  }
);

// =============================================================================
// POST /api/v1/super-admin/staff/invite
//
// Creates a new Lawyer (staff) account in the database.
// A temporary default password is set; the staff member should change it on
// first login (password-reset flow to be implemented separately).
//
// Request body (JSON):
//   {
//     name:  string  — Full name of the new staff member   (required)
//     email: string  — Firm email address                  (required)
//     role:  string  — 'LAWYER' | 'SUPER_ADMIN'            (optional, default: 'LAWYER')
//   }
//
// Responses:
//   201  { staff: { id, name, email, role, createdAt } }
//   400  — Missing required fields or email already in use
//   401  — Missing / invalid JWT
//   403  — Valid JWT but not SUPER_ADMIN
//   500  — Internal server error
// =============================================================================

router.post(
  '/staff/invite',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { name, email, role } = req.body as {
        name?:  string;
        email?: string;
        role?:  string;
      };

      // ── Validate required fields ─────────────────────────────────────────────
      if (!name?.trim() || !email?.trim()) {
        res.status(400).json({ error: 'Name and email are required' });
        return;
      }

      const normalizedEmail = email.trim().toLowerCase();

      // ── Validate role value ──────────────────────────────────────────────────
      const allowedRoles: string[] = [AdminRole.LAWYER, AdminRole.SUPER_ADMIN];
      const assignedRole: AdminRole =
        role && allowedRoles.includes(role)
          ? (role as AdminRole)
          : AdminRole.LAWYER;

      const prisma = getPrisma();

      // ── Duplicate email check ────────────────────────────────────────────────
      const existing = await prisma.lawyer.findUnique({
        where: { email: normalizedEmail },
        select: { id: true },
      });

      if (existing) {
        res.status(400).json({ error: 'A staff account with that email already exists' });
        return;
      }

      // ── Hash a temporary default password ───────────────────────────────────
      // The staff member must update this via the password-reset flow before
      // their first login. The temporary value is never exposed in the response.
      const TEMP_PASSWORD = `TempPass!${Math.random().toString(36).slice(2, 10)}`;
      const passwordHash = await bcrypt.hash(TEMP_PASSWORD, 12);

      // ── Create the new staff record ──────────────────────────────────────────
      const newStaff = await prisma.lawyer.create({
        data: {
          name:         name.trim(),
          email:        normalizedEmail,
          role:         assignedRole,
          passwordHash,
        },
        select: {
          id:        true,
          name:      true,
          email:     true,
          role:      true,
          createdAt: true,
        },
      });

      console.log(
        `[superAdmin] New staff created: ${newStaff.name} (${newStaff.email}) — role: ${newStaff.role}`
      );

      res.status(201).json({ staff: newStaff });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

// =============================================================================
// THE INDEPENDENCE LAW FIRM — SUPER ADMIN ELEVATION SCRIPT
// src/scripts/setSuperAdmin.ts
//
// One-time initialization script: elevates info@steamworks.io to SUPER_ADMIN.
//
// Usage (from project root):
//   npx ts-node -r dotenv/config src/scripts/setSuperAdmin.ts
// =============================================================================

import dotenv from 'dotenv';
dotenv.config();

import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient, AdminRole } from '@prisma/client';

const SUPER_ADMIN_EMAIL = 'info@steamworks.io';

async function main(): Promise<void> {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL as string,
    ssl:
      process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
  });

  const adapter = new PrismaPg(pool);
  const prisma = new PrismaClient({ adapter });

  try {
    // ── Look up the target lawyer ─────────────────────────────────────────────
    const lawyer = await prisma.lawyer.findUnique({
      where: { email: SUPER_ADMIN_EMAIL },
      select: { id: true, name: true, email: true, role: true },
    });

    if (!lawyer) {
      console.error(
        `[setSuperAdmin] No lawyer found with email: ${SUPER_ADMIN_EMAIL}`
      );
      process.exit(1);
    }

    if (lawyer.role === AdminRole.SUPER_ADMIN) {
      console.log(
        `[setSuperAdmin] ${lawyer.name} (${lawyer.email}) is already SUPER_ADMIN — no update needed.`
      );
      return;
    }

    // ── Elevate to SUPER_ADMIN ────────────────────────────────────────────────
    const updated = await prisma.lawyer.update({
      where: { id: lawyer.id },
      data: { role: AdminRole.SUPER_ADMIN },
      select: { id: true, name: true, email: true, role: true },
    });

    console.log(
      `[setSuperAdmin] ✅  Successfully elevated ${updated.name} (${updated.email}) to ${updated.role}.`
    );
  } finally {
    await prisma.$disconnect();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[setSuperAdmin] Fatal error:', err);
  process.exit(1);
});

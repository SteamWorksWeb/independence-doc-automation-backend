import 'dotenv/config';

// =============================================================================
// scripts/seed-test-invitation.ts
//
// Creates a stable, known test invitation in the database for milestone
// and integration testing.
//
// Prerequisites:
//   - A Lawyer record must already exist (run seed-dummy-lawyer.js first).
//   - DATABASE_URL must be set in .env.
//
// Safe to re-run: if the token already exists the script exits cleanly.
//
// Usage:
//   npm run seed:invitation
// =============================================================================

import { Pool }        from 'pg';
import { PrismaPg }    from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

// ── Prisma client (pg Pool + PrismaPg adapter, matching prisma.config.ts) ────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL as string,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
});
const adapter = new PrismaPg(pool);
const prisma  = new PrismaClient({ adapter });

async function main(): Promise<void> {

  // ── 1. Require an existing Lawyer record ────────────────────────────────
  const lawyer = await prisma.lawyer.findFirst();

  if (!lawyer) {
    console.error('No lawyer found. Run seed-dummy-lawyer.js first.');
    process.exit(1);
  }

  // ── 2. Idempotency check — skip if token already exists ─────────────────
  const existing = await prisma.invitation.findUnique({
    where: { token: 'TEST-INVITATION-TOKEN-001' },
  });

  if (existing) {
    console.log('Test invitation already exists. Skipping.');
    process.exit(0);
  }

  // ── 3. Create the test invitation ───────────────────────────────────────
  const created = await prisma.invitation.create({
    data: {
      email:     'milestone1@steamworks.test',
      token:     'TEST-INVITATION-TOKEN-001',
      lawyerId:  lawyer.id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // +30 days
      isUsed:    false,
    },
  });

  // ── 4. Report ────────────────────────────────────────────────────────────
  console.log('Test invitation created:');
  console.log('  ID:       ', created.id);
  console.log('  Email:    ', created.email);
  console.log('  Token:    ', created.token);
  console.log('  LawyerId: ', created.lawyerId);
  console.log('  Expires:  ', created.expiresAt);

  // ── 5. Disconnect ────────────────────────────────────────────────────────
  await prisma.$disconnect();
}

main();

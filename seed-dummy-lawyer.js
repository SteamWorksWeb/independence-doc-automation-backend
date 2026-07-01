/**
 * seed-dummy-lawyer.js
 *
 * Creates a single dummy Lawyer record directly via the Prisma client,
 * then prints the UUID so you can paste it into your frontend .env.local
 * as DEFAULT_LAWYER_ID.
 *
 * ── Prerequisites ────────────────────────────────────────────────────────────
 *   1. Run this from the BACKEND directory:
 *      cd "Independence Law - Backend"
 *      node seed-dummy-lawyer.js
 *
 *   2. The backend .env must have a valid DATABASE_URL pointing to the
 *      running PostgreSQL instance (AWS RDS or local).
 *
 *   3. Prisma migration must have been applied:
 *      npx prisma migrate dev --name init_database_vault
 *
 * ── What it does ─────────────────────────────────────────────────────────────
 *   - Imports @prisma/client (already installed in the backend)
 *   - Creates one Lawyer record with placeholder credentials
 *   - Prints the UUID — copy this to .env.local as DEFAULT_LAWYER_ID
 *
 * ── After running ─────────────────────────────────────────────────────────────
 *   Copy the UUID printed below into your frontend .env.local:
 *     DEFAULT_LAWYER_ID=<the-uuid-printed-here>
 *
 *   Then restart the Next.js dev server:
 *     npm run dev
 */

require("dotenv").config();
const { PrismaClient } = require("@prisma/client");
const { PrismaPg }    = require("@prisma/adapter-pg");
const { Pool }        = require("pg");

const pool    = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma  = new PrismaClient({ adapter });

async function main() {
  console.log("🌱  Seeding dummy lawyer record…\n");

  // Check if a dummy lawyer already exists to avoid duplicates
  const existing = await prisma.lawyer.findFirst({
    where: { email: "dev-lawyer@independence-law-test.local" },
  });

  if (existing) {
    console.log("✅  Dummy lawyer already exists:");
    console.log(`    UUID: ${existing.id}`);
    console.log(`    Name: ${existing.name}`);
    console.log(`    Email: ${existing.email}`);
    console.log("");
    console.log("📋  Copy this into your frontend .env.local:");
    console.log(`    DEFAULT_LAWYER_ID=${existing.id}`);
    return;
  }

  const lawyer = await prisma.lawyer.create({
    data: {
      name:         "Dev Placeholder Attorney",
      email:        "dev-lawyer@independence-law-test.local",
      // bcrypt hash of "dev-placeholder-password" (cost 12) — dev use only
      passwordHash: "$2b$12$devplaceholderXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    },
  });

  console.log("✅  Dummy lawyer created successfully:");
  console.log(`    UUID:  ${lawyer.id}`);
  console.log(`    Name:  ${lawyer.name}`);
  console.log(`    Email: ${lawyer.email}`);
  console.log("");
  console.log("─────────────────────────────────────────────────────");
  console.log("📋  Add this line to your FRONTEND .env.local:");
  console.log("");
  console.log(`    DEFAULT_LAWYER_ID=${lawyer.id}`);
  console.log("");
  console.log("─────────────────────────────────────────────────────");
  console.log("Then restart the Next.js dev server: npm run dev");
}

main()
  .catch((err) => {
    console.error("❌  Seed failed:", err.message ?? err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

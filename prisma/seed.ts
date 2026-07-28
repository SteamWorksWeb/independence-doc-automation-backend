/**
 * prisma/seed.ts
 *
 * Canonical database seeder for development and integration testing.
 * Inserts all foundational test data in a single idempotent run:
 *
 *   1. Admin Staff Lawyer  — admin@independencelaw.com
 *   2. Sample Client #1    — John Doe  (with DischargeSnapshot, fully analysed)
 *   3. Sample Client #2    — Jane Doe (with DischargeSnapshot, incomplete)
 *   4. Active Intake Token — Tied to Jane Doe for registration testing
 *
 * ── Idempotency ───────────────────────────────────────────────────────────────
 *   All records use upsert on unique fields (email / token) so the script
 *   can be re-run safely without duplicate-key errors.
 *
 * ── Usage ─────────────────────────────────────────────────────────────────────
 *   npx prisma db seed          (via the "prisma.seed" key in package.json)
 *   npx ts-node prisma/seed.ts  (direct invocation)
 *
 * ── Prerequisites ─────────────────────────────────────────────────────────────
 *   DATABASE_URL must be set in .env
 *   Migrations must be applied (npx prisma migrate deploy)
 * =============================================================================
 */

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg }     from "@prisma/adapter-pg";
import { Pool }         from "pg";
import bcrypt           from "bcrypt";

// ── Prisma 7: driver-adapter connection (mirrors prisma.config.ts) ────────────
const pool    = new Pool({ connectionString: process.env["DATABASE_URL"] });
const adapter = new PrismaPg(pool);
const prisma  = new PrismaClient({ adapter });

// ── Constants ─────────────────────────────────────────────────────────────────
const BCRYPT_COST           = 12;
const ADMIN_EMAIL           = "admin@independencelaw.com";
const ADMIN_PASSWORD        = "Admin2024!";
const JOHN_EMAIL            = "john.doe@example.com";
const JANE_EMAIL            = "jane@example.com";
const TEST_INVITE_TOKEN     = "test-intake-token-123";
const INVITE_EXPIRY_DAYS    = 30;

async function main(): Promise<void> {
  console.log("🌱  Seeding Independence Law database…\n");

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. ADMIN STAFF LAWYER
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("── Step 1: Admin Staff Lawyer ──────────────────────────────────");

  const adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, BCRYPT_COST);

  const adminLawyer = await prisma.lawyer.upsert({
    where: { email: ADMIN_EMAIL },
    create: {
      name:         "Admin Staff",
      email:        ADMIN_EMAIL,
      passwordHash: adminPasswordHash,
    },
    update: {
      name:         "Admin Staff",
      passwordHash: adminPasswordHash,
    },
  });

  console.log(`   ✅ Lawyer upserted: ${adminLawyer.name} (${adminLawyer.email})`);
  console.log(`      ID: ${adminLawyer.id}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. SAMPLE CLIENT #1 — John Doe (registered, verified, with snapshot)
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("\n── Step 2: John Doe (registered client) ───────────────────────");

  const johnPasswordHash = await bcrypt.hash("JohnDoe2024!", BCRYPT_COST);

  const johnDoe = await prisma.client.upsert({
    where: { email: JOHN_EMAIL },
    create: {
      name:         "John Doe",
      email:        JOHN_EMAIL,
      phone:        "(555) 123-4567",
      passwordHash: johnPasswordHash,
      isVerified:   true,
      status:       "Ready for Review",
      lawyerId:     adminLawyer.id,
    },
    update: {
      name:         "John Doe",
      phone:        "(555) 123-4567",
      passwordHash: johnPasswordHash,
      isVerified:   true,
      status:       "Ready for Review",
      lawyerId:     adminLawyer.id,
    },
    include: { dischargeSnapshots: true },
  });

  console.log(`   ✅ Client upserted: ${johnDoe.name} (${johnDoe.email})`);
  console.log(`      ID: ${johnDoe.id}`);

  // ── John Doe's DischargeSnapshot (analysed — dischargeable) ────────────────
  // Delete existing snapshots to avoid duplicates on re-run, then recreate.
  await prisma.dischargeSnapshot.deleteMany({
    where: { clientId: johnDoe.id },
  });

  const johnSnapshot = await prisma.dischargeSnapshot.create({
    data: {
      clientId:               johnDoe.id,
      hasFederalLoans:        "yes",
      principalBalance:       85000,
      householdSize:          3,
      monthlyGrossIncome:     3200,
      monthlyTakeHomePay:     2500,
      additionalIncome:       0,
      housingExpenses:        1200,
      transportationExpenses: 350,
      dependentCareExpenses:  400,
      isEmployed:             true,
      workInFieldOfStudy:     false,
      unemployed5PlusYears:   false,
      hasDisability:          true,
      didGraduate:            true,
      schoolClosed:           false,
      is65OrOlder:            false,
      isDischargeable:        true,
      status:                 "Analyzed",
    },
  });

  console.log(`   ✅ DischargeSnapshot created: ${johnSnapshot.id}`);
  console.log(`      isDischargeable: ${johnSnapshot.isDischargeable}`);
  console.log(`      status: ${johnSnapshot.status}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. SAMPLE CLIENT #2 — Jane Doe (pre-registration, unverified)
  //    This client exists but hasn't set a password yet — the invite flow
  //    will allow her to register via the test invite token.
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("\n── Step 3: Jane Doe (pending registration) ────────────────────");

  // Placeholder hash — will be replaced when Jane registers via invite token.
  const placeholderHash = await bcrypt.hash("PLACEHOLDER_NOT_FOR_LOGIN", BCRYPT_COST);

  const janeDoe = await prisma.client.upsert({
    where: { email: JANE_EMAIL },
    create: {
      name:         "Jane Doe",
      email:        JANE_EMAIL,
      phone:        "(555) 987-6543",
      passwordHash: placeholderHash,
      isVerified:   false,      // Not yet registered — invite pending
      status:       "Intake Pending",
      lawyerId:     adminLawyer.id,
    },
    update: {
      name:         "Jane Doe",
      phone:        "(555) 987-6543",
      // Do NOT overwrite passwordHash on update — she may have already registered
      isVerified:   false,
      status:       "Intake Pending",
      lawyerId:     adminLawyer.id,
    },
    include: { dischargeSnapshots: true },
  });

  console.log(`   ✅ Client upserted: ${janeDoe.name} (${janeDoe.email})`);
  console.log(`      ID: ${janeDoe.id}`);
  console.log(`      isVerified: ${janeDoe.isVerified} (pending invite registration)`);

  // ── Jane Doe's DischargeSnapshot (incomplete — awaiting analysis) ──────────
  await prisma.dischargeSnapshot.deleteMany({
    where: { clientId: janeDoe.id },
  });

  const janeSnapshot = await prisma.dischargeSnapshot.create({
    data: {
      clientId:               janeDoe.id,
      hasFederalLoans:        "yes",
      principalBalance:       42000,
      householdSize:          1,
      monthlyGrossIncome:     2800,
      monthlyTakeHomePay:     2100,
      additionalIncome:       200,
      housingExpenses:        950,
      transportationExpenses: 150,
      dependentCareExpenses:  0,
      isEmployed:             false,
      workInFieldOfStudy:     false,
      unemployed5PlusYears:   true,
      hasDisability:          false,
      didGraduate:            false,
      schoolClosed:           true,
      is65OrOlder:            false,
      isDischargeable:        null,  // Not yet analysed
      status:                 "Incomplete",
    },
  });

  console.log(`   ✅ DischargeSnapshot created: ${janeSnapshot.id}`);
  console.log(`      isDischargeable: ${janeSnapshot.isDischargeable} (not yet analysed)`);
  console.log(`      status: ${janeSnapshot.status}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. ACTIVE INTAKE TOKEN — Tied to Jane Doe
  //    Token: "test-intake-token-123"
  //    Used in integration tests for GET /api/v1/auth/invite/verify
  //    and POST /api/v1/auth/intake/setup-password
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("\n── Step 4: Active Intake Token ─────────────────────────────────");

  // Delete any existing invitation with this token (for clean re-runs)
  await prisma.invitation.deleteMany({
    where: { token: TEST_INVITE_TOKEN },
  });

  // Also clean up any prior invitations for Jane's email to avoid confusion
  await prisma.invitation.deleteMany({
    where: { email: JANE_EMAIL },
  });

  const invitation = await prisma.invitation.create({
    data: {
      email:     JANE_EMAIL,
      token:     TEST_INVITE_TOKEN,
      lawyerId:  adminLawyer.id,
      expiresAt: new Date(Date.now() + INVITE_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
      isUsed:    false,
    },
  });

  console.log(`   ✅ Invitation created`);
  console.log(`      ID:        ${invitation.id}`);
  console.log(`      Email:     ${invitation.email}`);
  console.log(`      Token:     ${invitation.token}`);
  console.log(`      Expires:   ${invitation.expiresAt.toISOString()}`);
  console.log(`      isUsed:    ${invitation.isUsed}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("\n═══════════════════════════════════════════════════════════════");
  console.log("✅  DATABASE SEED COMPLETE");
  console.log("═══════════════════════════════════════════════════════════════");
  console.log("");
  console.log("  📌 Admin Lawyer");
  console.log(`     Email:    ${ADMIN_EMAIL}`);
  console.log(`     Password: ${ADMIN_PASSWORD}`);
  console.log(`     ID:       ${adminLawyer.id}`);
  console.log("");
  console.log("  📌 Client: John Doe (registered, verified)");
  console.log(`     Email:    ${JOHN_EMAIL}`);
  console.log(`     ID:       ${johnDoe.id}`);
  console.log("");
  console.log("  📌 Client: Jane Doe (pending registration)");
  console.log(`     Email:    ${JANE_EMAIL}`);
  console.log(`     ID:       ${janeDoe.id}`);
  console.log("");
  console.log("  📌 Intake Token (for Jane Doe)");
  console.log(`     Token:    ${TEST_INVITE_TOKEN}`);
  console.log(`     Verify:   GET /api/v1/auth/invite/verify?token=${TEST_INVITE_TOKEN}`);
  console.log(`     Register: POST /api/v1/auth/intake/setup-password { token, password }`);
  console.log("");
  console.log("═══════════════════════════════════════════════════════════════\n");
}

main()
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error("\n❌  Seed failed:", message);
    if (err instanceof Error && err.stack) {
      console.error(err.stack);
    }
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });

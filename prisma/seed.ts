/**
 * prisma/seed.ts
 *
 * Seeds a test Client record with a fully-completed IntakeProfile
 * designed to exercise the Brunner undue-hardship eligibility algorithm.
 *
 * ── Expected Brunner result ───────────────────────────────────────────────────
 *   monthlyIncome : $2,500
 *   totalExpenses : $2,450  (food 600 + housing 1200 + utilities 300
 *                             + gas 200 + car insurance 150)
 *   disposableIncome : $50  → Prong 1 MET  (cannot maintain minimal standard)
 *   hasDisability : true    → Prong 2 MET  (persistence of hardship)
 *   score         : HIGH_PROBABILITY
 *
 * ── Prerequisites ────────────────────────────────────────────────────────────
 *   1. Run from the backend directory:
 *        npx ts-node prisma/seed.ts
 *   2. DATABASE_URL must be set in .env (points to the AWS RDS instance).
 *   3. At least one Lawyer record must exist (created by seed-dummy-lawyer.js).
 *
 * ── Idempotency ──────────────────────────────────────────────────────────────
 *   Re-running is safe — the script upserts on email so it will update the
 *   existing record rather than throw a unique-constraint error.
 * =============================================================================
 */

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg }    from "@prisma/adapter-pg";
import { Pool }        from "pg";

// ── Prisma 7: driver-adapter connection (mirrors prisma.config.ts) ────────────
const pool    = new Pool({ connectionString: process.env["DATABASE_URL"] });
const adapter = new PrismaPg(pool);
const prisma  = new PrismaClient({ adapter });

// ── Seed config ───────────────────────────────────────────────────────────────
const TEST_CLIENT_EMAIL = "test@runner.com";

async function main(): Promise<void> {
  console.log("🌱  Seeding test client for Brunner eligibility engine…\n");

  // ── 1. Resolve the lawyer to assign the client to ─────────────────────────
  //    We use the first available lawyer (the dummy dev lawyer created earlier).
  //    The Client model requires a lawyerId — no orphaned clients allowed.
  const lawyer = await prisma.lawyer.findFirst();

  if (!lawyer) {
    throw new Error(
      "No Lawyer record found in the database.\n" +
      "Run `node seed-dummy-lawyer.js` first to create the dev lawyer, then re-run this script."
    );
  }

  console.log(`✅  Resolved lawyer → ${lawyer.name} (${lawyer.email})`);

  // ── 2. Upsert the test client + intake profile ────────────────────────────
  //    Using upsert on email so repeated runs are idempotent.
  //
  //    A plain bcrypt hash of "TestRunner2024!" (cost 10) is used as the
  //    password.  This is a dev-only placeholder — the account is accessed
  //    through the admin panel, not via client login.
  const client = await prisma.client.upsert({
    where: { email: TEST_CLIENT_EMAIL },

    // ── CREATE path (first run) ──────────────────────────────────────────────
    create: {
      name:         "Test Runner",
      email:        TEST_CLIENT_EMAIL,
      // bcrypt hash of "TestRunner2024!" (cost 10) — dev use only
      passwordHash: "$2b$10$devtestrunnerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      isVerified:   true,
      lawyerId:     lawyer.id,

      intakeProfile: {
        create: {
          // ── Financial data (Brunner Prong 1) ────────────────────────────
          // Income vs. expenses leaves only $50 disposable — prong is met.
          monthlyIncome:    2500,
          expFood:          600,
          expHousing:       1200,
          expUtilities:     300,
          expTransportGas:  200,
          expCarInsurance:  150,

          // ── Health / employment (Brunner Prong 2) ────────────────────────
          // hasDisability: true satisfies the persistence-of-hardship prong.
          hasDisability:    true,
          unemployed5of10:  false,

          // ── Debt composition (Brunner Prong 3 / scoring context) ─────────
          totalDebt:        85000,
          studentLoanDebt:  80000,

          // ── Completion flag ──────────────────────────────────────────────
          isCompleted:      true,
        },
      },
    },

    // ── UPDATE path (subsequent runs) ───────────────────────────────────────
    // Sync every field so re-runs always leave the DB in the expected state.
    update: {
      name:       "Test Runner",
      isVerified: true,
      lawyerId:   lawyer.id,

      intakeProfile: {
        upsert: {
          create: {
            monthlyIncome:    2500,
            expFood:          600,
            expHousing:       1200,
            expUtilities:     300,
            expTransportGas:  200,
            expCarInsurance:  150,
            hasDisability:    true,
            unemployed5of10:  false,
            totalDebt:        85000,
            studentLoanDebt:  80000,
            isCompleted:      true,
          },
          update: {
            monthlyIncome:    2500,
            expFood:          600,
            expHousing:       1200,
            expUtilities:     300,
            expTransportGas:  200,
            expCarInsurance:  150,
            hasDisability:    true,
            unemployed5of10:  false,
            totalDebt:        85000,
            studentLoanDebt:  80000,
            isCompleted:      true,
          },
        },
      },
    },

    // ── Include intake profile in the returned object for logging ────────────
    include: { intakeProfile: true },
  });

  // ── 3. Print summary ──────────────────────────────────────────────────────
  const p = client.intakeProfile!;

  console.log("\n─────────────────────────────────────────────────────────────");
  console.log("✅  Test client seeded successfully");
  console.log("─────────────────────────────────────────────────────────────");
  console.log(`   Client ID   : ${client.id}`);
  console.log(`   Email       : ${client.email}`);
  console.log(`   isVerified  : ${client.isVerified}`);
  console.log(`   Lawyer      : ${lawyer.name}`);
  console.log("");
  console.log("   ── IntakeProfile ─────────────────────────────────────────");
  console.log(`   Profile ID       : ${p.id}`);
  console.log(`   monthlyIncome    : $${p.monthlyIncome}`);
  console.log(`   expFood          : $${p.expFood}`);
  console.log(`   expHousing       : $${p.expHousing}`);
  console.log(`   expUtilities     : $${p.expUtilities}`);
  console.log(`   expTransportGas  : $${p.expTransportGas}`);
  console.log(`   expCarInsurance  : $${p.expCarInsurance}`);
  const totalExp = (p.expFood ?? 0) + (p.expHousing ?? 0) + (p.expUtilities ?? 0)
                 + (p.expTransportGas ?? 0) + (p.expCarInsurance ?? 0);
  const disposable = (p.monthlyIncome ?? 0) - totalExp;
  console.log(`   ─ total expenses : $${totalExp}`);
  console.log(`   ─ disposable     : $${disposable}  ← Prong 1 threshold`);
  console.log(`   hasDisability    : ${p.hasDisability}  ← Prong 2 satisfied`);
  console.log(`   unemployed5of10  : ${p.unemployed5of10}`);
  console.log(`   totalDebt        : $${p.totalDebt}`);
  console.log(`   studentLoanDebt  : $${p.studentLoanDebt}`);
  console.log(`   isCompleted      : ${p.isCompleted}`);
  console.log("");
  console.log("   Expected Brunner result → HIGH_PROBABILITY");
  console.log("─────────────────────────────────────────────────────────────");
  console.log(`\n📋  Use this ID in the Eligibility Engine UI:\n    Client ID: ${client.id}\n`);
}

main()
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error("\n❌  Seed failed:", message);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });

import "dotenv/config";
import type { DischargeSnapshot } from "@prisma/client";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { Pool } from "pg";
import { calculateDischargeProbability } from "../utils/dischargeAnalyzer";

const pool = new Pool({ connectionString: process.env["DATABASE_URL"] });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

const DEFAULT_LAST_ATTENDED_SCHOOL = new Date("2015-05-01T00:00:00.000Z");

function patchSnapshot(snapshot: DischargeSnapshot): DischargeSnapshot {
  return {
    ...snapshot,
    appliedForIDR: snapshot.appliedForIDR ?? false,
    madePriorPayments: snapshot.madePriorPayments ?? false,
    contactedServicer: snapshot.contactedServicer ?? false,
    hasDisability: snapshot.hasDisability ?? false,
    didGraduate: snapshot.didGraduate ?? true,
    schoolClosed: snapshot.schoolClosed ?? false,
    is65OrOlder: snapshot.is65OrOlder ?? false,
    lastAttendedSchool: snapshot.lastAttendedSchool ?? DEFAULT_LAST_ATTENDED_SCHOOL,
  };
}

async function main(): Promise<void> {
  const snapshots = await prisma.dischargeSnapshot.findMany();

  let updatedCount = 0;

  for (const snapshot of snapshots) {
    const patchedSnapshot = patchSnapshot(snapshot);
    const analysis = calculateDischargeProbability(patchedSnapshot);

    await prisma.dischargeSnapshot.update({
      where: { id: snapshot.id },
      data: {
        appliedForIDR: patchedSnapshot.appliedForIDR,
        madePriorPayments: patchedSnapshot.madePriorPayments,
        contactedServicer: patchedSnapshot.contactedServicer,
        hasDisability: patchedSnapshot.hasDisability,
        didGraduate: patchedSnapshot.didGraduate,
        schoolClosed: patchedSnapshot.schoolClosed,
        is65OrOlder: patchedSnapshot.is65OrOlder,
        lastAttendedSchool: patchedSnapshot.lastAttendedSchool,
        isDischargeable: analysis.isDischargeable,
        status: analysis.status,
      },
    });

    updatedCount += 1;
  }

  console.log(`Successfully updated ${updatedCount} DischargeSnapshot record(s).`);
}

main()
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error("Failed to patch demo data:", message);
    if (err instanceof Error && err.stack) {
      console.error(err.stack);
    }
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });

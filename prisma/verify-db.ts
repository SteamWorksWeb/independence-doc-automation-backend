/**
 * prisma/verify-db.ts
 *
 * Read-only diagnostic: lists every Client in the database with their
 * email and intake-profile completion status.  Makes NO writes.
 */

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg }    from "@prisma/adapter-pg";
import { Pool }        from "pg";

const pool    = new Pool({ connectionString: process.env["DATABASE_URL"] });
const adapter = new PrismaPg(pool);
const prisma  = new PrismaClient({ adapter });

async function main(): Promise<void> {
  const clients = await prisma.client.findMany({
    select: {
      email: true,
      intakeProfile: {
        select: { isCompleted: true },
      },
    },
  });

  console.log(JSON.stringify(clients, null, 2));
}

main()
  .catch((err: unknown) => {
    console.error("❌  Query failed:", err instanceof Error ? err.message : String(err));
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });

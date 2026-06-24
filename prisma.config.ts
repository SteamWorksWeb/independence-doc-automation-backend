/**
 * prisma.config.ts
 *
 * Prisma 7 configuration — connection URL lives here, not in schema.prisma.
 * dotenv/config is loaded first so DATABASE_URL is available from .env.
 *
 * See: https://pris.ly/d/config-datasource
 */
import "dotenv/config";
import { defineConfig } from "prisma/config";

const databaseUrl = process.env["DATABASE_URL"];

if (!databaseUrl) {
  throw new Error(
    "[prisma.config] DATABASE_URL is not set. " +
    "Copy .env.example to .env and configure your PostgreSQL connection string."
  );
}

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    url: databaseUrl,
  },
});

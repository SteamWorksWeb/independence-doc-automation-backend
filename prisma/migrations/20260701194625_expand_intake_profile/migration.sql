/*
  Warnings:

  - You are about to drop the column `employmentStatus` on the `intake_profiles` table. All the data in the column will be lost.
  - You are about to drop the column `loanTypes` on the `intake_profiles` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "intake_profiles" DROP COLUMN "employmentStatus",
DROP COLUMN "loanTypes",
ADD COLUMN     "county" TEXT,
ADD COLUMN     "dob" TEXT,
ADD COLUMN     "expApparel" DOUBLE PRECISION,
ADD COLUMN     "expCarInsurance" DOUBLE PRECISION,
ADD COLUMN     "expFood" DOUBLE PRECISION,
ADD COLUMN     "expHousekeeping" DOUBLE PRECISION,
ADD COLUMN     "expHousing" DOUBLE PRECISION,
ADD COLUMN     "expPersonalCare" DOUBLE PRECISION,
ADD COLUMN     "expTransportGas" DOUBLE PRECISION,
ADD COLUMN     "expUtilities" DOUBLE PRECISION,
ADD COLUMN     "expectingRefund" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "hasCar" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "hasDisability" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "hasRetirement" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "householdSize" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "housingStatus" TEXT,
ADD COLUMN     "isEmployed" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "schoolsHistory" TEXT,
ADD COLUMN     "ssn" TEXT,
ADD COLUMN     "unemployed5of10" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "unmetBasicNeeds" TEXT;

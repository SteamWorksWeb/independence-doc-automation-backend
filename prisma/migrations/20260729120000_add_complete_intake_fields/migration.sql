-- AlterTable
ALTER TABLE "clients"
ADD COLUMN     "intakeStatus" TEXT NOT NULL DEFAULT 'Incomplete';

-- AlterTable
ALTER TABLE "discharge_snapshots"
ADD COLUMN     "ownsVehicle" BOOLEAN,
ADD COLUMN     "militaryBranch" TEXT,
ADD COLUMN     "militaryStartDate" TIMESTAMP(3),
ADD COLUMN     "militaryEndDate" TIMESTAMP(3),
ADD COLUMN     "dischargeCharacterization" TEXT;

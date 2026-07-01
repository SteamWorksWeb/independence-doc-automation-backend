-- CreateTable
CREATE TABLE "intake_profiles" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "phone" TEXT,
    "address" TEXT,
    "employmentStatus" TEXT,
    "monthlyIncome" DOUBLE PRECISION,
    "totalDebt" DOUBLE PRECISION,
    "studentLoanDebt" DOUBLE PRECISION,
    "loanTypes" TEXT,
    "hardshipNotes" TEXT,
    "isCompleted" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "intake_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "intake_profiles_clientId_key" ON "intake_profiles"("clientId");

-- AddForeignKey
ALTER TABLE "intake_profiles" ADD CONSTRAINT "intake_profiles_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

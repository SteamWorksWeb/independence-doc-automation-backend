/*
  Warnings:

  - Added the required column `lawyerId` to the `invitations` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "invitations" ADD COLUMN     "lawyerId" TEXT NOT NULL;

-- CreateIndex
CREATE INDEX "invitations_lawyerId_idx" ON "invitations"("lawyerId");

-- AddForeignKey
ALTER TABLE "invitations" ADD CONSTRAINT "invitations_lawyerId_fkey" FOREIGN KEY ("lawyerId") REFERENCES "lawyers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

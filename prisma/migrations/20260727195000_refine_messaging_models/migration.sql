-- DropForeignKey
ALTER TABLE "conversation_messages" DROP CONSTRAINT "conversation_messages_conversationId_fkey";

-- DropForeignKey
ALTER TABLE "conversation_messages" DROP CONSTRAINT "conversation_messages_senderId_fkey";

-- DropForeignKey
ALTER TABLE "conversations" DROP CONSTRAINT "conversations_clientId_fkey";

-- DropForeignKey
ALTER TABLE "messages" DROP CONSTRAINT "messages_clientId_fkey";

-- DropForeignKey
ALTER TABLE "messages" DROP CONSTRAINT "messages_lawyerId_fkey";

-- DropIndex
DROP INDEX "conversations_clientId_idx";

-- DropIndex
DROP INDEX "messages_clientId_createdAt_idx";

-- DropIndex
DROP INDEX "messages_clientId_idx";

-- AlterTable
ALTER TABLE "conversations" DROP COLUMN "clientId",
DROP COLUMN "subject",
ADD COLUMN     "assignedToId" TEXT,
ADD COLUMN     "borrowerId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "messages" DROP COLUMN "clientId",
DROP COLUMN "content",
DROP COLUMN "lawyerId",
ADD COLUMN     "body" TEXT NOT NULL,
ADD COLUMN     "conversationId" TEXT NOT NULL,
ADD COLUMN     "deletedAt" TIMESTAMP(3),
ADD COLUMN     "senderUserId" TEXT,
ADD COLUMN     "visibility" "Visibility" NOT NULL DEFAULT 'CLIENT_VISIBLE',
DROP COLUMN "senderType",
ADD COLUMN     "senderType" "SenderType" NOT NULL;

-- DropTable
DROP TABLE "conversation_messages";

-- CreateTable
CREATE TABLE "message_reads" (
    "messageId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "readAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "message_reads_pkey" PRIMARY KEY ("messageId","userId")
);

-- CreateTable
CREATE TABLE "conversation_access_logs" (
    "id" TEXT NOT NULL,
    "conversationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "viewedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "conversation_access_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "conversation_access_logs_conversationId_idx" ON "conversation_access_logs"("conversationId");

-- CreateIndex
CREATE UNIQUE INDEX "conversations_borrowerId_key" ON "conversations"("borrowerId");

-- CreateIndex
CREATE INDEX "conversations_assignedToId_idx" ON "conversations"("assignedToId");

-- CreateIndex
CREATE INDEX "messages_conversationId_idx" ON "messages"("conversationId");

-- CreateIndex
CREATE INDEX "messages_conversationId_createdAt_idx" ON "messages"("conversationId", "createdAt");

-- AddForeignKey
ALTER TABLE "messages" ADD CONSTRAINT "messages_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "conversations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "message_reads" ADD CONSTRAINT "message_reads_messageId_fkey" FOREIGN KEY ("messageId") REFERENCES "messages"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "conversation_access_logs" ADD CONSTRAINT "conversation_access_logs_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "conversations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "conversations" ADD CONSTRAINT "conversations_borrowerId_fkey" FOREIGN KEY ("borrowerId") REFERENCES "clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "conversations" ADD CONSTRAINT "conversations_assignedToId_fkey" FOREIGN KEY ("assignedToId") REFERENCES "lawyers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

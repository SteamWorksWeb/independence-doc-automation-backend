-- Add userType discriminator to clients table
-- LEAD = invited borrower (intake flow, not yet promoted)
-- CLIENT = manually promoted by lawyer/admin
ALTER TABLE clients ADD COLUMN IF NOT EXISTS "userType" TEXT NOT NULL DEFAULT 'LEAD';

-- Promote all pre-existing records to CLIENT.
-- These were created before this feature existed and belong on the Client roster.
UPDATE clients SET "userType" = 'CLIENT';

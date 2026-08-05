/**
 * scratch/send-demo-email.ts
 * One-shot demo email sender — not committed to production code.
 * Run with: npx tsx scratch/send-demo-email.ts
 */
import 'dotenv/config';
import { sendInviteEmail, sendBorrowerInviteEmail } from '../src/utils/email';

const DEMO_TO        = 'info@steamworks.io';
const DEMO_INVITE    = 'https://independence-doc-automation.vercel.app/login?token=DEMO_TOKEN_NOT_VALID';
const DEMO_INTAKE    = 'https://independence-doc-automation.vercel.app/intake?token=DEMO_TOKEN_NOT_VALID';

async function main() {
  console.log(`\nSending demo invite email to ${DEMO_TO}…`);
  await sendInviteEmail(DEMO_TO, DEMO_INVITE);
  console.log('✅ Client portal invite email sent.\n');

  console.log(`Sending demo borrower intake email to ${DEMO_TO}…`);
  await sendBorrowerInviteEmail(DEMO_TO, DEMO_INTAKE);
  console.log('✅ Borrower intake email sent.\n');
}

main().catch((err) => {
  console.error('❌ Error sending demo email:', err);
  process.exit(1);
});

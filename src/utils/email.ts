// =============================================================================
// THE INDEPENDENCE LAW FIRM — EMAIL UTILITY
// src/utils/email.ts
//
// Responsibilities:
//   - Initialise the Resend client using RESEND_API_KEY from env.
//   - Export sendVerificationEmail() for the authentication flow.
//
// Security notes:
//   - RESEND_API_KEY is read exclusively from env — never hardcoded.
//   - The magic-link token is a one-time-use UUID hashed server-side.
//   - The 'from' address is hardcoded to the firm's verified Resend domain:
//     apply@theindependencelaw.com
//     (Do NOT change this to onboarding@resend.dev — that sandbox address
//      silently fails for all recipients except the API key owner.)
//
// Template origin: Independence Law brand palette — navy / gold / off-white.
// =============================================================================

import { Resend } from 'resend';

// ── Env guard ─────────────────────────────────────────────────────────────────
// These are validated at server startup in server.ts. We re-check here so
// the utility can also be imported safely in tests / scripts.
const RESEND_API_KEY = process.env.RESEND_API_KEY;

if (!RESEND_API_KEY) {
  throw new Error('[email] FATAL: RESEND_API_KEY environment variable is not set.');
}

// Hardcoded to the firm's verified Resend domain.
// Do NOT revert to onboarding@resend.dev (Resend sandbox — silently fails
// for all recipients who are not the API-key owner).
const FROM_ADDRESS = 'The Independence Law Firm <apply@theindependencelaw.com>';

// ── Resend client (singleton) ─────────────────────────────────────────────────
const resend = new Resend(RESEND_API_KEY);

// ── Frontend base URL ─────────────────────────────────────────────────────────
// In production this will be the Vercel deployment URL.
// Controlled via FRONTEND_URL env var; falls back to localhost for development.
const FRONTEND_URL = process.env.FRONTEND_URL ?? 'http://localhost:3000';

// =============================================================================
// sendVerificationEmail
//
// Sends the magic-link verification email to a newly registered client.
//
// @param toEmail  — The client's email address (recipient).
// @param token    — The raw UUID token (NOT hashed). It is embedded in the URL
//                   so the client can click it. The backend stores the HASH.
// =============================================================================
export async function sendVerificationEmail(
  toEmail: string,
  token: string,
): Promise<void> {
  const verifyUrl = `${FRONTEND_URL}/verify?token=${token}`;

  const html = buildVerificationEmailHtml(verifyUrl);

  let sendError: unknown;

  try {
    const { error } = await resend.emails.send({
      from:    FROM_ADDRESS,
      to:      toEmail,
      subject: 'Verify your Independence Law Portal access',
      html,
    });

    if (error) {
      sendError = error;
    }
  } catch (err) {
    console.error('RESEND API ERROR:', err);
    throw new Error(`[email] Unexpected error calling Resend SDK: ${String(err)}`);
  }

  if (sendError) {
    console.error('RESEND API ERROR:', sendError);
    throw new Error(
      `[email] Failed to send verification email: ${
        (sendError as { message?: string }).message ?? String(sendError)
      }`
    );
  }

  console.log(`[email] Verification email dispatched to ${toEmail} via ${FROM_ADDRESS}`);
}

// =============================================================================
// buildVerificationEmailHtml (private)
//
// Returns a self-contained HTML string. Inline styles are intentional —
// most email clients strip <style> blocks.
//
// Brand palette:
//   Navy  #0D1B2A  (primary background, header)
//   Gold  #C9A84C  (accent, CTA button)
//   Light #F5F1EB  (body background)
//   White #FFFFFF  (card background)
//   Text  #2D2D2D  (body text)
// =============================================================================
function buildVerificationEmailHtml(verifyUrl: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Verify your Independence Law Portal access</title>
</head>
<body style="
  margin: 0;
  padding: 0;
  background-color: #F5F1EB;
  font-family: Georgia, 'Times New Roman', serif;
  color: #2D2D2D;
">

  <!-- Outer wrapper -->
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>
      <td align="center" style="padding: 40px 16px;">

        <!-- Card -->
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
               style="max-width: 600px; width: 100%; background-color: #FFFFFF;
                      border-radius: 4px; overflow: hidden;
                      box-shadow: 0 2px 8px rgba(0,0,0,0.10);">

          <!-- Header -->
          <tr>
            <td style="
              background-color: #0D1B2A;
              padding: 36px 40px;
              text-align: center;
            ">
              <!-- Wordmark -->
              <p style="
                margin: 0;
                font-size: 11px;
                letter-spacing: 4px;
                text-transform: uppercase;
                color: #C9A84C;
                font-family: Arial, Helvetica, sans-serif;
              ">THE INDEPENDENCE LAW FIRM</p>
              <h1 style="
                margin: 10px 0 0;
                font-size: 26px;
                font-weight: normal;
                color: #FFFFFF;
                letter-spacing: 1px;
              ">Client Portal</h1>
              <!-- Decorative rule -->
              <div style="
                width: 48px;
                height: 2px;
                background-color: #C9A84C;
                margin: 16px auto 0;
              "></div>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding: 44px 40px 32px;">

              <p style="
                margin: 0 0 20px;
                font-size: 16px;
                line-height: 1.7;
                color: #2D2D2D;
              ">
                You have been invited to access your secure client portal with
                The Independence Law Firm. Please verify your email address to
                complete your registration and gain access to your case documents.
              </p>

              <p style="
                margin: 0 0 32px;
                font-size: 15px;
                line-height: 1.7;
                color: #555555;
                font-family: Arial, Helvetica, sans-serif;
              ">
                Click the button below to verify your email address. This link
                is valid for <strong>24 hours</strong> and can only be used once.
              </p>

              <!-- CTA Button -->
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin: 0 auto 36px;">
                <tr>
                  <td style="
                    background-color: #C9A84C;
                    border-radius: 3px;
                  ">
                    <a href="${verifyUrl}"
                       target="_blank"
                       style="
                         display: inline-block;
                         padding: 14px 36px;
                         font-family: Arial, Helvetica, sans-serif;
                         font-size: 15px;
                         font-weight: bold;
                         letter-spacing: 1px;
                         color: #0D1B2A;
                         text-decoration: none;
                         text-transform: uppercase;
                       ">
                      Verify My Email
                    </a>
                  </td>
                </tr>
              </table>

              <!-- Fallback URL -->
              <p style="
                margin: 0 0 8px;
                font-size: 12px;
                color: #888888;
                font-family: Arial, Helvetica, sans-serif;
              ">
                If the button does not work, copy and paste this URL into your browser:
              </p>
              <p style="
                margin: 0 0 32px;
                font-size: 12px;
                word-break: break-all;
                font-family: 'Courier New', Courier, monospace;
                color: #0D1B2A;
              ">
                ${verifyUrl}
              </p>

              <!-- Security note -->
              <div style="
                border-top: 1px solid #E8E4DD;
                padding-top: 24px;
                margin-top: 8px;
              ">
                <p style="
                  margin: 0;
                  font-size: 13px;
                  line-height: 1.6;
                  color: #888888;
                  font-family: Arial, Helvetica, sans-serif;
                ">
                  If you did not request access to the Independence Law Client Portal,
                  you may safely disregard this email. No account will be created
                  without email verification. For security concerns, please contact
                  your attorney directly.
                </p>
              </div>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="
              background-color: #0D1B2A;
              padding: 24px 40px;
              text-align: center;
            ">
              <p style="
                margin: 0;
                font-size: 11px;
                letter-spacing: 2px;
                text-transform: uppercase;
                color: #C9A84C;
                font-family: Arial, Helvetica, sans-serif;
              ">Confidential &nbsp;·&nbsp; Attorney–Client Privileged</p>
              <p style="
                margin: 8px 0 0;
                font-size: 11px;
                color: #5C7080;
                font-family: Arial, Helvetica, sans-serif;
              ">© ${new Date().getFullYear()} The Independence Law Firm. All rights reserved.</p>
            </td>
          </tr>

        </table>
        <!-- /Card -->

      </td>
    </tr>
  </table>

</body>
</html>
  `.trim();
}

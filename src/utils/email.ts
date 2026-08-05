// =============================================================================
// LIBERTY LAW — EMAIL UTILITY
// src/utils/email.ts
//
// Responsibilities:
//   - Initialise the Resend client using RESEND_API_KEY from env.
//   - Export sendVerificationEmail()   for the authentication flow.
//   - Export sendInviteEmail()          for the Client portal invitation flow.
//   - Export sendBorrowerInviteEmail()  for the Discharge Snapshot pipeline.
//
// Security notes:
//   - RESEND_API_KEY is read exclusively from env — never hardcoded.
//   - The magic-link token is a one-time-use UUID hashed server-side.
//   - The 'from' address is hardcoded to the firm's verified Resend domain:
//     apply@theindependencelaw.com
//     (Do NOT change this to onboarding@resend.dev — that sandbox address
//      silently fails for all recipients except the API key owner.)
//
// Brand palette (updated — matches the Liberty Law web application):
//   Navy    #1A2744  (primary background, header, footer)
//   Crimson #B31E3C  (CTA buttons, accent rule, decorative dividers)
//   Light   #F2F4F7  (body background)
//   White   #FFFFFF  (card background)
//   Text    #1A2744  (headings)
//   Muted   #555F6E  (body/secondary text)
// =============================================================================

import { Resend } from 'resend';

// ── Brand constants ────────────────────────────────────────────────────────────
// Update LOGO_URL if the Vercel deployment URL changes.
const LOGO_URL      = 'https://independence-doc-automation.vercel.app/logo.png';

const COLOR_NAVY    = '#1A2744';
const COLOR_CRIMSON = '#B31E3C';
const COLOR_BG      = '#F2F4F7';
const COLOR_WHITE   = '#FFFFFF';
const COLOR_TEXT    = '#1A2744';
const COLOR_MUTED   = '#555F6E';
const COLOR_BORDER  = '#E5E7EB';

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
const FROM_ADDRESS = 'Liberty Law <apply@theindependencelaw.com>';

// ── Resend client (singleton) ─────────────────────────────────────────────────
const resend = new Resend(RESEND_API_KEY);

// ── Frontend base URL ─────────────────────────────────────────────────────────
// In production this will be the Vercel deployment URL.
// Controlled via FRONTEND_URL env var; falls back to localhost for development.
const FRONTEND_URL = process.env.FRONTEND_URL ?? 'http://localhost:3000';

// =============================================================================
// Shared HTML shell builder
//
// Builds a complete email document with the Liberty Law brand header and
// footer. Each template passes in a content block for the body section.
//
// @param title       — <title> and browser tab text
// @param headerTitle — White h1 text inside the navy header
// @param bodyHtml    — Raw HTML for the body content area
// =============================================================================
function buildEmailShell(
  title:       string,
  headerTitle: string,
  bodyHtml:    string,
): string {
  const year = new Date().getFullYear();

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
</head>
<body style="
  margin: 0;
  padding: 0;
  background-color: ${COLOR_BG};
  font-family: Arial, Helvetica, sans-serif;
  color: ${COLOR_MUTED};
">

  <!-- Outer wrapper -->
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>
      <td align="center" style="padding: 40px 16px;">

        <!-- Card -->
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
               style="max-width: 600px; width: 100%; background-color: ${COLOR_WHITE};
                      border-radius: 6px; overflow: hidden;
                      box-shadow: 0 4px 16px rgba(0,0,0,0.10);">

          <!-- ── Header ── -->
          <tr>
            <td style="
              background-color: ${COLOR_NAVY};
              padding: 32px 40px 28px;
              text-align: center;
            ">
              <!-- Official Liberty Law logo -->
              <img
                src="${LOGO_URL}"
                alt="Liberty Law"
                width="150"
                style="
                  display: block;
                  margin: 0 auto 20px;
                  max-width: 150px;
                  height: auto;
                  border: 0;
                "
              />
              <!-- Email-specific heading -->
              <h1 style="
                margin: 0;
                font-size: 22px;
                font-weight: 600;
                color: ${COLOR_WHITE};
                font-family: Georgia, 'Times New Roman', serif;
                letter-spacing: 0.5px;
              ">${headerTitle}</h1>
              <!-- Crimson accent rule -->
              <div style="
                width: 40px;
                height: 3px;
                background-color: ${COLOR_CRIMSON};
                margin: 14px auto 0;
                border-radius: 2px;
              "></div>
            </td>
          </tr>

          <!-- ── Body ── -->
          <tr>
            <td style="padding: 44px 40px 36px;">
              ${bodyHtml}
            </td>
          </tr>

          <!-- ── Footer ── -->
          <tr>
            <td style="
              background-color: ${COLOR_NAVY};
              padding: 20px 40px;
              text-align: center;
              border-top: 3px solid ${COLOR_CRIMSON};
            ">
              <p style="
                margin: 0 0 6px;
                font-size: 10px;
                letter-spacing: 2px;
                text-transform: uppercase;
                color: rgba(255,255,255,0.55);
                font-family: Arial, Helvetica, sans-serif;
              ">Confidential &nbsp;·&nbsp; Attorney–Client Privileged</p>
              <p style="
                margin: 0;
                font-size: 11px;
                color: rgba(255,255,255,0.35);
                font-family: Arial, Helvetica, sans-serif;
              ">© ${year} Liberty Law. All rights reserved.</p>
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

// =============================================================================
// Shared CTA button builder
//
// Returns an HTML table-based button (required for reliable Outlook rendering).
// =============================================================================
function buildCtaButton(href: string, label: string): string {
  return `
<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin: 0 auto 36px;">
  <tr>
    <td style="
      background-color: ${COLOR_CRIMSON};
      border-radius: 4px;
    ">
      <a href="${href}"
         target="_blank"
         style="
           display: inline-block;
           padding: 14px 40px;
           font-family: Arial, Helvetica, sans-serif;
           font-size: 14px;
           font-weight: bold;
           letter-spacing: 1px;
           color: ${COLOR_WHITE};
           text-decoration: none;
           text-transform: uppercase;
         ">
        ${label}
      </a>
    </td>
  </tr>
</table>`;
}

// =============================================================================
// Shared fallback URL block builder
// =============================================================================
function buildFallbackUrl(url: string): string {
  return `
<p style="
  margin: 0 0 8px;
  font-size: 12px;
  color: #9CA3AF;
  font-family: Arial, Helvetica, sans-serif;
">
  If the button does not work, copy and paste this URL into your browser:
</p>
<p style="
  margin: 0 0 32px;
  font-size: 12px;
  word-break: break-all;
  font-family: 'Courier New', Courier, monospace;
  color: ${COLOR_CRIMSON};
">
  ${url}
</p>`;
}

// =============================================================================
// Shared security notice block builder
// =============================================================================
function buildSecurityNote(text: string): string {
  return `
<div style="
  border-top: 1px solid ${COLOR_BORDER};
  padding-top: 24px;
  margin-top: 8px;
">
  <p style="
    margin: 0;
    font-size: 12px;
    line-height: 1.6;
    color: #9CA3AF;
    font-family: Arial, Helvetica, sans-serif;
  ">
    ${text}
  </p>
</div>`;
}

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
      subject: 'Verify your Liberty Law Portal access',
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
// sendInviteEmail
//
// Sends a client portal invitation email to a prospective client.
// Called by POST /api/v1/admin/invites after the Invitation record is created.
//
// @param toEmail    — The invitee's email address (recipient).
// @param inviteLink — The full registration URL containing the invite token.
// =============================================================================
export async function sendInviteEmail(
  toEmail: string,
  inviteLink: string,
): Promise<void> {
  const html = buildInviteEmailHtml(inviteLink);

  let sendError: unknown;

  try {
    const { error } = await resend.emails.send({
      from:    FROM_ADDRESS,
      to:      toEmail,
      subject: 'You have been invited to the Liberty Law Client Portal',
      html,
    });

    if (error) {
      sendError = error;
    }
  } catch (err) {
    console.error('RESEND API ERROR:', err);
    throw new Error(`[email] Unexpected error calling Resend SDK (invite): ${String(err)}`);
  }

  if (sendError) {
    console.error('RESEND API ERROR:', sendError);
    throw new Error(
      `[email] Failed to send invite email: ${
        (sendError as { message?: string }).message ?? String(sendError)
      }`
    );
  }

  console.log(`[email] Invite email dispatched to ${toEmail} via ${FROM_ADDRESS}`);
}

// =============================================================================
// sendBorrowerInviteEmail
//
// Sends a Discharge Snapshot intake invitation to a prospective borrower.
// Called by POST /api/v1/admin/borrowers/invite after the Invitation record is
// created. This function is FULLY ISOLATED from sendInviteEmail — it has its
// own subject line and HTML body. The word "Client" must NOT appear in the
// email sent to the borrower.
//
// @param toEmail    — The borrower's email address (recipient).
// @param intakeLink — The full intake URL containing the one-time invite token.
// =============================================================================
export async function sendBorrowerInviteEmail(
  toEmail: string,
  intakeLink: string,
): Promise<void> {
  const html = buildBorrowerInviteEmailHtml(toEmail, intakeLink);

  let sendError: unknown;

  try {
    const { error } = await resend.emails.send({
      from:    FROM_ADDRESS,
      to:      toEmail,
      subject: 'Action Required: Complete Your Discharge Snapshot Intake Questionnaire',
      html,
    });

    if (error) {
      sendError = error;
    }
  } catch (err) {
    console.error('RESEND API ERROR:', err);
    throw new Error(`[email] Unexpected error calling Resend SDK (borrower invite): ${String(err)}`);
  }

  if (sendError) {
    console.error('RESEND API ERROR:', sendError);
    throw new Error(
      `[email] Failed to send borrower invite email: ${
        (sendError as { message?: string }).message ?? String(sendError)
      }`
    );
  }

  console.log(`[email] Borrower intake invitation dispatched to ${toEmail} via ${FROM_ADDRESS}`);
}

// =============================================================================
// buildVerificationEmailHtml (private)
// =============================================================================
function buildVerificationEmailHtml(verifyUrl: string): string {
  const body = `
    <p style="
      margin: 0 0 20px;
      font-size: 16px;
      line-height: 1.75;
      color: ${COLOR_TEXT};
      font-family: Georgia, 'Times New Roman', serif;
    ">
      You have been invited to access your secure client portal with
      Liberty Law. Please verify your email address to complete your
      registration and gain access to your case documents.
    </p>

    <p style="
      margin: 0 0 32px;
      font-size: 15px;
      line-height: 1.7;
      color: ${COLOR_MUTED};
      font-family: Arial, Helvetica, sans-serif;
    ">
      Click the button below to verify your email address. This link
      is valid for <strong style="color:${COLOR_TEXT};">24 hours</strong>
      and can only be used once.
    </p>

    ${buildCtaButton(verifyUrl, 'Verify My Email')}
    ${buildFallbackUrl(verifyUrl)}
    ${buildSecurityNote(
      'If you did not request access to the Liberty Law Client Portal, ' +
      'you may safely disregard this email. No account will be created ' +
      'without email verification. For security concerns, please contact ' +
      'your attorney directly.'
    )}
  `;

  return buildEmailShell(
    'Verify your Liberty Law Portal access',
    'Client Portal',
    body,
  );
}

// =============================================================================
// buildInviteEmailHtml (private)
// =============================================================================
function buildInviteEmailHtml(inviteLink: string): string {
  const body = `
    <p style="
      margin: 0 0 20px;
      font-size: 16px;
      line-height: 1.75;
      color: ${COLOR_TEXT};
      font-family: Georgia, 'Times New Roman', serif;
    ">
      Your attorney has invited you to access your secure client portal with
      Liberty Law. This portal gives you direct access to your case documents,
      eligibility status, and secure communication with your legal team.
    </p>

    <p style="
      margin: 0 0 32px;
      font-size: 15px;
      line-height: 1.7;
      color: ${COLOR_MUTED};
      font-family: Arial, Helvetica, sans-serif;
    ">
      Click the button below to create your account. This invitation link
      is valid for <strong style="color:${COLOR_TEXT};">7 days</strong>
      and can only be used once.
    </p>

    ${buildCtaButton(inviteLink, 'Accept Invitation')}
    ${buildFallbackUrl(inviteLink)}
    ${buildSecurityNote(
      'If you did not expect this invitation, you may safely disregard this ' +
      'email. No account will be created without your action. For questions, ' +
      'contact your attorney directly.'
    )}
  `;

  return buildEmailShell(
    'You have been invited to the Liberty Law Client Portal',
    'Client Portal Invitation',
    body,
  );
}

// =============================================================================
// buildBorrowerInviteEmailHtml (private)
//
// IMPORTANT: This template must NEVER use the word "Client". The recipient
// is addressed as a "borrower" throughout. The CTA is scoped specifically to
// the "Discharge Snapshot Intake Questionnaire" workflow.
// =============================================================================
function buildBorrowerInviteEmailHtml(recipientEmail: string, intakeLink: string): string {
  const body = `
    <p style="
      margin: 0 0 20px;
      font-size: 16px;
      line-height: 1.75;
      color: ${COLOR_TEXT};
      font-family: Georgia, 'Times New Roman', serif;
    ">
      Liberty Law has opened a secure intake questionnaire on your behalf as
      part of the student loan discharge review process. Your responses will
      allow our team to assess your discharge eligibility and prepare your
      case file.
    </p>

    <p style="
      margin: 0 0 20px;
      font-size: 15px;
      line-height: 1.7;
      color: ${COLOR_MUTED};
      font-family: Arial, Helvetica, sans-serif;
    ">
      Please click the button below to begin your
      <strong style="color:${COLOR_TEXT};">Discharge Snapshot Intake Questionnaire</strong>.
      This link is valid for <strong style="color:${COLOR_TEXT};">7 days</strong>
      and can only be used once.
    </p>

    <p style="
      margin: 0 0 32px;
      font-size: 14px;
      line-height: 1.7;
      color: ${COLOR_MUTED};
      font-family: Arial, Helvetica, sans-serif;
    ">
      This questionnaire has been prepared for:
      <strong style="color: ${COLOR_CRIMSON};">${recipientEmail}</strong>
    </p>

    ${buildCtaButton(intakeLink, 'Begin Intake Questionnaire')}
    ${buildFallbackUrl(intakeLink)}
    ${buildSecurityNote(
      'If you did not expect this message, you may safely disregard it. ' +
      'No information will be submitted without your action. For questions, ' +
      'please contact your attorney directly.'
    )}
  `;

  return buildEmailShell(
    'Complete Your Discharge Snapshot Intake Questionnaire',
    'Discharge Snapshot Intake',
    body,
  );
}

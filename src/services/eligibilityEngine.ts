// =============================================================================
// THE INDEPENDENCE LAW FIRM — ELIGIBILITY ENGINE SERVICE
// src/services/eligibilityEngine.ts
//
// This module is the authoritative scoring authority for student-loan
// discharge eligibility. The frontend MUST NOT calculate scores; all
// scoring logic lives here and is returned via the secured API endpoint.
//
// Algorithm (temporary — v1 point-based pre-screener):
//   Base score  : 50
//   Income < 3k : +20   (strong poverty signal)
//   Income > 5k : -20   (likely above discharge threshold)
//   Disability  : +15   (Brunner Prong 2 — persistence of hardship)
//   Unemployed  : +15   (Brunner Prong 2 — persistence of hardship)
//   Owns car    : -5    (asset reduces hardship score)
//   Expecting refund : -5 (asset reduces hardship score)
//   Final score is clamped to [0, 100].
//
// Status thresholds:
//   score >= 70  → 'Highly Eligible'
//   score >= 45  → 'Review Required'
//   score <  45  → 'Ineligible'
//
// Return shape:
//   { score: number, status: EligibilityStatus, reasons: string[] }
// =============================================================================

import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

// ── Prisma client singleton (shared across service calls) ─────────────────────
let _prisma: PrismaClient | null = null;

function getPrisma(): PrismaClient {
  if (!_prisma) {
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL as string,
      ssl:
        process.env.NODE_ENV === 'production'
          ? { rejectUnauthorized: false }
          : false,
    });
    const adapter = new PrismaPg(pool);
    _prisma = new PrismaClient({ adapter });
  }
  return _prisma;
}

// ── Public types ──────────────────────────────────────────────────────────────

export type EligibilityStatus = 'Highly Eligible' | 'Review Required' | 'Ineligible';

export interface EligibilityResult {
  /** Numeric score in range [0, 100]. */
  score: number;
  /** Human-readable eligibility band derived from the score. */
  status: EligibilityStatus;
  /** Ordered list of factors (positive and negative) that shaped the score. */
  reasons: string[];
}

// ── Sentinel errors ───────────────────────────────────────────────────────────

/** Thrown when the clientId does not match any Client row. */
export class ClientNotFoundError extends Error {
  constructor(clientId: string) {
    super(`Client not found: ${clientId}`);
    this.name = 'ClientNotFoundError';
  }
}

/** Thrown when the client exists but has no IntakeProfile yet. */
export class IntakeProfileMissingError extends Error {
  constructor(clientId: string) {
    super(`Client ${clientId} has not completed an intake profile.`);
    this.name = 'IntakeProfileMissingError';
  }
}

// =============================================================================
// evaluateClient
//
// Fetches the client's IntakeProfile from Prisma and runs the v1 point-based
// eligibility algorithm. All database I/O is centralised here so the route
// handler stays thin.
//
// @param clientId - UUID of the client to evaluate.
// @returns        EligibilityResult — score, status, and reasons array.
// @throws ClientNotFoundError      — if no Client row exists for clientId.
// @throws IntakeProfileMissingError — if the client has no IntakeProfile.
// =============================================================================

export async function evaluateClient(clientId: string): Promise<EligibilityResult> {
  const prisma = getPrisma();

  // ── Fetch client with intake profile ─────────────────────────────────────
  const client = await prisma.client.findUnique({
    where: { id: clientId },
    include: { intakeProfile: true },
  });

  if (!client) {
    throw new ClientNotFoundError(clientId);
  }

  const profile = client.intakeProfile;

  if (!profile) {
    throw new IntakeProfileMissingError(clientId);
  }

  // ── Scoring algorithm ─────────────────────────────────────────────────────
  let score  = 50;
  const reasons: string[] = ['Base score: 50'];

  // Income bracket adjustments
  const income = profile.monthlyIncome ?? 0;

  if (income < 3000) {
    score += 20;
    reasons.push(
      `Monthly income ($${income.toFixed(2)}) is below $3,000 — strong poverty indicator (+20)`
    );
  } else if (income > 5000) {
    score -= 20;
    reasons.push(
      `Monthly income ($${income.toFixed(2)}) exceeds $5,000 — above discharge threshold (−20)`
    );
  } else {
    reasons.push(
      `Monthly income ($${income.toFixed(2)}) is in mid-range ($3,000–$5,000) — no adjustment`
    );
  }

  // Disability — Brunner Prong 2 persistence indicator
  if (profile.hasDisability) {
    score += 15;
    reasons.push('Documented disability — persistent hardship indicator (+15)');
  }

  // Long-term unemployment — Brunner Prong 2 persistence indicator
  if (!profile.isEmployed || profile.unemployed5of10) {
    score += 15;
    reasons.push('Currently unemployed or unemployed 5 of last 10 years (+15)');
  }

  // Vehicle ownership — asset that reduces hardship score
  if (profile.hasCar) {
    score -= 5;
    reasons.push('Owns a vehicle — asset on record (−5)');
  }

  // Expecting tax refund — asset that reduces hardship score
  if (profile.expectingRefund) {
    score -= 5;
    reasons.push('Expecting a tax refund — additional asset (−5)');
  }

  // ── Clamp to [0, 100] ─────────────────────────────────────────────────────
  score = Math.max(0, Math.min(100, score));

  // ── Derive status band ────────────────────────────────────────────────────
  const status: EligibilityStatus =
    score >= 70 ? 'Highly Eligible' :
    score >= 45 ? 'Review Required' :
                  'Ineligible';

  console.log(
    `[eligibilityEngine] Client ${clientId} → score=${score}, status="${status}"`
  );

  return { score, status, reasons };
}

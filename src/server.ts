// =============================================================================
// THE INDEPENDENCE LAW FIRM — EXPRESS SERVER
// src/server.ts
//
// Boot sequence:
//   1. Load & validate required env vars (fail fast if missing)
//   2. Apply global middleware  (CORS, JSON body parser)
//   3. Mount API routes         (/api/v1/...)
//   4. 404 catch-all
//   5. Centralised error handler (no stack trace leaks to client)
// =============================================================================

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

import authRouter from './routes/auth';
import clientRouter from './routes/clients';
import intakeRouter from './routes/intake';
import adminRouter from './routes/admin';

// ── Load environment ──────────────────────────────────────────────────────────
dotenv.config();

// ── Validate required env vars at startup ────────────────────────────────────
const REQUIRED_ENV = [
  'PORT',
  'API_BEARER_TOKEN',
  'CORS_ORIGINS',
  'DATABASE_URL',
  'RESEND_API_KEY',
  'EMAIL_FROM_ADDRESS',
  'JWT_SECRET',
  'FRONTEND_URL',
] as const;
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[server] FATAL: Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const PORT = parseInt(process.env.PORT as string, 10);
const CORS_ORIGINS = (process.env.CORS_ORIGINS as string)
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();

// ── CORS — strict allowlist, no wildcard ─────────────────────────────────────
//
//   We derive the allowed-origin list exclusively from CORS_ORIGINS in .env.
//   A wildcard '*' is never permitted. Any request from an origin not on the
//   list will receive a CORS error before it hits any route handler.
//
app.use(
  cors({
    origin: (incomingOrigin, callback) => {
      // Allow server-to-server / same-origin requests (origin is undefined)
      if (!incomingOrigin) {
        return callback(null, true);
      }
      if (CORS_ORIGINS.includes(incomingOrigin)) {
        return callback(null, true);
      }
      callback(new Error(`CORS: origin '${incomingOrigin}' is not allowed`));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// ── JSON body parser ──────────────────────────────────────────────────────────
app.use(express.json());

// ── Health check (unauthenticated) ────────────────────────────────────────────
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'independence-law-backend' });
});

// ── API routes ────────────────────────────────────────────────────────────────
app.use('/api/auth', authRouter);        // legacy path — kept for frontend compat
app.use('/api/v1/auth', authRouter);     // versioned alias (POST /api/v1/auth/login)
app.use('/api/v1/clients', clientRouter);
app.use('/api/v1/intake', intakeRouter);
app.use('/api/v1/admin', adminRouter);

// ── 404 catch-all ────────────────────────────────────────────────────────────
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Global error handler ─────────────────────────────────────────────────────
//
//   Must have exactly four parameters for Express to treat it as an error
//   handler. Logs the full error server-side, but sends only a generic
//   message to the client — stack traces must never reach the wire.
//
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[server] Independence Law Backend running on port ${PORT}`);
  console.log(`[server] Allowed origins: ${CORS_ORIGINS.join(', ')}`);
  console.log(`[server] Environment: ${process.env.NODE_ENV ?? 'development'}`);
});

export default app;

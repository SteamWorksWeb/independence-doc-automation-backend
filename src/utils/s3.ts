// =============================================================================
// THE INDEPENDENCE LAW FIRM — AWS S3 UTILITY
// src/utils/s3.ts
//
// Responsibilities:
//   - Initialise a singleton S3Client from environment variables.
//   - Export generatePresignedPutUrl()  — presigned PUT URL for direct
//     browser-to-S3 uploads (avoids routing large files through the API).
//   - Export buildS3Url()               — constructs the permanent HTTPS URL
//     for a stored object (used when saving the Document record).
//
// Upload flow:
//   1. Client POSTs to /api/v1/client/documents/presigned-url
//      → backend returns { url, s3Key }
//   2. Client PUTs the file binary directly to `url` (browser fetch / axios)
//   3. Client POSTs to /api/v1/client/documents/confirm with { s3Key, ... }
//      → backend saves a Document row pointing at buildS3Url(s3Key)
//
// Security:
//   - Presigned URLs are time-limited (default 300 s / 5 min).
//   - The S3 bucket should have BlockPublicAccess enabled; objects are only
//     accessible via presigned URLs or a CloudFront distribution.
//   - Credentials are read exclusively from env — never hardcoded.
// =============================================================================

import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

// ── Env guard ─────────────────────────────────────────────────────────────────
// Validated at server startup in server.ts for the core required vars.
// We re-check the S3-specific vars here so the utility fails fast with a
// meaningful message if the AWS config is absent.
const AWS_REGION          = process.env.AWS_REGION;
const AWS_ACCESS_KEY_ID   = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const AWS_S3_BUCKET_NAME  = process.env.AWS_S3_BUCKET_NAME;

if (!AWS_REGION || !AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY || !AWS_S3_BUCKET_NAME) {
  throw new Error(
    '[s3] FATAL: Missing one or more required AWS environment variables: ' +
    'AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET_NAME'
  );
}

// ── S3 client singleton ───────────────────────────────────────────────────────
// Constructed once at import time and reused across all requests.
const s3Client = new S3Client({
  region:      AWS_REGION,
  credentials: {
    accessKeyId:     AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  },
});

// ── Exported bucket name ──────────────────────────────────────────────────────
export const S3_BUCKET = AWS_S3_BUCKET_NAME;

// =============================================================================
// generatePresignedPutUrl
//
// Generates a time-limited presigned PUT URL that allows a client browser
// to upload a single file directly to S3 without passing the binary through
// this API server.
//
// @param s3Key      — The full S3 object key (e.g. "clients/abc/documents/xyz.pdf")
// @param contentType — MIME type of the file (e.g. "application/pdf")
// @param expiresIn  — Seconds until the URL expires. Default: 300 (5 min).
// @returns          — The presigned HTTPS PUT URL string.
// =============================================================================
export async function generatePresignedPutUrl(
  s3Key:       string,
  contentType: string,
  expiresIn    = 300,
): Promise<string> {
  const command = new PutObjectCommand({
    Bucket:      S3_BUCKET,
    Key:         s3Key,
    ContentType: contentType,
  });

  return getSignedUrl(s3Client, command, { expiresIn });
}

// =============================================================================
// generatePresignedGetUrl
//
// Generates a time-limited presigned GET URL that allows a browser or API
// client to download / view a private S3 object without making it public.
// Used by the admin document-view endpoint.
//
// @param s3Key     — The full S3 object key (e.g. "clients/abc/documents/xyz.pdf")
// @param expiresIn — Seconds until the URL expires. Default: 900 (15 min).
// @returns         — The presigned HTTPS GET URL string.
// =============================================================================
export async function generatePresignedGetUrl(
  s3Key:    string,
  expiresIn = 900,
): Promise<string> {
  const command = new GetObjectCommand({
    Bucket: S3_BUCKET,
    Key:    s3Key,
  });

  return getSignedUrl(s3Client, command, { expiresIn });
}

// =============================================================================
// deleteS3Object
//
// Permanently deletes an object from the S3 bucket.
// Called by the admin document-delete endpoint BEFORE removing the DB record,
// so that a failed S3 deletion prevents orphaned database references.
//
// @param s3Key — The full S3 object key to delete.
// @returns     — Resolves when the DeleteObjectCommand completes.
// =============================================================================
export async function deleteS3Object(s3Key: string): Promise<void> {
  const command = new DeleteObjectCommand({
    Bucket: S3_BUCKET,
    Key:    s3Key,
  });

  await s3Client.send(command);
}

// =============================================================================
// buildS3Url
//
// Constructs the permanent HTTPS URL for an object stored in the bucket.
// Stored as Document.fileUrl in the database.
//
// Note: If you add CloudFront in front of the bucket in the future, swap
// this to return a CloudFront URL (e.g. https://cdn.theindependencelaw.com/<key>)
// without changing any route code.
//
// @param s3Key — The full S3 object key.
// @returns     — Permanent S3 HTTPS URL.
// =============================================================================
export function buildS3Url(s3Key: string): string {
  return `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${s3Key}`;
}

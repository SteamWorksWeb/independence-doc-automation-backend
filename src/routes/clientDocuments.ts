// =============================================================================
// THE INDEPENDENCE LAW FIRM - CLIENT DOCUMENTS ROUTER
// src/routes/clientDocuments.ts
//
// Mounted at: /api/v1/client/documents
// =============================================================================

import { Router, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import {
  requireClientJwt,
  ClientRequest,
} from '../middleware/clientJwt';

const DEFAULT_REQUIRED_DOCUMENTS = ['Government ID', 'Recent Paystubs'];

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

function normalizeRequiredDocuments(flaggedDocuments: unknown): string[] {
  if (!Array.isArray(flaggedDocuments)) {
    return DEFAULT_REQUIRED_DOCUMENTS;
  }

  const documents = flaggedDocuments
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);

  return documents.length > 0 ? documents : DEFAULT_REQUIRED_DOCUMENTS;
}

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

router.use(requireClientJwt);

router.get(
  '/required',
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;
      const prisma = getPrisma();

      const latestSnapshot = await prisma.leadIntake.findFirst({
        where: { clientId },
        orderBy: { createdAt: 'desc' },
        select: { flaggedDocuments: true },
      });

      res.status(200).json({
        requiredDocuments: normalizeRequiredDocuments(
          latestSnapshot?.flaggedDocuments
        ),
      });
    } catch (err) {
      next(err);
    }
  }
);

router.post(
  '/upload',
  upload.single('file'),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientId = (req as ClientRequest).clientId;
      const prisma = getPrisma();
      const file = req.file;
      const { documentType } = req.body as { documentType?: string };

      if (!file) {
        res.status(400).json({ error: 'file is required.' });
        return;
      }

      const normalizedDocumentType = documentType?.trim() || 'Other';
      const fileUrl = `https://mock-s3-bucket.com/${file.originalname}`;

      const document = await prisma.document.create({
        data: {
          fileName: file.originalname,
          fileUrl,
          documentType: normalizedDocumentType,
          mimeType: file.mimetype || 'application/octet-stream',
          sizeBytes: file.size,
          uploadedBy: 'CLIENT',
          clientId,
        },
        select: {
          id: true,
          clientId: true,
          fileName: true,
          fileUrl: true,
          documentType: true,
          mimeType: true,
          sizeBytes: true,
          uploadedBy: true,
          uploadedAt: true,
          createdAt: true,
        },
      });

      res.status(201).json({ document });
    } catch (err) {
      next(err);
    }
  }
);

export default router;

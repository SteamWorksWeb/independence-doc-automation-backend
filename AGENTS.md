# AGENTS.md â€” Independence Law BACKEND

## WORKSPACE IDENTITY LOCK (READ FIRST, EVERY TASK)
This workspace is the **BACKEND** (Node.js/Express + Prisma + RDS).
Canonical ID: INDEPENDENCE-LAW-BACKEND

Before reading, editing, or creating ANY file, you MUST:
1. Read the file `.ag-workspace` in the workspace root.
2. Confirm its TRIMMED contents (ignore surrounding whitespace/newlines) equal: INDEPENDENCE-LAW-BACKEND
   - Fallback if `.ag-workspace` is missing: confirm this root contains
     `render.yaml` AND `prisma.config.ts` AND `src/server.ts`.
3. Compare against the TARGET declared at the top of my prompt.
   - If they MATCH: reply "âœ… Workspace confirmed: BACKEND" then proceed.
   - If they DO NOT match, the marker is missing, or you are unsure: STOP.
     Do not read, edit, or create anything. Reply "í»‘ WORKSPACE MISMATCH",
     state what you actually found, and wait for my instruction.

## HARD BOUNDARY
Never modify files outside this workspace root. This repo is isolated from
the FRONTEND repo per the Seesaw Protocol. No cross-repo edits, ever.

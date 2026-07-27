const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: false });

async function main() {
  // List all tables
  const tables = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename");
  console.log('=== TABLES IN DB ===');
  tables.rows.forEach(r => console.log(' -', r.tablename));

  // Check if invitations table exists
  const hasInvitations = tables.rows.some(r => r.tablename === 'invitations');
  console.log('\n=== invitations table exists:', hasInvitations);

  if (hasInvitations) {
    const cols = await pool.query("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'invitations' ORDER BY ordinal_position");
    console.log('=== invitations columns ===');
    cols.rows.forEach(r => console.log(' -', r.column_name, ':', r.data_type));
  }

  // Check _prisma_migrations
  const migrations = await pool.query("SELECT migration_name, finished_at FROM _prisma_migrations ORDER BY finished_at");
  console.log('\n=== APPLIED MIGRATIONS ===');
  migrations.rows.forEach(r => console.log(' -', r.migration_name, '|', r.finished_at));

  await pool.end();
}

main().catch(e => { console.error('ERROR:', e.message); pool.end(); });

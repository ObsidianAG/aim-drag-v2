#!/usr/bin/env node
/**
 * scripts/guard-db-env.mjs -- Database migration environment guard
 *
 * Blocks `db:migrate` unless the operator explicitly sets
 * DB_MIGRATE_CONFIRMED=1 and provides a valid DATABASE_URL.
 *
 * Usage:
 *   DB_MIGRATE_CONFIRMED=1 DATABASE_URL="..." pnpm db:migrate
 *
 * This prevents accidental production migrations from CI or local dev.
 */

const confirmed = process.env.DB_MIGRATE_CONFIRMED;
const dbUrl = process.env.DATABASE_URL;

if (confirmed !== '1') {
  console.error(
    'ERROR: DB_MIGRATE_CONFIRMED is not set to "1".\n' +
    'Database migrations are guarded to prevent accidental execution.\n' +
    'To proceed, run:\n' +
    '  DB_MIGRATE_CONFIRMED=1 DATABASE_URL="..." pnpm db:migrate'
  );
  process.exit(1);
}

if (!dbUrl || dbUrl.trim().length === 0) {
  console.error(
    'ERROR: DATABASE_URL is not set.\n' +
    'A valid database connection string is required for migrations.\n' +
    'To proceed, run:\n' +
    '  DB_MIGRATE_CONFIRMED=1 DATABASE_URL="mysql://..." pnpm db:migrate'
  );
  process.exit(1);
}

// Reject obviously dangerous URLs
const lower = dbUrl.toLowerCase();
if (lower.includes('localhost') || lower.includes('127.0.0.1')) {
  if (process.env.NODE_ENV === 'production') {
    console.error(
      'ERROR: DATABASE_URL points to localhost in production mode.\n' +
      'This is likely a misconfiguration. Aborting.'
    );
    process.exit(1);
  }
}

console.log('guard-db-env: Environment check passed. Proceeding with migration.');

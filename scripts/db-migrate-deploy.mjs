#!/usr/bin/env node
/**
 * scripts/db-migrate-deploy.mjs -- Production migration deploy
 *
 * Applies all pending Drizzle migrations to the database.
 * Uses drizzle-orm/postgres-js/migrator for forward-only migration.
 */

import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set.');
  process.exit(1);
}

const client = postgres(DATABASE_URL, { max: 1 });
const db = drizzle(client);

try {
  console.log('db-migrate-deploy: Applying pending migrations...');
  await migrate(db, { migrationsFolder: './drizzle' });
  console.log('db-migrate-deploy: All migrations applied successfully.');
  await client.end();
  process.exit(0);
} catch (err) {
  console.error('db-migrate-deploy: Migration failed:', err.message);
  await client.end();
  process.exit(1);
}

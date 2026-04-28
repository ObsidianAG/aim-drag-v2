/**
 * server/db/connection.ts -- PostgreSQL connection via postgres.js + Drizzle ORM
 *
 * AIM DRAG: All queries use parameterized statements via Drizzle ORM.
 * No raw string SQL interpolation allowed.
 */

import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.js';

const DATABASE_URL = process.env['DATABASE_URL'];

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is required');
}

/** Raw postgres.js client -- used only by Drizzle, never for raw string queries */
export const pgClient = postgres(DATABASE_URL, {
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10,
});

/** Drizzle ORM instance -- all queries go through this */
export const db = drizzle(pgClient, { schema });

/** Close the connection pool */
export async function closeDb(): Promise<void> {
  await pgClient.end();
}

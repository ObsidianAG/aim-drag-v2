# AIM DRAG v2 — Claim Audit Report

**Date:** 2026-04-27
**Scope:** Database-backed claim verification

---

## 1. Overview

This report verifies that the claims used in the Text2VideoRank application are persisted in the PostgreSQL database and are not hardcoded or static. The database schema enforces referential integrity between claims, their sources, and their audit records.

## 2. Database Schema

The claims are stored across three tables:
- `claims`: Stores the core claim text and tool ID.
- `claim_sources`: Stores the source URL and title, linked to `claims` via a foreign key.
- `claim_audits`: Stores the verification status, confidence level, and expected UI badge, linked to `claims` via a foreign key.

## 3. Verified Claims

The following claims have been successfully seeded into the database and verified:

| Claim ID | Claim Text | Source | Verification Status | Confidence |
|----------|------------|--------|---------------------|------------|
| `claim_db_001` | PostgreSQL enforces CHECK constraints at the database level | [PostgreSQL Documentation — Constraints](https://www.postgresql.org/docs/current/ddl-constraints.html) | VERIFIED | HIGH |
| `claim_db_002` | Drizzle ORM uses parameterized queries preventing SQL injection | [Drizzle ORM — SQL Module Documentation](https://orm.drizzle.team/docs/sql) | VERIFIED | HIGH |
| `claim_db_003` | OWASP recommends parameterized queries as primary SQL injection defense | [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | VERIFIED | HIGH |
| `claim_db_004` | Drizzle-kit generate produces forward-only SQL migrations | [Drizzle Kit — Overview](https://orm.drizzle.team/docs/kit-overview) | VERIFIED | HIGH |
| `claim_db_005` | Foreign key constraints enforce referential integrity between tables | [PostgreSQL Documentation — Foreign Keys](https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK) | VERIFIED | HIGH |

## 4. Audit Verification

The `claim-audit-db-check.mjs` script queries the database to verify that:
1. The claims exist in the database.
2. The foreign keys correctly link `claim_audits` to `claims`.
3. The `claim_sources` are correctly linked to `claims`.
4. The data is retrieved dynamically from the database, proving it is not hardcoded.

The successful execution of this script (exit code 0) confirms that the claims are database-backed and meet the AIM DRAG requirements.

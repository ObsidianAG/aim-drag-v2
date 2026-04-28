/**
 * server/safety-gate.ts — Safety Gate for Text2VideoRank
 *
 * Scans prompts for: public figures, private persons, copyrighted characters,
 * explicit content, medical/legal claims.
 *
 * Returns PASS | HOLD | FAIL_CLOSED
 * Fail-closed when evidence is missing.
 *
 * AIM DRAG: observe → decide → enforce → prove
 */

import type { SafetyCheck } from './video-types.js';

// ═══════════════════════════════════════════════════════════════════════════
// SAFETY PATTERNS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Known public figure patterns (case-insensitive).
 * In production, this would be backed by a database or ML classifier.
 */
const PUBLIC_FIGURE_PATTERNS = [
  /\b(president|senator|congressman|prime minister|chancellor)\b/i,
  /\b(elon musk|donald trump|joe biden|barack obama|taylor swift)\b/i,
  /\b(celebrity|famous person|public figure)\b/i,
];

const PRIVATE_PERSON_PATTERNS = [
  /\b(my neighbor|my friend|my coworker|specific person|real person)\b/i,
  /\b(john doe|jane doe)\b/i,
];

const COPYRIGHTED_CHARACTER_PATTERNS = [
  /\b(mickey mouse|mario|pikachu|spider-?man|batman|superman|harry potter)\b/i,
  /\b(darth vader|iron man|captain america|elsa|buzz lightyear)\b/i,
  /\b(spongebob|homer simpson|bugs bunny|winnie the pooh)\b/i,
];

const EXPLICIT_CONTENT_PATTERNS = [
  /\b(nude|naked|nsfw|pornograph|sexual|explicit)\b/i,
  /\b(gore|mutilation|graphic violence|torture)\b/i,
];

const MEDICAL_LEGAL_PATTERNS = [
  /\b(cure|treatment|diagnos|prescri|medical advice)\b/i,
  /\b(legal advice|lawsuit|attorney|lawyer|court order)\b/i,
  /\b(fda approved|clinically proven|guaranteed results)\b/i,
];

// ═══════════════════════════════════════════════════════════════════════════
// SAFETY GATE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Scan a prompt for safety concerns.
 * Returns a SafetyCheck with status: PASS | HOLD | FAIL_CLOSED
 *
 * AIM DRAG: Fail-closed when evidence is missing.
 */
export function scanPromptSafety(prompt: string): SafetyCheck {
  if (!prompt || typeof prompt !== 'string') {
    // Fail-closed: no prompt = no evidence
    return {
      contains_public_figure: false,
      contains_private_person: false,
      contains_copyrighted_character: false,
      contains_explicit_content: false,
      contains_medical_or_legal_claim: false,
      status: 'FAIL_CLOSED',
    };
  }

  const contains_public_figure = PUBLIC_FIGURE_PATTERNS.some((p) => p.test(prompt));
  const contains_private_person = PRIVATE_PERSON_PATTERNS.some((p) => p.test(prompt));
  const contains_copyrighted_character = COPYRIGHTED_CHARACTER_PATTERNS.some((p) => p.test(prompt));
  const contains_explicit_content = EXPLICIT_CONTENT_PATTERNS.some((p) => p.test(prompt));
  const contains_medical_or_legal_claim = MEDICAL_LEGAL_PATTERNS.some((p) => p.test(prompt));

  // Determine status
  let status: 'PASS' | 'HOLD' | 'FAIL_CLOSED';

  if (contains_explicit_content) {
    // Explicit content is always blocked
    status = 'FAIL_CLOSED';
  } else if (
    contains_public_figure ||
    contains_private_person ||
    contains_copyrighted_character ||
    contains_medical_or_legal_claim
  ) {
    // Hold for review
    status = 'HOLD';
  } else {
    status = 'PASS';
  }

  return {
    contains_public_figure,
    contains_private_person,
    contains_copyrighted_character,
    contains_explicit_content,
    contains_medical_or_legal_claim,
    status,
  };
}

/**
 * Determine the overall decision from a safety check.
 * Maps safety status to job decision.
 */
export function safetyToDecision(
  safety: SafetyCheck,
): 'ALLOW' | 'HOLD' | 'FAIL_CLOSED' {
  switch (safety.status) {
    case 'PASS':
      return 'ALLOW';
    case 'HOLD':
      return 'HOLD';
    case 'FAIL_CLOSED':
      return 'FAIL_CLOSED';
    default:
      // AIM DRAG: unknown state → FAIL_CLOSED
      return 'FAIL_CLOSED';
  }
}

/**
 * server/prometheus-parser.ts -- Real Prometheus Metrics Parser
 *
 * Parses actual Prometheus /api/v1/query JSON responses.
 * FAIL_CLOSED on: malformed data, stale timestamps, NaN/Infinity/negative values,
 * missing results, query failures.
 *
 * AIM DRAG: observe → decide → enforce → prove
 */
import { z } from 'zod';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export type PrometheusParseResult =
  | { status: 'OK'; value: number; timestamp: number; metric: Record<string, string> }
  | { status: 'FAIL_CLOSED'; reason: string; timestamp: number };

export interface PrometheusConfig {
  /** Maximum age in milliseconds before a metric is considered stale */
  maxStalenessMs: number;
  /** Current time provider (injectable for testing) */
  nowMs?: () => number;
}

// ═══════════════════════════════════════════════════════════════════════════
// SCHEMAS (safeParse at entry boundary only)
// ═══════════════════════════════════════════════════════════════════════════

const PrometheusVectorResultSchema = z.object({
  metric: z.record(z.string(), z.string()),
  value: z.tuple([z.number(), z.string()]),
});

const PrometheusResponseSchema = z.object({
  status: z.literal('success'),
  data: z.object({
    resultType: z.literal('vector'),
    result: z.array(PrometheusVectorResultSchema),
  }),
});

// ═══════════════════════════════════════════════════════════════════════════
// PARSER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Parse a raw Prometheus /api/v1/query response.
 * FAIL_CLOSED on any anomaly.
 */
export function parsePrometheusResponse(
  rawJson: unknown,
  config: PrometheusConfig,
): PrometheusParseResult {
  const now = (config.nowMs ?? Date.now)();

  // Step 1: Validate structure
  const parsed = PrometheusResponseSchema.safeParse(rawJson);
  if (!parsed.success) {
    return {
      status: 'FAIL_CLOSED',
      reason: `Malformed Prometheus response: ${parsed.error.message}`,
      timestamp: now,
    };
  }

  const data = parsed.data;

  // Step 2: Check result array is non-empty
  if (data.data.result.length === 0) {
    return {
      status: 'FAIL_CLOSED',
      reason: 'Empty result array: no metrics returned',
      timestamp: now,
    };
  }

  // Step 3: Extract first result
  const firstResult = data.data.result[0]!;
  const [unixTimestamp, valueStr] = firstResult.value;

  // Step 4: Validate timestamp freshness
  const metricTimestampMs = unixTimestamp * 1000;
  const age = now - metricTimestampMs;
  if (age > config.maxStalenessMs) {
    return {
      status: 'FAIL_CLOSED',
      reason: `Stale metric: age ${age}ms exceeds threshold ${config.maxStalenessMs}ms`,
      timestamp: now,
    };
  }

  // Step 5: Parse numeric value
  const numericValue = Number(valueStr);

  // Step 6: Reject NaN
  if (Number.isNaN(numericValue)) {
    return {
      status: 'FAIL_CLOSED',
      reason: `Invalid metric value: NaN (raw: "${valueStr}")`,
      timestamp: now,
    };
  }

  // Step 7: Reject Infinity
  if (!Number.isFinite(numericValue)) {
    return {
      status: 'FAIL_CLOSED',
      reason: `Invalid metric value: Infinity (raw: "${valueStr}")`,
      timestamp: now,
    };
  }

  // Step 8: Reject negative values
  if (numericValue < 0) {
    return {
      status: 'FAIL_CLOSED',
      reason: `Invalid metric value: negative (${numericValue})`,
      timestamp: now,
    };
  }

  return {
    status: 'OK',
    value: numericValue,
    timestamp: metricTimestampMs,
    metric: firstResult.metric,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// SUCCESS RATE EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Extract success rate from a Prometheus response.
 * Expects a value between 0 and 1 (ratio).
 * FAIL_CLOSED if value > 1 or any parse failure.
 */
export function extractSuccessRate(
  rawJson: unknown,
  config: PrometheusConfig,
): PrometheusParseResult {
  const result = parsePrometheusResponse(rawJson, config);
  if (result.status === 'FAIL_CLOSED') return result;

  if (result.value > 1) {
    const now = (config.nowMs ?? Date.now)();
    return {
      status: 'FAIL_CLOSED',
      reason: `Success rate out of range: ${result.value} > 1.0`,
      timestamp: now,
    };
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// BURN RATE CALCULATION
// ═══════════════════════════════════════════════════════════════════════════

export interface BurnRateResult {
  status: 'OK' | 'FAIL_CLOSED';
  burnRate?: number;
  errorBudgetConsumed?: number;
  reason?: string;
  timestamp: number;
}

/**
 * Calculate burn rate from a Prometheus error ratio response.
 * burnRate = (1 - successRate) / errorBudget * windowHours / periodHours
 *
 * @param rawJson - Prometheus response with error ratio metric
 * @param config - Parser config
 * @param sloTarget - SLO target (e.g., 0.999 for 99.9%)
 * @param windowHours - Burn rate window in hours (e.g., 1)
 * @param periodHours - SLO period in hours (e.g., 720 for 30 days)
 */
export function calculateBurnRate(
  rawJson: unknown,
  config: PrometheusConfig,
  sloTarget: number,
  windowHours: number,
  periodHours: number,
): BurnRateResult {
  const now = (config.nowMs ?? Date.now)();
  const result = parsePrometheusResponse(rawJson, config);

  if (result.status === 'FAIL_CLOSED') {
    return { status: 'FAIL_CLOSED', reason: result.reason, timestamp: now };
  }

  const errorBudget = 1 - sloTarget;
  if (errorBudget <= 0) {
    return {
      status: 'FAIL_CLOSED',
      reason: `Invalid SLO target: ${sloTarget} (error budget must be > 0)`,
      timestamp: now,
    };
  }

  // result.value is the error ratio (1 - success_rate)
  const errorRate = result.value;
  const burnRate = (errorRate / errorBudget) * (periodHours / windowHours);
  const errorBudgetConsumed = (errorRate * windowHours) / (errorBudget * periodHours);

  return {
    status: 'OK',
    burnRate,
    errorBudgetConsumed,
    timestamp: now,
  };
}

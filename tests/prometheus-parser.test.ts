/**
 * tests/prometheus-parser.test.ts -- Gate 1: Real Prometheus Parsing
 *
 * Validates FAIL_CLOSED behavior on all anomalous paths.
 * No fake/placeholder metrics. Real Prometheus /api/v1/query format.
 */
import { describe, it, expect } from 'vitest';
import {
  parsePrometheusResponse,
  extractSuccessRate,
  calculateBurnRate,
  type PrometheusConfig,
} from '../server/prometheus-parser.js';

// ═══════════════════════════════════════════════════════════════════════════
// FIXTURES
// ═══════════════════════════════════════════════════════════════════════════

const NOW_MS = 1_700_000_000_000; // Fixed "now" for deterministic tests

function makeConfig(overrides?: Partial<PrometheusConfig>): PrometheusConfig {
  return {
    maxStalenessMs: 60_000, // 60 seconds
    nowMs: () => NOW_MS,
    ...overrides,
  };
}

/** A valid Prometheus /api/v1/query response (vector type) */
function makeValidResponse(value: string = '0.95', timestampSec: number = NOW_MS / 1000 - 10) {
  return {
    status: 'success',
    data: {
      resultType: 'vector',
      result: [
        {
          metric: { __name__: 'http_requests_success_ratio', job: 'api-server', instance: 'pod-1' },
          value: [timestampSec, value],
        },
      ],
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// GATE 1 TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('Gate 1: Prometheus Parser', () => {
  describe('parsePrometheusResponse', () => {
    it('valid response → extracts value correctly', () => {
      const response = makeValidResponse('0.95');
      const result = parsePrometheusResponse(response, makeConfig());

      expect(result.status).toBe('OK');
      if (result.status === 'OK') {
        expect(result.value).toBe(0.95);
        expect(result.metric.__name__).toBe('http_requests_success_ratio');
        expect(result.metric.job).toBe('api-server');
      }
    });

    it('stale timestamp → FAIL_CLOSED', () => {
      // Timestamp is 120 seconds old, threshold is 60 seconds
      const staleTimestamp = NOW_MS / 1000 - 120;
      const response = makeValidResponse('0.99', staleTimestamp);
      const result = parsePrometheusResponse(response, makeConfig());

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Stale metric');
        expect(result.reason).toContain('exceeds threshold');
      }
    });

    it('malformed JSON (not an object) → FAIL_CLOSED', () => {
      const result = parsePrometheusResponse('not json', makeConfig());
      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Malformed');
      }
    });

    it('malformed JSON (missing data field) → FAIL_CLOSED', () => {
      const result = parsePrometheusResponse({ status: 'success' }, makeConfig());
      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Malformed');
      }
    });

    it('missing result (status: error) → FAIL_CLOSED', () => {
      const response = {
        status: 'error',
        errorType: 'bad_data',
        error: 'invalid query',
      };
      const result = parsePrometheusResponse(response, makeConfig());
      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Malformed');
      }
    });

    it('NaN value → FAIL_CLOSED', () => {
      const response = makeValidResponse('NaN');
      const result = parsePrometheusResponse(response, makeConfig());

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('NaN');
      }
    });

    it('negative value → FAIL_CLOSED', () => {
      const response = makeValidResponse('-0.5');
      const result = parsePrometheusResponse(response, makeConfig());

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('negative');
      }
    });

    it('empty result array → FAIL_CLOSED', () => {
      const response = {
        status: 'success',
        data: {
          resultType: 'vector',
          result: [],
        },
      };
      const result = parsePrometheusResponse(response, makeConfig());

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Empty result array');
      }
    });

    it('Infinity value → FAIL_CLOSED', () => {
      const response = makeValidResponse('Infinity');
      const result = parsePrometheusResponse(response, makeConfig());

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Infinity');
      }
    });

    it('null input → FAIL_CLOSED', () => {
      const result = parsePrometheusResponse(null, makeConfig());
      expect(result.status).toBe('FAIL_CLOSED');
    });

    it('undefined input → FAIL_CLOSED', () => {
      const result = parsePrometheusResponse(undefined, makeConfig());
      expect(result.status).toBe('FAIL_CLOSED');
    });
  });

  describe('extractSuccessRate', () => {
    it('valid success rate (0.997) → extracts correctly', () => {
      const response = makeValidResponse('0.997');
      const result = extractSuccessRate(response, makeConfig());

      expect(result.status).toBe('OK');
      if (result.status === 'OK') {
        expect(result.value).toBe(0.997);
      }
    });

    it('success rate > 1 → FAIL_CLOSED', () => {
      const response = makeValidResponse('1.5');
      const result = extractSuccessRate(response, makeConfig());

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('out of range');
      }
    });

    it('success rate exactly 1.0 → OK', () => {
      const response = makeValidResponse('1.0');
      const result = extractSuccessRate(response, makeConfig());
      expect(result.status).toBe('OK');
    });

    it('success rate exactly 0.0 → OK', () => {
      const response = makeValidResponse('0');
      const result = extractSuccessRate(response, makeConfig());
      expect(result.status).toBe('OK');
    });
  });

  describe('calculateBurnRate', () => {
    it('calculates burn rate from real Prometheus format', () => {
      // Error ratio of 0.002 (99.8% success) against 99.9% SLO
      const response = makeValidResponse('0.002');
      const result = calculateBurnRate(
        response,
        makeConfig(),
        0.999, // SLO target
        1,     // 1-hour window
        720,   // 30-day period
      );

      expect(result.status).toBe('OK');
      if (result.status === 'OK') {
        // burnRate = (0.002 / 0.001) * (720 / 1) = 1440
        expect(result.burnRate).toBeCloseTo(1440, 1);
        expect(result.errorBudgetConsumed).toBeDefined();
      }
    });

    it('malformed input → FAIL_CLOSED propagated', () => {
      const result = calculateBurnRate(
        { garbage: true },
        makeConfig(),
        0.999,
        1,
        720,
      );
      expect(result.status).toBe('FAIL_CLOSED');
    });

    it('invalid SLO target (1.0 exactly) → FAIL_CLOSED', () => {
      const response = makeValidResponse('0.001');
      const result = calculateBurnRate(
        response,
        makeConfig(),
        1.0, // impossible SLO
        1,
        720,
      );
      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('error budget must be > 0');
      }
    });
  });
});

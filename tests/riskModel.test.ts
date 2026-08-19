import { describe, expect, it } from 'vitest';
import { normalizeRiskResult } from '../src/lib/riskModel';

describe('normalizeRiskResult', () => {
  it('clamps malformed scores and derives a valid classification', () => {
    const result = normalizeRiskResult({
      threatScore: 240,
      classification: 'unknown',
      riskIndicators: ['A', 'A', '', 7],
    }, 'example.com');

    expect(result.threatScore).toBe(100);
    expect(result.classification).toBe('Malicious');
    expect(result.target).toBe('example.com');
    expect(result.riskIndicators).toEqual(['A']);
  });

  it('normalizes missing narrative fields', () => {
    const result = normalizeRiskResult({ threatScore: '42' }, 'example.org');

    expect(result.threatScore).toBe(42);
    expect(result.classification).toBe('Suspicious');
    expect(result.explanation).toContain('No analyst explanation');
    expect(result.recommendation).toContain('normal defensive caution');
    expect(result.technicalSummary.dns).toContain('No DNS summary');
  });

  it('raises confidence with multiple evidence sources', () => {
    const result = normalizeRiskResult({
      threatScore: 73,
      classification: 'Phishing',
      riskIndicators: ['PUNYCODE'],
      raw: {
        dns: { reputation: [{ source: 'example' }] },
        ssl: { authorized: false },
        whois: { registrar: 'Example Registrar' },
        heuristics: { isPunycode: true },
      },
      technicalSummary: { threatIntel: 'Known signal' },
    }, 'xn--example.test');

    expect(result.riskModel.confidence).toBe('high');
    expect(result.riskModel.scoreBand).toBe('High risk');
    expect(result.riskModel.reasons).toContain('Punycode/homograph indicator present');
  });

  it('keeps a valid classification supplied by the analyst model', () => {
    const result = normalizeRiskResult({ threatScore: 12, classification: 'Malicious' }, 'safe.example');
    expect(result.classification).toBe('Malicious');
    expect(result.riskModel.classification).toBe('Malicious');
  });
});

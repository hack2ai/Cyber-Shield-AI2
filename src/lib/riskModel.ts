import type { ThreatOverviewResult } from '../components/ThreatOverview';

export const THREAT_CLASSIFICATIONS = ['Safe', 'Suspicious', 'Phishing', 'Malicious'] as const;
export type NormalizedClassification = typeof THREAT_CLASSIFICATIONS[number];

function numeric(value: unknown, fallback = 0) {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function cleanString(value: unknown, fallback: string) {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback;
}

function normalizeClassification(value: unknown, score: number): NormalizedClassification {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    const direct = THREAT_CLASSIFICATIONS.find(item => item.toLowerCase() === normalized);
    if (direct) return direct;
  }
  if (score >= 80) return 'Malicious';
  if (score >= 60) return 'Phishing';
  if (score >= 35) return 'Suspicious';
  return 'Safe';
}

export interface RiskModelResult extends ThreatOverviewResult {
  riskModel: {
    score: number;
    classification: NormalizedClassification;
    confidence: 'high' | 'medium' | 'low';
    scoreBand: string;
    reasons: string[];
  };
}

export function normalizeRiskResult(input: any, targetFallback = 'Unknown target'): RiskModelResult {
  const rawScore = numeric(input?.threatScore, 0);
  const score = Math.max(0, Math.min(100, Math.round(rawScore)));
  const classification = normalizeClassification(input?.classification, score);

  const indicators = Array.isArray(input?.riskIndicators)
    ? [...new Set(input.riskIndicators
        .filter((item: unknown): item is string => typeof item === 'string')
        .map(item => item.trim())
        .filter(Boolean))]
        .slice(0, 20)
    : [];

  const target = cleanString(input?.target, targetFallback);
  const explanation = cleanString(input?.explanation, 'No analyst explanation was returned.');
  const recommendation = cleanString(input?.recommendation, 'Use normal defensive caution and validate the indicator before taking action.');
  const technicalSummary = {
    dns: cleanString(input?.technicalSummary?.dns, 'No DNS summary returned.'),
    ssl: cleanString(input?.technicalSummary?.ssl, 'No TLS summary returned.'),
    whois: cleanString(input?.technicalSummary?.whois, 'No WHOIS summary returned.'),
    threatIntel: cleanString(input?.technicalSummary?.threatIntel, 'No threat-intelligence summary returned.'),
  };

  const reasons = [...indicators];
  if (input?.raw?.dns?.reputation?.length) reasons.push('Reputation listing evidence present');
  if (input?.raw?.heuristics?.isPunycode) reasons.push('Punycode/homograph indicator present');
  if (input?.raw?.heuristics?.suspiciousTLD) reasons.push('Suspicious TLD indicator present');
  if (input?.raw?.heuristics?.isShortener) reasons.push('URL shortener indicator present');
  const uniqueReasons = [...new Set(reasons)].slice(0, 12);

  const evidenceCount = [
    input?.raw?.dns,
    input?.raw?.ssl,
    input?.raw?.whois,
    input?.raw?.heuristics,
    technicalSummary.threatIntel,
  ].filter(Boolean).length;
  const confidence: 'high' | 'medium' | 'low' = evidenceCount >= 4 ? 'high' : evidenceCount >= 2 ? 'medium' : 'low';

  const scoreBand = score >= 80 ? 'Critical risk' : score >= 60 ? 'High risk' : score >= 35 ? 'Elevated risk' : 'Low risk';

  return {
    ...input,
    threatScore: score,
    classification,
    target,
    explanation,
    recommendation,
    riskIndicators: indicators,
    technicalSummary,
    riskModel: { score, classification, confidence, scoreBand, reasons: uniqueReasons },
  };
}

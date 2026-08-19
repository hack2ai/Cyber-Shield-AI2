import React from 'react';
import { BrainCircuit, Camera, Lock, Shield, Target } from 'lucide-react';
import { motion } from 'motion/react';
import { StatusPill, ThreatScoreRing, EvidenceStat, RiskSignal, ThreatClassification } from './SocPrimitives';

export interface ThreatOverviewResult {
  threatScore: number;
  classification: ThreatClassification;
  explanation: string;
  recommendation: string;
  riskIndicators: string[];
  type?: string;
  target?: string;
  technicalSummary?: {
    dns?: string;
    ssl?: string;
    whois?: string;
    threatIntel?: string;
  };
  raw?: {
    ssl?: { authorized?: boolean; issuer?: { O?: string; CN?: string } };
    dns?: { ips?: string[]; reputation?: unknown[] };
  };
}

function severityForSignal(label: string, score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (/shortener|punycode|blacklist|phishing/i.test(label)) return 'high';
  return score >= 35 ? 'medium' : 'low';
}

export function ThreatOverview({ result, onCapture }: { result: ThreatOverviewResult; onCapture?: () => void }) {
  const score = Math.max(0, Math.min(100, Number(result.threatScore) || 0));
  const target = result.target || 'Unknown target';
  const ip = result.raw?.dns?.ips?.[0] || 'Not resolved';
  const reputationHits = result.raw?.dns?.reputation?.length || 0;
  const sslTrusted = result.raw?.ssl?.authorized;

  return (
    <motion.section
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border-sky-400/15 p-5 md:p-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <StatusPill classification={result.classification} />
            <span className="status-badge"><Target size={11} /> {result.type || 'target'}</span>
          </div>
          <h2 className="mt-3 break-all text-xl font-semibold tracking-tight text-slate-100 md:text-2xl">{target}</h2>
          <p className="mt-1 text-xs text-slate-500">Analyst assessment generated from collected network, certificate and heuristic evidence.</p>
        </div>
        {onCapture && (
          <button onClick={onCapture} className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-sky-400/20 hover:bg-sky-400/[0.05]">
            <Camera size={14} /> Export evidence
          </button>
        )}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-[auto,1fr]">
        <div className="flex items-center justify-center lg:justify-start">
          <ThreatScoreRing score={score} size={150} />
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <EvidenceStat label="Primary IP" value={ip} />
          <EvidenceStat label="TLS posture" value={sslTrusted === undefined ? 'Not available' : sslTrusted ? 'Trusted' : 'Untrusted'} tone={sslTrusted === true ? 'good' : sslTrusted === false ? 'bad' : 'default'} />
          <EvidenceStat label="Reputation hits" value={reputationHits} tone={reputationHits > 0 ? 'bad' : 'good'} />
          <EvidenceStat label="Analysis mode" value="AI + heuristics" />
          <EvidenceStat label="Decision" value={result.classification} tone={score >= 80 ? 'bad' : score >= 60 ? 'warn' : score < 30 ? 'good' : 'default'} />
          <EvidenceStat label="Evidence state" value="Collected" tone="good" />
        </div>
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-white/[0.06] bg-black/15 p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <BrainCircuit size={14} className="text-sky-300" /> Analyst narrative
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-300">{result.explanation}</p>
        </div>
        <div className="rounded-xl border border-sky-400/10 bg-sky-400/[0.025] p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Shield size={14} className="text-sky-300" /> Recommended action
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-300">{result.recommendation}</p>
        </div>
      </div>

      {result.riskIndicators.length > 0 && (
        <div className="mt-6">
          <div className="mb-3 flex items-center justify-between">
            <p className="section-label">Risk signals</p>
            <span className="text-[10px] text-slate-600">{result.riskIndicators.length} indicators</span>
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            {result.riskIndicators.map((indicator, index) => (
              <RiskSignal key={`${indicator}-${index}`} label={indicator.replaceAll('_', ' ')} severity={severityForSignal(indicator, score)} />
            ))}
          </div>
        </div>
      )}

      <div className="mt-6 grid gap-3 md:grid-cols-3">
        <div className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-black/15 p-3">
          <Lock size={15} className="text-slate-500" />
          <div><p className="section-label">TLS evidence</p><p className="text-xs text-slate-300">{result.technicalSummary?.ssl || 'No TLS summary returned.'}</p></div>
        </div>
        <div className="rounded-lg border border-white/[0.06] bg-black/15 p-3"><p className="section-label">DNS evidence</p><p className="mt-1 text-xs text-slate-300 line-clamp-3">{result.technicalSummary?.dns || 'No DNS summary returned.'}</p></div>
        <div className="rounded-lg border border-white/[0.06] bg-black/15 p-3"><p className="section-label">Threat intelligence</p><p className="mt-1 text-xs text-slate-300 line-clamp-3">{result.technicalSummary?.threatIntel || 'No threat-intelligence summary returned.'}</p></div>
      </div>
    </motion.section>
  );
}

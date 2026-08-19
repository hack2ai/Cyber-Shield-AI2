import React, { useMemo, useState } from 'react';
import { Activity, ArrowLeft, History, Layers3, Shield, Terminal } from 'lucide-react';
import { motion } from 'motion/react';
import LegacyApp from './App';
import { InvestigationWorkspace } from './components/InvestigationWorkspace';
import { ThreatOverview, type ThreatOverviewResult } from './components/ThreatOverview';

function localFallback(target: string): ThreatOverviewResult {
  const lower = target.toLowerCase();
  const suspiciousTerms = ['login', 'verify', 'secure', 'update', 'account', 'password', 'wallet', 'paypal', 'apple'];
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'];
  const isPunycode = lower.includes('xn--');
  const isShortener = shorteners.some(item => lower.includes(item));
  const keywordHits = suspiciousTerms.filter(item => lower.includes(item));
  let threatScore = 8 + keywordHits.length * 12 + (isPunycode ? 42 : 0) + (isShortener ? 28 : 0);
  threatScore = Math.min(97, threatScore);
  const classification = threatScore >= 80 ? 'Malicious' : threatScore >= 60 ? 'Phishing' : threatScore >= 35 ? 'Suspicious' : 'Safe';
  const riskIndicators = [
    ...keywordHits.map(item => `PHISHING_KEYWORD: ${item}`),
    ...(isShortener ? ['URL_SHORTENER_DETECTED'] : []),
    ...(isPunycode ? ['PUNYCODE_HOMOGRAPH_RISK'] : []),
  ];
  return {
    threatScore,
    classification,
    target,
    type: 'target',
    explanation: `Static fallback analysis completed for ${target}. The server intelligence endpoint was unavailable, so only deterministic client-side indicators were used.`,
    recommendation: threatScore >= 60 ? 'Treat as high risk. Do not authenticate, download files, or disclose sensitive information.' : 'No high-confidence malicious indicator was detected by the local fallback. Continue with normal caution.',
    riskIndicators,
    technicalSummary: {
      dns: 'Server DNS evidence unavailable in fallback mode.',
      ssl: 'Server TLS evidence unavailable in fallback mode.',
      threatIntel: 'Client-side heuristic engine active.',
    },
    raw: { dns: { ips: [], reputation: [] }, ssl: {}, },
  };
}

export default function ModernApp() {
  const [target, setTarget] = useState('');
  const [result, setResult] = useState<ThreatOverviewResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showLegacy, setShowLegacy] = useState(false);
  const [lastScannedAt, setLastScannedAt] = useState<Date | null>(null);

  const statusText = useMemo(() => {
    if (isAnalyzing) return 'Investigation running';
    if (result) return 'Investigation complete';
    return 'Engine ready';
  }, [isAnalyzing, result]);

  const analyze = async () => {
    const value = target.trim();
    if (!value || isAnalyzing) return;
    setIsAnalyzing(true);
    setError(null);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || `Analysis service returned ${response.status}.`);
      }
      const data = await response.json() as ThreatOverviewResult;
      setResult(data);
      setLastScannedAt(new Date());
    } catch (caught) {
      console.warn('Modern workspace fallback activated:', caught);
      setResult(localFallback(value));
      setLastScannedAt(new Date());
      setError('Live intelligence service unavailable. Showing deterministic fallback evidence.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  if (showLegacy) {
    return (
      <div className="relative min-h-screen">
        <button onClick={() => setShowLegacy(false)} className="fixed left-4 top-4 z-[120] inline-flex items-center gap-2 rounded-lg border border-sky-400/20 bg-slate-950/90 px-3 py-2 text-xs font-medium text-sky-300 shadow-xl backdrop-blur-xl hover:bg-slate-900">
          <ArrowLeft size={14} /> Back to SOC workspace
        </button>
        <LegacyApp />
      </div>
    );
  }

  return (
    <div className="min-h-screen px-4 py-5 text-slate-100 md:px-6 lg:px-8">
      <div className="mx-auto max-w-[1500px]">
        <header className="mb-6 flex flex-col gap-4 border-b border-white/[0.07] pb-5 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-sky-400/20 bg-sky-400/[0.06] text-sky-300 shadow-[0_10px_30px_rgba(14,165,233,.08)]">
              <Shield size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2"><h1 className="text-lg font-semibold tracking-tight">Cyber Shield AI</h1><span className="status-badge">SOC workspace</span></div>
              <p className="mt-1 text-xs text-slate-500">AI-assisted threat intelligence and defensive indicator analysis</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="status-badge"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />{statusText}</div>
            <button onClick={() => setShowLegacy(true)} className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs font-medium text-slate-400 hover:border-sky-400/20 hover:text-slate-200"><Layers3 size={14} /> Full console</button>
          </div>
        </header>

        <div className="mb-5 grid gap-3 md:grid-cols-3">
          <div className="glass-panel flex items-center gap-3 p-3"><Activity size={16} className="text-sky-300" /><div><p className="section-label">Analysis engine</p><p className="text-xs font-semibold text-slate-200">AI + deterministic fallback</p></div></div>
          <div className="glass-panel flex items-center gap-3 p-3"><Terminal size={16} className="text-emerald-300" /><div><p className="section-label">Evidence sources</p><p className="text-xs font-semibold text-slate-200">DNS · TLS · WHOIS · heuristics</p></div></div>
          <div className="glass-panel flex items-center gap-3 p-3"><History size={16} className="text-amber-300" /><div><p className="section-label">Last investigation</p><p className="text-xs font-semibold text-slate-200">{lastScannedAt ? lastScannedAt.toLocaleTimeString() : 'No scan yet'}</p></div></div>
        </div>

        <div className="space-y-5">
          <InvestigationWorkspace value={target} onChange={setTarget} onAnalyze={analyze} isAnalyzing={isAnalyzing} error={error} />

          {result ? (
            <ThreatOverview result={result} />
          ) : (
            <section className="glass-panel min-h-[360px] border-dashed border-white/[0.10] p-8">
              <div className="flex h-full min-h-[300px] flex-col items-center justify-center text-center">
                <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-sky-400/15 bg-sky-400/[0.05] text-sky-300"><Shield size={24} /></div>
                <h2 className="mt-5 text-xl font-semibold text-slate-200">Ready for investigation</h2>
                <p className="mt-2 max-w-lg text-sm leading-6 text-slate-500">Enter an indicator above to build an evidence-backed threat assessment. Results will appear here as a focused analyst view.</p>
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

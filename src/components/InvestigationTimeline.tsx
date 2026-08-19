import React from 'react';
import { BrainCircuit, CheckCircle2, CircleDot, Database, Flag, Globe2, ShieldAlert } from 'lucide-react';

export interface TimelineEvent {
  label: string;
  detail: string;
  state?: 'complete' | 'active' | 'warning';
}

export function InvestigationTimeline({ result }: { result: any }) {
  const score = Number(result?.threatScore) || 0;
  const events: TimelineEvent[] = [
    { label: 'Indicator received', detail: `${result?.type || 'Target'} accepted for analysis.`, state: 'complete' },
    { label: 'Infrastructure collected', detail: result?.raw?.dns?.ips?.length ? `${result.raw.dns.ips.length} network endpoint(s) resolved.` : 'No server-side network endpoint evidence returned.', state: result?.raw?.dns?.ips?.length ? 'complete' : 'warning' },
    { label: 'Certificate posture checked', detail: result?.raw?.ssl?.authorized === undefined ? 'TLS evidence unavailable.' : result.raw.ssl.authorized ? 'Certificate chain presented as authorized.' : 'Certificate authorization failed or was not trusted.', state: result?.raw?.ssl?.authorized === undefined ? 'warning' : result.raw.ssl.authorized ? 'complete' : 'warning' },
    { label: 'Registration context reviewed', detail: result?.raw?.whois?.registrar ? `Registrar: ${result.raw.whois.registrar}.` : 'WHOIS registration details unavailable.', state: result?.raw?.whois?.registrar ? 'complete' : 'warning' },
    { label: 'Heuristic signals scored', detail: `${result?.riskIndicators?.length || 0} risk indicator(s) contributed to the assessment.`, state: 'complete' },
    { label: 'Threat decision generated', detail: `${result?.classification || 'Unknown'} classification with risk score ${score}/100.`, state: score >= 60 ? 'warning' : 'active' },
  ];

  const icons = [Globe2, Database, ShieldAlert, Flag, BrainCircuit, CheckCircle2];

  return (
    <section className="glass-panel p-5 md:p-6">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-indigo-400/15 bg-indigo-400/[0.05] text-indigo-300"><CircleDot size={16} /></div>
        <div><p className="section-label">Investigation timeline</p><h3 className="text-sm font-semibold text-slate-100">How the assessment was assembled</h3><p className="mt-1 text-xs text-slate-500">A concise audit trail of collection, enrichment, scoring and decision stages.</p></div>
      </div>

      <div className="mt-5">
        {events.map((event, index) => {
          const Icon = icons[index] || CircleDot;
          const tone = event.state === 'warning' ? 'border-amber-400/20 bg-amber-400/[0.05] text-amber-300' : event.state === 'active' ? 'border-sky-400/20 bg-sky-400/[0.05] text-sky-300' : 'border-emerald-400/20 bg-emerald-400/[0.05] text-emerald-300';
          return (
            <div key={event.label} className="flex gap-3">
              <div className="flex w-8 shrink-0 flex-col items-center">
                <div className={`flex h-8 w-8 items-center justify-center rounded-full border ${tone}`}><Icon size={14} /></div>
                {index < events.length - 1 && <div className="my-1 h-10 w-px bg-white/[0.08]" />}
              </div>
              <div className="pb-5 pt-1">
                <p className="text-xs font-semibold text-slate-200">{event.label}</p>
                <p className="mt-1 text-[11px] leading-5 text-slate-500">{event.detail}</p>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

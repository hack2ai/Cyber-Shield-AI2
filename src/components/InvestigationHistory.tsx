import React from 'react';
import { Clock3, ExternalLink, History, Trash2 } from 'lucide-react';
import { cn } from './soc-utils';
import type { ThreatOverviewResult } from './ThreatOverview';

export interface InvestigationRecord {
  id: string;
  createdAt: string;
  target: string;
  result: ThreatOverviewResult;
}

const STORAGE_KEY = 'cyber-shield-investigation-history';

export function readInvestigationHistory(): InvestigationRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveInvestigation(result: ThreatOverviewResult) {
  const existing = readInvestigationHistory();
  const record: InvestigationRecord = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
    target: result.target || 'Unknown target',
    result,
  };
  const next = [record, ...existing.filter(item => item.target !== record.target)].slice(0, 25);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  window.dispatchEvent(new Event('cyber-shield-history-updated'));
}

export function clearInvestigationHistory() {
  localStorage.removeItem(STORAGE_KEY);
  window.dispatchEvent(new Event('cyber-shield-history-updated'));
}

export function InvestigationHistory({ onSelect }: { onSelect: (result: ThreatOverviewResult) => void }) {
  const [records, setRecords] = React.useState<InvestigationRecord[]>([]);

  React.useEffect(() => {
    const refresh = () => setRecords(readInvestigationHistory());
    refresh();
    window.addEventListener('cyber-shield-history-updated', refresh);
    return () => window.removeEventListener('cyber-shield-history-updated', refresh);
  }, []);

  return (
    <section className="glass-panel p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-slate-300"><History size={16} /></div>
          <div><p className="section-label">Recent investigations</p><h3 className="text-sm font-semibold text-slate-100">Local analyst history</h3></div>
        </div>
        {records.length > 0 && <button onClick={clearInvestigationHistory} className="inline-flex items-center gap-1.5 rounded-md border border-white/10 px-2 py-1 text-[10px] text-slate-500 hover:border-red-400/20 hover:text-red-300"><Trash2 size={11} /> Clear</button>}
      </div>

      {records.length === 0 ? (
        <div className="mt-4 rounded-lg border border-dashed border-white/[0.08] px-4 py-8 text-center"><Clock3 size={18} className="mx-auto text-slate-700" /><p className="mt-2 text-xs text-slate-500">No investigations saved in this browser yet.</p></div>
      ) : (
        <div className="mt-4 divide-y divide-white/[0.05]">
          {records.map(record => {
            const score = Number(record.result.threatScore) || 0;
            const tone = score >= 80 ? 'text-red-300' : score >= 60 ? 'text-orange-300' : score >= 35 ? 'text-amber-300' : 'text-emerald-300';
            return (
              <button key={record.id} onClick={() => onSelect(record.result)} className="flex w-full items-center gap-3 py-3 text-left hover:bg-white/[0.02]">
                <span className={cn('w-10 shrink-0 text-sm font-semibold', tone)}>{score}</span>
                <span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium text-slate-200">{record.target}</span><span className="mt-0.5 block text-[10px] text-slate-600">{new Date(record.createdAt).toLocaleString()}</span></span>
                <ExternalLink size={13} className="shrink-0 text-slate-700" />
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}

import React, { useMemo } from 'react';
import { Activity, Globe2, Mail, MessageSquare, Phone, Search, Shield, Terminal, Zap, type LucideIcon } from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from './soc-utils';

export type InvestigationMode = 'url' | 'domain' | 'ip' | 'email' | 'phone' | 'message' | 'keyword';

const modes: Array<{ id: InvestigationMode; label: string; icon: LucideIcon; description: string; placeholder: string }> = [
  { id: 'url', label: 'URL', icon: Globe2, description: 'Inspect a full web address', placeholder: 'https://example.com/login' },
  { id: 'domain', label: 'DOMAIN', icon: Search, description: 'Review domain infrastructure', placeholder: 'example.com' },
  { id: 'ip', label: 'IP', icon: Terminal, description: 'Probe an IPv4 endpoint', placeholder: '203.0.113.10' },
  { id: 'email', label: 'EMAIL', icon: Mail, description: 'Audit an email identity', placeholder: 'security@example.com' },
  { id: 'phone', label: 'PHONE', icon: Phone, description: 'Review a phone indicator', placeholder: '+31 20 123 4567' },
  { id: 'message', label: 'MESSAGE', icon: MessageSquare, description: 'Analyze suspicious text', placeholder: 'Paste suspicious SMS or message content...' },
  { id: 'keyword', label: 'KEYWORD', icon: Activity, description: 'Search a threat indicator', placeholder: 'campaign-name or malware-family' },
];

export function InvestigationWorkspace({
  value,
  onChange,
  onAnalyze,
  isAnalyzing = false,
  error,
}: {
  value: string;
  onChange: (value: string) => void;
  onAnalyze: () => void;
  isAnalyzing?: boolean;
  error?: string | null;
}) {
  const [mode, setMode] = React.useState<InvestigationMode>('url');
  const activeMode = modes.find(item => item.id === mode) || modes[0];
  const Icon = activeMode.icon;

  const detectedMode = useMemo<InvestigationMode | null>(() => {
    const input = value.trim();
    if (!input) return null;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) return 'email';
    if (/^\+?[\d\s()-]{7,20}$/.test(input)) return 'phone';
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) return 'ip';
    if (/^https?:\/\//i.test(input)) return 'url';
    if (input.includes(' ') && input.length > 24) return 'message';
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(input)) return 'domain';
    return 'keyword';
  }, [value]);

  return (
    <section className="glass-panel border-sky-400/15 p-5 md:p-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-sky-400/20 bg-sky-400/[0.06] text-sky-300">
            <Shield size={18} />
          </div>
          <div>
            <p className="section-label">Investigation workspace</p>
            <h2 className="mt-1 text-lg font-semibold text-slate-100">Start a threat investigation</h2>
            <p className="mt-1 max-w-2xl text-xs leading-5 text-slate-500">Submit one indicator, let the engine classify it, and review evidence in a single analyst workflow.</p>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-emerald-400/10 bg-emerald-400/[0.04] px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.12em] text-emerald-300">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Engine ready
        </div>
      </div>

      <div className="mt-6 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        {modes.map(item => {
          const ModeIcon = item.icon;
          const selected = item.id === mode;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setMode(item.id)}
              className={cn(
                'rounded-lg border px-3 py-2.5 text-left transition',
                selected ? 'border-sky-400/30 bg-sky-400/[0.08] text-sky-200' : 'border-white/[0.06] bg-white/[0.015] text-slate-500 hover:border-white/10 hover:text-slate-300'
              )}
            >
              <ModeIcon size={14} />
              <div className="mt-2 text-[10px] font-semibold tracking-[0.08em]">{item.label}</div>
            </button>
          );
        })}
      </div>

      <div className="mt-5 rounded-xl border border-white/[0.07] bg-black/20 p-3 md:p-4">
        <div className="mb-2 flex items-center justify-between gap-3">
          <label className="section-label" htmlFor="investigation-target">Target indicator</label>
          {detectedMode && <span className="text-[10px] text-sky-300">Detected: {detectedMode.toUpperCase()}</span>}
        </div>
        <div className="flex flex-col gap-3 lg:flex-row">
          <div className="relative flex-1">
            <Icon className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" size={16} />
            <input
              id="investigation-target"
              value={value}
              onChange={event => onChange(event.target.value)}
              onKeyDown={event => { if (event.key === 'Enter' && value.trim() && !isAnalyzing) onAnalyze(); }}
              placeholder={activeMode.placeholder}
              aria-invalid={Boolean(error)}
              className={cn('w-full rounded-lg border bg-slate-950/70 py-3 pl-10 pr-4 text-sm text-slate-100 outline-none transition placeholder:text-slate-700', error ? 'border-red-400/30 focus:border-red-400/50' : 'border-white/[0.08] focus:border-sky-400/30')}
            />
          </div>
          <motion.button
            type="button"
            whileTap={{ scale: 0.98 }}
            onClick={onAnalyze}
            disabled={!value.trim() || isAnalyzing}
            className="inline-flex min-h-12 items-center justify-center gap-2 rounded-lg bg-sky-500 px-5 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isAnalyzing ? <><Activity size={16} className="animate-spin" /> Analyzing…</> : <><Zap size={16} /> Analyze indicator</>}
          </motion.button>
        </div>
        {error ? <p className="mt-2 text-xs text-red-300">{error}</p> : <p className="mt-2 text-[11px] text-slate-600">Use a URL, domain, IPv4, email, phone number, message, or keyword. Press Enter to run the investigation.</p>}
      </div>
    </section>
  );
}

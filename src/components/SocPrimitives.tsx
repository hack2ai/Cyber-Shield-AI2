import React from 'react';
import { AlertTriangle, CheckCircle2, Info, Shield, ShieldAlert, ShieldCheck } from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from './soc-utils';

export type ThreatClassification = 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious';

const classificationStyles: Record<ThreatClassification, string> = {
  Safe: 'border-emerald-400/20 bg-emerald-400/[0.06] text-emerald-300',
  Suspicious: 'border-amber-400/20 bg-amber-400/[0.06] text-amber-300',
  Phishing: 'border-orange-400/20 bg-orange-400/[0.06] text-orange-300',
  Malicious: 'border-red-400/20 bg-red-400/[0.06] text-red-300',
};

function classificationIcon(classification: ThreatClassification) {
  switch (classification) {
    case 'Safe': return CheckCircle2;
    case 'Suspicious': return Info;
    case 'Phishing': return ShieldAlert;
    case 'Malicious': return AlertTriangle;
  }
}

export function SectionHeader({
  eyebrow,
  title,
  icon: Icon = Shield,
  action,
}: {
  eyebrow?: string;
  title: string;
  icon?: React.ComponentType<{ size?: number; className?: string }>;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-sky-400/15 bg-sky-400/[0.06] text-sky-300">
          <Icon size={16} />
        </div>
        <div className="min-w-0">
          {eyebrow && <p className="section-label mb-1">{eyebrow}</p>}
          <h3 className="truncate text-sm font-semibold text-slate-100">{title}</h3>
        </div>
      </div>
      {action}
    </div>
  );
}

export function StatusPill({ classification }: { classification: ThreatClassification }) {
  const Icon = classificationIcon(classification);
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em]', classificationStyles[classification])}>
      <Icon size={12} />
      {classification}
    </span>
  );
}

export function ThreatScoreRing({ score, size = 132 }: { score: number; size?: number }) {
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (safeScore / 100) * circumference;
  const tone = safeScore < 30 ? 'text-emerald-400' : safeScore < 60 ? 'text-amber-400' : safeScore < 80 ? 'text-orange-400' : 'text-red-400';
  const stroke = safeScore < 30 ? '#34d399' : safeScore < 60 ? '#fbbf24' : safeScore < 80 ? '#fb923c' : '#f87171';

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} aria-label={`Threat score ${safeScore} out of 100`}>
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(148,163,184,.12)" strokeWidth="7" />
        <motion.circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke={stroke}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.1, ease: 'easeOut' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn('text-4xl font-semibold tracking-tight', tone)}>{safeScore}</span>
        <span className="text-[9px] font-medium uppercase tracking-[0.18em] text-slate-500">Risk score</span>
      </div>
    </div>
  );
}

export function EvidenceStat({ label, value, tone = 'default' }: { label: string; value: React.ReactNode; tone?: 'default' | 'good' | 'warn' | 'bad' }) {
  const toneClass = tone === 'good' ? 'text-emerald-300' : tone === 'warn' ? 'text-amber-300' : tone === 'bad' ? 'text-red-300' : 'text-slate-100';
  return (
    <div className="rounded-lg border border-white/[0.06] bg-black/20 p-3">
      <p className="section-label">{label}</p>
      <p className={cn('mt-1 truncate text-sm font-semibold', toneClass)}>{value}</p>
    </div>
  );
}

export function RiskSignal({ label, detail, severity = 'medium' }: { label: string; detail?: string; severity?: 'low' | 'medium' | 'high' | 'critical' }) {
  const styles = {
    low: 'border-emerald-400/15 bg-emerald-400/[0.04] text-emerald-300',
    medium: 'border-amber-400/15 bg-amber-400/[0.04] text-amber-300',
    high: 'border-orange-400/15 bg-orange-400/[0.04] text-orange-300',
    critical: 'border-red-400/15 bg-red-400/[0.04] text-red-300',
  };
  return (
    <div className={cn('rounded-lg border px-3 py-2', styles[severity])}>
      <p className="text-xs font-semibold">{label}</p>
      {detail && <p className="mt-0.5 text-[11px] opacity-70">{detail}</p>}
    </div>
  );
}

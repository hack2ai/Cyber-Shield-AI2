import React from 'react';
import { Check, Clipboard, ChevronDown, Globe2, KeyRound, Network, Radar } from 'lucide-react';
import { cn } from './soc-utils';

export function EvidenceIntelligence({ result }: { result: any }) {
  const [open, setOpen] = React.useState<string | null>('dns');
  const [copied, setCopied] = React.useState<string | null>(null);

  const copy = async (value: string, id: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(id);
      window.setTimeout(() => setCopied(current => current === id ? null : current), 1200);
    } catch {
      setCopied(null);
    }
  };

  const dns = result?.raw?.dns || {};
  const ssl = result?.raw?.ssl || {};
  const whois = result?.raw?.whois || {};
  const heuristics = result?.raw?.heuristics || {};
  const intel = result?.technicalSummary?.threatIntel || 'No threat-intelligence summary returned.';

  const rows = [
    { id: 'dns', title: 'DNS infrastructure', icon: Network, summary: dns.ips?.length ? `${dns.ips.length} resolved endpoint${dns.ips.length === 1 ? '' : 's'}` : 'No resolved endpoints', body: (
      <div className="space-y-3">
        <EvidenceRow label="Resolved IPv4" value={dns.ips?.join(', ') || 'None'} copyValue={dns.ips?.join(', ') || ''} id="dns-ip" onCopy={copy} copied={copied} />
        <EvidenceRow label="DNS reputation" value={dns.reputation?.length ? `${dns.reputation.length} listing hit(s)` : 'No listing hits'} tone={dns.reputation?.length ? 'bad' : 'good'} />
        <EvidenceRow label="MX records" value={dns.records?.mx?.map((item: any) => `${item.exchange} (priority ${item.priority})`).join(', ') || 'None returned'} />
        <EvidenceRow label="TXT records" value={dns.records?.txt?.flat?.().join(' · ') || dns.records?.txt?.join?.(' · ') || 'None returned'} />
      </div>
    )},
    { id: 'tls', title: 'TLS / certificate posture', icon: KeyRound, summary: ssl.authorized === undefined ? 'Evidence unavailable' : ssl.authorized ? 'Certificate trusted' : 'Certificate not trusted', body: (
      <div className="space-y-3">
        <EvidenceRow label="Authorization" value={ssl.authorized === undefined ? 'Not available' : ssl.authorized ? 'Trusted' : 'Untrusted'} tone={ssl.authorized === undefined ? 'default' : ssl.authorized ? 'good' : 'bad'} />
        <EvidenceRow label="Issuer" value={ssl.issuer?.O || ssl.issuer?.CN || 'Not returned'} />
        <EvidenceRow label="Valid from" value={ssl.valid_from ? new Date(ssl.valid_from).toLocaleString() : 'Not returned'} />
        <EvidenceRow label="Valid to" value={ssl.valid_to ? new Date(ssl.valid_to).toLocaleString() : 'Not returned'} />
        <EvidenceRow label="Fingerprint" value={ssl.fingerprint || 'Not returned'} copyValue={ssl.fingerprint || ''} id="tls-fp" onCopy={copy} copied={copied} mono />
      </div>
    )},
    { id: 'whois', title: 'Registration / WHOIS', icon: Globe2, summary: whois.registrar || 'Registration evidence unavailable', body: (
      <div className="space-y-3">
        <EvidenceRow label="Registrar" value={whois.registrar || 'Not returned'} />
        <EvidenceRow label="Created" value={whois.creationDate || whois.createdDate || 'Not returned'} />
        <EvidenceRow label="Expires" value={whois.expiryDate || whois.expirationDate || 'Not returned'} />
        <EvidenceRow label="Abuse contact" value={whois.registrarAbuseContactEmail || 'Not returned'} copyValue={whois.registrarAbuseContactEmail || ''} id="whois-abuse" onCopy={copy} />
      </div>
    )},
    { id: 'heuristics', title: 'Heuristic signals', icon: Radar, summary: `${result?.riskIndicators?.length || 0} risk indicator(s)`, body: (
      <div className="grid gap-3 sm:grid-cols-2">
        <EvidenceRow label="Entropy" value={typeof heuristics.entropy === 'number' ? heuristics.entropy.toFixed(3) : 'N/A'} />
        <EvidenceRow label="Punycode" value={heuristics.isPunycode ? 'Detected' : 'Not detected'} tone={heuristics.isPunycode ? 'bad' : 'good'} />
        <EvidenceRow label="Suspicious TLD" value={heuristics.suspiciousTLD ? 'Detected' : 'Not detected'} tone={heuristics.suspiciousTLD ? 'warn' : 'good'} />
        <EvidenceRow label="URL shortener" value={heuristics.isShortener ? 'Detected' : 'Not detected'} tone={heuristics.isShortener ? 'warn' : 'good'} />
      </div>
    )},
    { id: 'intel', title: 'Threat intelligence', icon: Radar, summary: 'Analyst synthesis', body: <p className="text-sm leading-6 text-slate-300">{intel}</p> },
  ];

  return (
    <section className="glass-panel p-5 md:p-6">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyan-400/15 bg-cyan-400/[0.05] text-cyan-300"><Radar size={16} /></div>
        <div><p className="section-label">Evidence intelligence</p><h3 className="text-sm font-semibold text-slate-100">Collected technical evidence</h3><p className="mt-1 text-xs text-slate-500">Inspect the raw signals behind the risk decision. Expand sections for normalized evidence and copy key values.</p></div>
      </div>

      <div className="mt-5 divide-y divide-white/[0.06] rounded-xl border border-white/[0.07] bg-black/10">
        {rows.map(row => {
          const Icon = row.icon;
          const expanded = open === row.id;
          return (
            <div key={row.id}>
              <button onClick={() => setOpen(expanded ? null : row.id)} className="flex w-full items-center gap-3 px-4 py-3.5 text-left hover:bg-white/[0.02]">
                <Icon size={15} className={expanded ? 'text-cyan-300' : 'text-slate-600'} />
                <div className="min-w-0 flex-1"><p className="text-xs font-semibold text-slate-200">{row.title}</p><p className="truncate text-[10px] text-slate-600">{row.summary}</p></div>
                <ChevronDown size={15} className={cn('text-slate-600 transition-transform', expanded && 'rotate-180 text-cyan-300')} />
              </button>
              {expanded && <div className="border-t border-white/[0.05] px-4 py-4">{row.body}</div>}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function EvidenceRow({ label, value, tone = 'default', copyValue, onCopy, copied, id, mono = false }: { label: string; value: string; tone?: 'default' | 'good' | 'warn' | 'bad'; copyValue?: string; onCopy?: (value: string, id: string) => void; copied?: string | null; id?: string; mono?: boolean }) {
  const toneClass = tone === 'good' ? 'text-emerald-300' : tone === 'warn' ? 'text-amber-300' : tone === 'bad' ? 'text-red-300' : 'text-slate-300';
  return (
    <div className="rounded-lg border border-white/[0.06] bg-slate-950/35 px-3 py-2.5">
      <div className="flex items-center justify-between gap-3"><span className="section-label">{label}</span>{copyValue && onCopy && id && <button onClick={() => onCopy(copyValue, id)} className="inline-flex items-center gap-1 text-[10px] text-slate-600 hover:text-cyan-300">{copied === id ? <Check size={11} /> : <Clipboard size={11} />}{copied === id ? 'Copied' : 'Copy'}</button>}</div>
      <p className={cn('mt-1 break-all text-xs', toneClass, mono && 'font-mono text-[11px]')}>{value || 'None'}</p>
    </div>
  );
}

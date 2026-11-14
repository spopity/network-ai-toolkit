import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Cpu, MessageSquare, RefreshCw, ShieldCheck, Sparkles, Wifi } from 'lucide-react';
import type { DashboardState, Snapshot } from '../types';
import { C, Card, Pill, TONE, type Tone } from '../components/ui';
import { relTime } from '../lib/format';

export const NOTHING = /^nothing notable\.?$/i;
const SOURCE_LABEL: Record<string, string> = { claude: 'Claude', gemini: 'Gemini', ollama: 'Ollama (local)' };
/* ------------------------------------------------------------------ AI briefing */

export function Briefing({
  data,
  snap,
  collecting,
  onCollect,
  onAsk,
}: {
  data: DashboardState;
  snap: Snapshot;
  collecting: boolean;
  onCollect: () => void;
  onAsk: (q: string) => void;
}) {
  const analysis = data.analysis;
  const sections = analysis?.sections ?? {};
  const findings = [
    { key: 'security', label: 'Security', icon: ShieldCheck, color: C.pink, text: sections.security },
    { key: 'wifi', label: 'Wi-Fi', icon: Wifi, color: C.teal, text: sections.wifi },
    { key: 'system', label: 'System', icon: Cpu, color: C.amber, text: sections.system },
  ];
  const flagged = findings.filter((f) => f.text && !NOTHING.test(f.text.trim()));
  const outbound = snap.security.firewall_drops?.outbound?.total ?? 0;
  const down = data.watchdog?.up === false;

  let tone: Tone = 'ok';
  let verdict = 'All clear - nothing needs your attention';
  if (down || outbound) {
    tone = 'high';
    verdict = down ? 'Internet is down' : 'A device contacted a blocklisted address';
  } else if (flagged.length) {
    tone = 'caution';
    verdict = `${flagged.length} finding${flagged.length > 1 ? 's' : ''} to review`;
  } else if (!analysis?.sections?.overall) {
    tone = 'neutral';
    verdict = 'No analysis yet';
  }
  const t = TONE[tone];
  const overall = sections.overall || 'The AI briefing runs once a day at 03:00 UTC over the last 24h of checks.';

  return (
    <Card
      title="AI briefing"
      icon={<Sparkles size={15} className="text-violet-400" />}
      className="relative overflow-hidden"
      action={<Pill tone={tone}>{verdict}</Pill>}
    >
      <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 bg-gradient-to-b ${t.glow} to-transparent`} />
      <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-violet-500/10 blur-3xl" />
      <p className="max-w-4xl bg-gradient-to-r from-white to-violet-200 bg-clip-text text-lg font-semibold leading-snug text-transparent sm:text-xl">
        {overall}
      </p>

      <div className="mt-4 grid grid-cols-1 items-start gap-2.5 md:grid-cols-3">
        {findings.map((f) => {
          const clear = !f.text || NOTHING.test(f.text.trim());
          return (
            <div key={f.key} className="relative overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
              <div className="mb-1.5 flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider" style={{ color: f.color }}>
                  <f.icon size={13} />
                  {f.label}
                </span>
                {clear ? (
                  <CheckCircle2 size={14} className="text-emerald-400" />
                ) : (
                  <AlertTriangle size={14} className="text-amber-400" />
                )}
              </div>
              <ExpandText text={clear ? 'Nothing notable.' : f.text!} dim={clear} />
            </div>
          );
        })}
      </div>

      <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="truncate text-[11px] text-slate-500">
          Daily analysis {relTime(analysis?.analyzed_at ?? snap.collected_at)} · via {SOURCE_LABEL[analysis?.source ?? ''] ?? '—'} ·
          24h of 5-min checks summarized
        </p>
        <div className="flex shrink-0 gap-2">
          <button
            onClick={() =>
              onAsk(
                flagged.length
                  ? `The monitor flagged: ${flagged.map((f) => `${f.label}: ${f.text}`).join(' | ')} - investigate on the router and tell me what's real and what to do.`
                  : 'The monitor says all clear. Do a quick health check of the router anyway and tell me if anything looks off.',
              )
            }
            className="inline-flex items-center gap-1.5 rounded-lg bg-violet-500/15 px-2.5 py-1.5 text-xs font-medium text-violet-200 ring-1 ring-violet-500/25 transition hover:bg-violet-500/25"
          >
            <MessageSquare size={13} /> Ask Tshoot
          </button>
          <button
            onClick={onCollect}
            disabled={collecting}
            className="inline-flex items-center gap-1.5 rounded-lg bg-white/[0.05] px-2.5 py-1.5 text-xs font-medium text-slate-300 ring-1 ring-white/10 transition hover:bg-white/[0.08] disabled:opacity-50"
          >
            <RefreshCw size={13} className={collecting ? 'animate-spin-fast' : ''} /> {collecting ? 'Checking…' : 'Re-check'}
          </button>
        </div>
      </div>
    </Card>
  );
}
function ExpandText({ text, dim }: { text: string; dim: boolean }) {
  const [open, setOpen] = useState(false);
  const long = text.length > 170;
  return (
    <div>
      <p className={`text-[13px] leading-relaxed ${dim ? 'text-slate-500' : 'text-slate-300'} ${long && !open ? 'line-clamp-3' : ''}`}>{text}</p>
      {long && (
        <button onClick={() => setOpen((o) => !o)} className="mt-1 text-[11px] font-medium text-sky-300 hover:text-sky-200">
          {open ? 'Less' : 'More'}
        </button>
      )}
    </div>
  );
}

import { useMemo } from 'react';
import { Globe } from 'lucide-react';
import type { DashboardState, Snapshot } from '../types';
import { Card } from '../components/ui';
import { clock, duration, relTime } from '../lib/format';
import { MiniStat } from './ConnectionCard';

/* ------------------------------------------------------------------ uptime */

export function UptimeCard({ data, snap }: { data: DashboardState; snap: Snapshot }) {
  const wd = data.watchdog ?? {};
  const hist = wd.history ?? [];
  const upPct = hist.length ? (100 * hist.filter((h) => h.up).length) / hist.length : null;
  // ~1,400 checks in 12 h: bucket them so each bar is visible; a bucket is "down" if any check failed
  const buckets = useMemo(() => {
    const n = Math.min(72, hist.length);
    if (!n) return [];
    const size = hist.length / n;
    return Array.from({ length: n }, (_, i) => {
      const part = hist.slice(Math.floor(i * size), Math.floor((i + 1) * size));
      const downs = part.filter((p) => !p.up).length;
      return { ts: part[0]?.ts ?? '', end: part[part.length - 1]?.ts ?? '', downs, total: part.length };
    });
  }, [hist]);
  const w24 = (snap.wan as { watchdog_24h?: { outages: number; total_downtime_s: number; longest_s: number; auto_restarts: number } }).watchdog_24h;
  const online = wd.up !== false;

  return (
    <Card title="Uptime" icon={<Globe size={15} className="text-emerald-400" />} action={<LiveDot up={online} />}>
      <div className="flex items-baseline gap-1">
        <span className="text-[34px] font-semibold leading-none tabular-nums text-white">{upPct != null ? upPct.toFixed(upPct === 100 ? 0 : 1) : '—'}</span>
        <span className="text-sm text-slate-400">% · last 12 h</span>
      </div>
      <div className="mt-3 flex h-9 items-end gap-[2px]">
        {buckets.map((b) => (
          <div
            key={b.ts}
            title={`${clock(b.ts)}–${clock(b.end)}: ${b.downs ? `${b.downs} failed checks` : 'all checks up'}`}
            className={`h-full min-w-0 flex-1 rounded-[3px] transition-colors ${
              b.downs ? 'bg-red-400 shadow-[0_0_12px_rgba(248,113,113,0.55)]' : 'bg-emerald-400/60 hover:bg-emerald-300'
            }`}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[11px] text-slate-500">
        <span>{hist[0] ? clock(hist[0].ts) : ''}</span>
        <span>now</span>
      </div>

      <div className="mt-4 mb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">Last 24 h</div>
      <div className="grid grid-cols-3 gap-2">
        <MiniStat label="Drops" value={String(w24?.outages ?? 0)} tone={w24?.outages ? 'text-amber-300' : undefined} />
        <MiniStat label="Total" value={duration(w24?.total_downtime_s ?? 0)} />
        <MiniStat label="Longest" value={duration(w24?.longest_s ?? 0)} />
      </div>
      <div className="mt-3 space-y-1 text-[11px] text-slate-500">
        <p>
          WAN {snap.wan.proto?.toUpperCase()} · <span className="font-mono text-slate-400">{snap.wan.ip || '—'}</span>
        </p>
        <p>
          Watchdog checked {relTime(wd.checked_at)} · auto-restart after 5 min down
          {wd.last_restart_at ? ` · last ${relTime(wd.last_restart_at)}` : ''}
        </p>
      </div>
    </Card>
  );
}
function LiveDot({ up }: { up: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2 text-xs font-medium ${up ? 'text-emerald-300' : 'text-red-300'}`}>
      <span className="relative flex h-2.5 w-2.5">
        <span className={`absolute inline-flex h-full w-full rounded-full ${up ? 'bg-emerald-400' : 'bg-red-400'} animate-ping-soft`} />
        <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${up ? 'bg-emerald-400' : 'bg-red-400'}`} />
      </span>
      {up ? 'Live' : 'Down'}
    </span>
  );
}

import { useMemo, useState } from 'react';
import { TrendingUp } from 'lucide-react';
import type { Snapshot } from '../types';
import { AreaChart, Legend } from '../components/AreaChart';
import { C, Card, Segmented, Skeleton } from '../components/ui';
import { useConnmon } from '../hooks/useConnmon';

/* ------------------------------------------------------------------ connection quality */

export function ConnectionCard({ snap, className = '' }: { snap: Snapshot; className?: string }) {
  const [hours, setHours] = useState(24);
  const { points, available } = useConnmon(hours);
  const cm = snap.wan.connmon;
  const st = snap.wan.speedtest;

  const chart = useMemo(() => {
    const p = points ?? [];
    return {
      x: p.map((r) => r.ts * 1000),
      ping: p.map((r) => r.ping),
      jitter: p.map((r) => r.jitter),
      markers: p.filter((r) => r.quality < 100).map((r) => ({ t: r.ts * 1000, label: `${r.quality}% line quality` })),
      max: p.length ? Math.max(...p.map((r) => r.ping)) : null,
      worst: p.length ? Math.min(...p.map((r) => r.quality)) : null,
    };
  }, [points]);

  return (
    <Card
      title="Connection quality"
      icon={<TrendingUp size={15} className="text-sky-400" />}
      className={className}
      action={
        <Segmented
          options={[
            { label: '24h', value: 24 },
            { label: '7d', value: 168 },
          ]}
          value={hours}
          onChange={setHours}
        />
      }
    >
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <Legend
          items={[
            { name: 'Ping', color: C.sky },
            { name: 'Jitter', color: C.pink },
            { name: 'Packet loss', color: C.red },
          ]}
        />
        <span className="text-[11px] text-slate-500">connmon · 30 s test to 8.8.8.8 every 5 min</span>
      </div>
      {points === null ? (
        <Skeleton className="h-[210px]" />
      ) : (
        <AreaChart
          x={chart.x}
          height={210}
          series={[
            { name: 'Ping', color: C.sky, values: chart.ping, unit: ' ms' },
            { name: 'Jitter', color: C.pink, values: chart.jitter, unit: ' ms' },
          ]}
          markers={chart.markers}
          formatX={(t) =>
            hours > 24
              ? new Date(t).toLocaleDateString([], { weekday: 'short', day: 'numeric' })
              : new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          }
          empty={available ? 'connmon has no results in this window yet.' : 'Router unreachable - connmon data unavailable.'}
        />
      )}
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <MiniStat label="Avg ping" value={cm?.ping_ms_avg != null ? `${cm.ping_ms_avg} ms` : '—'} sub={cm?.ping_ms_avg_7d != null ? `7-day ${cm.ping_ms_avg_7d} ms` : undefined} />
        <MiniStat label="Peak ping" value={chart.max != null ? `${chart.max.toFixed(1)} ms` : '—'} />
        <MiniStat
          label="Line quality"
          value={chart.worst != null ? `${chart.worst}%` : '—'}
          sub={chart.markers.length ? `${chart.markers.length} lossy tests` : 'no packet loss'}
          tone={chart.markers.length ? 'text-amber-300' : 'text-emerald-400'}
        />
        <MiniStat
          label="Speedtest"
          value={st ? `${Math.round(st.download_mbps ?? 0)} / ${Math.round(st.upload_mbps ?? 0)}` : '—'}
          sub={st ? `Mbps · ${st.server ?? ''}` : undefined}
        />
      </div>
    </Card>
  );
}
export function MiniStat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className="rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
      <div className="truncate text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-0.5 text-[15px] font-semibold tabular-nums text-white">{value}</div>
      {sub && <div className={`truncate text-[11px] ${tone ?? 'text-slate-500'}`}>{sub}</div>}
    </div>
  );
}

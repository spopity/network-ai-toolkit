import { useState } from 'react';
import { FileText, MessageSquare } from 'lucide-react';
import { C, Card, Segmented } from '../components/ui';
import { useJson } from '../hooks/useJson';
import { relTime } from '../lib/format';
import { NET_COLOR, Stat } from './DnsCard';

/** Weekly / monthly report (router_agent/report.py, saved in logs/reports/, /api/reports). */

type Period = 'week' | 'month';

interface Internet {
  wan_up_pct: number | null;
  outages_measured: number;
  downtime_min: number;
  router_reboots: number;
}
interface Line {
  speedtests: number;
  download_mbps_avg: number | null;
  upload_mbps_avg: number | null;
  ping_ms_avg: number | null;
}
interface Traffic {
  download_gb?: number; // absent when the period is { not_collected: true }
  upload_gb?: number;
  coverage?: string; // "3 of 7 days": collection started part-way through the period
  per_day_gb?: { day: string; down: number; up: number }[];
  top_devices?: { device: string; network: string; down_gb: number; up_gb: number }[];
}
interface Dns {
  queries?: number;
  blocked_pct: number | null;
}
interface Facts {
  internet: Internet | null;
  line: Line | null;
  traffic: Traffic | null;
  dns: Dns | null;
  new_devices: { device: string; vendor: string | null; first_seen: string }[];
  events: { counts: Record<string, number> } | null;
  previous: { internet: Internet | null; line: Line | null; traffic: Traffic | null; dns: Dns | null };
  errors?: string[];
}
interface Report {
  period: Period;
  start: string;
  end: string;
  generated_at: string;
  summary: string | null;
  source: string;
  error?: string;
  facts: Facts;
}

const SOURCE_LABEL: Record<string, string> = { claude: 'Claude', gemini: 'Gemini', ollama: 'Ollama (local)' };

function day(iso: string) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' });
}

/** "+12%" vs the previous period, or nothing when there is no basis. */
function change(now: number | null | undefined, before: number | null | undefined): string | undefined {
  if (now == null || before == null || before === 0) return undefined;
  const pct = Math.round((100 * (now - before)) / before);
  return `${pct > 0 ? '+' : ''}${pct}%`;
}

function gb(n: number) {
  return n >= 100 ? n.toFixed(0) : n.toFixed(1);
}

export function ReportCard({ onAsk }: { onAsk: (q: string) => void }) {
  const [period, setPeriod] = useState<Period>('week');
  const { data } = useJson<{ reports: Report[] }>(`/api/reports?period=${period}&limit=1`, 30 * 60_000);
  const r = data?.reports?.[0];

  return (
    <Card
      title={r ? `${period === 'week' ? 'Weekly' : 'Monthly'} report · ${day(r.start)} – ${day(r.end)}` : 'Report'}
      icon={<FileText size={15} className="text-violet-400" />}
      action={
        <div className="flex items-center gap-2">
          {r && (
            <button
              onClick={() =>
                onAsk(
                  `Look at the ${period === 'week' ? 'weekly' : 'monthly'} network report for ${r.start} to ${r.end}. ` +
                    'Is anything in it worth acting on?',
                )
              }
              className="flex shrink-0 items-center gap-1.5 rounded-lg bg-white/[0.04] px-2.5 py-1 text-[11px] font-medium text-slate-300 ring-1 ring-white/10 transition hover:bg-white/[0.08] hover:text-white"
            >
              <MessageSquare size={12} /> Ask Tshoot
            </button>
          )}
          <Segmented
            options={[
              { label: 'Week', value: 'week' as Period },
              { label: 'Month', value: 'month' as Period },
            ]}
            value={period}
            onChange={setPeriod}
          />
        </div>
      }
    >
      {!data ? (
        <div className="h-24 animate-pulse rounded-xl bg-white/[0.03]" />
      ) : !r ? (
        <p className="text-[12.5px] text-slate-500">
          No {period === 'week' ? 'weekly' : 'monthly'} report yet. The first one is written{' '}
          {period === 'week' ? 'on Monday morning' : 'on the 1st of next month'} (network-ai-report-{period === 'week' ? 'weekly' : 'monthly'}.timer).
        </p>
      ) : (
        <ReportBody r={r} />
      )}
    </Card>
  );
}

function ReportBody({ r }: { r: Report }) {
  const f = r.facts;
  const p = f.previous ?? ({} as Facts['previous']);
  const bullets = (r.summary ?? '')
    .split('\n')
    .map((l) => l.replace(/^\s*[-•*]\s*/, '').trim())
    .filter(Boolean);
  const perDay = f.traffic?.per_day_gb ?? [];
  const maxDay = Math.max(1, ...perDay.map((d) => d.down + d.up));
  const top = f.traffic?.top_devices ?? [];
  const maxTop = Math.max(1, ...top.map((d) => d.down_gb + d.up_gb));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
        <Stat
          label="Internet up"
          value={f.internet?.wan_up_pct != null ? `${f.internet.wan_up_pct}%` : '–'}
          sub={f.internet ? (f.internet.outages_measured ? `${f.internet.outages_measured}× · ${f.internet.downtime_min} min` : 'no outages') : undefined}
          accent={C.emerald}
        />
        <Stat
          label="Speedtest Mbps"
          value={f.line?.download_mbps_avg != null ? `${Math.round(f.line.download_mbps_avg)}↓` : '–'}
          sub={f.line?.upload_mbps_avg != null ? `${Math.round(f.line.upload_mbps_avg)}↑` : undefined}
          accent={C.violet}
        />
        <Stat
          label="Downloaded"
          value={f.traffic?.download_gb != null ? `${gb(f.traffic.download_gb)} GB` : '–'}
          sub={f.traffic?.coverage ?? (p.traffic?.coverage ? undefined : change(f.traffic?.download_gb, p.traffic?.download_gb))}
          accent={C.sky}
        />
        <Stat
          label="DNS queries"
          value={f.dns?.queries ? f.dns.queries.toLocaleString() : '–'}
          sub={f.dns?.blocked_pct != null ? `${f.dns.blocked_pct}% blocked` : 'not collected'}
          accent={C.amber}
        />
        <Stat label="New devices" value={String(f.new_devices?.length ?? 0)} accent={C.pink} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <div className="lg:col-span-3">
          {bullets.length ? (
            <ul className="space-y-1.5 text-[13px] leading-relaxed text-slate-300">
              {bullets.map((b, i) => (
                <li key={i} className="flex gap-2">
                  <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-violet-400/70" />
                  <span>{b}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12.5px] text-slate-500">No AI summary ({r.error ?? 'no LLM answered'}); the numbers above are from the archive.</p>
          )}
          <div className="mt-2 text-[11px] text-slate-500">
            Written {relTime(r.generated_at)}
            {r.source && r.source !== 'none' ? ` · via ${SOURCE_LABEL[r.source] ?? r.source}` : ''}
            {f.errors?.length ? ` · missing: ${f.errors.map((e) => e.split(':')[0]).join(', ')}` : ''}
          </div>
        </div>

        <div className="space-y-4 lg:col-span-2">
          {perDay.length > 0 && (
            <div>
              <div className="mb-1.5 text-[10.5px] font-medium uppercase tracking-wider text-slate-500">Traffic per day</div>
              <div className="flex h-20 gap-1">
                {perDay.map((d) => (
                  <div
                    key={d.day}
                    className="flex h-full flex-1 flex-col justify-end"
                    title={`${day(d.day)}: ${gb(d.down)} GB down, ${gb(d.up)} GB up`}
                  >
                    <div style={{ height: `${(100 * d.up) / maxDay}%`, background: C.pink }} className="min-h-px rounded-t-sm opacity-80" />
                    <div style={{ height: `${(100 * d.down) / maxDay}%`, background: C.sky }} className="min-h-px opacity-80" />
                  </div>
                ))}
              </div>
              <div className="mt-1 flex justify-between text-[10px] text-slate-500">
                <span>{day(perDay[0].day)}</span>
                <span>{day(perDay[perDay.length - 1].day)}</span>
              </div>
            </div>
          )}
          {top.length > 0 && (
            <div>
              <div className="mb-1.5 text-[10.5px] font-medium uppercase tracking-wider text-slate-500">Top devices</div>
              <div className="space-y-1.5">
                {top.map((d) => (
                  <div key={d.device} className="text-[12px]">
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5 text-slate-300">
                        <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: NET_COLOR[d.network] ?? C.slate }} />
                        <span className="truncate">{d.device}</span>
                      </span>
                      <span className="shrink-0 tabular-nums text-slate-400">{gb(d.down_gb + d.up_gb)} GB</span>
                    </div>
                    <div className="mt-0.5 h-1 rounded-full bg-white/[0.04]">
                      <div className="h-1 rounded-full" style={{ width: `${(100 * (d.down_gb + d.up_gb)) / maxTop}%`, background: C.sky }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {f.new_devices?.length > 0 && (
            <div>
              <div className="mb-1.5 text-[10.5px] font-medium uppercase tracking-wider text-slate-500">New devices</div>
              <div className="flex flex-wrap gap-1.5">
                {f.new_devices.slice(0, 12).map((d, i) => (
                  <span key={i} className="rounded-md bg-white/[0.04] px-2 py-0.5 text-[11px] text-slate-300 ring-1 ring-white/[0.06]" title={d.first_seen}>
                    {d.device}
                    {d.vendor ? <span className="text-slate-500"> · {d.vendor}</span> : null}
                  </span>
                ))}
                {f.new_devices.length > 12 && <span className="text-[11px] text-slate-500">+{f.new_devices.length - 12} more</span>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

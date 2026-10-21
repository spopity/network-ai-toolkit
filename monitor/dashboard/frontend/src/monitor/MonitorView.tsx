import { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  CheckCircle2,
  Cpu,
  Gauge,
  Globe,
  History,
  MessageSquare,
  Power,
  RefreshCw,
  Router as RouterIcon,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Thermometer,
  TrendingUp,
  Wifi,
  WifiOff,
  Zap,
} from 'lucide-react';
import type { DashboardState, HistoryResponse, MeshNode, Snapshot, WatchdogEvent, WifiClient } from '../types';
import { AreaChart, Legend } from '../components/AreaChart';
import { C, Card, Meter, Pill, Segmented, Skeleton, StatTile, TONE, type Tone } from '../components/ui';
import { useConnmon } from '../hooks/useConnmon';
import { clock, compact, dayClock, duration, isRandomMac, relTime } from '../lib/format';

interface Props {
  data: DashboardState | null;
  history: HistoryResponse | null;
  error: string | null;
  collecting: boolean;
  onCollect: () => void;
  onAsk: (question: string) => void;
}

const NOTHING = /^nothing notable\.?$/i;

export function MonitorView({ data, history, error, collecting, onCollect, onAsk }: Props) {
  const snap = data?.snapshot ?? null;

  if (!snap) {
    return (
      <div className="mx-auto max-w-[1400px] space-y-4 p-4 lg:p-6">
        {error && <Pill tone="high">Dashboard API unreachable: {error}</Pill>}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 2xl:grid-cols-6">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-[118px]" />
          ))}
        </div>
        <Skeleton className="h-[200px]" />
        <Skeleton className="h-[300px]" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1400px] space-y-4 p-4 pb-28 lg:p-6 lg:pb-8">
      <KpiGrid data={data!} snap={snap} />
      <Briefing data={data!} snap={snap} collecting={collecting} onCollect={onCollect} onAsk={onAsk} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ConnectionCard className="lg:col-span-2" snap={snap} />
        <UptimeCard data={data!} snap={snap} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ThreatsCard snap={snap} />
        <WifiCard snap={snap} finding={data?.analysis?.sections?.wifi} />
        <RouterCard snap={snap} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 lg:items-start">
        <TrendsCard className="lg:col-span-2" history={history} />
        <EventsCard data={data!} history={history} />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ KPI tiles */

function KpiGrid({ data, snap }: { data: DashboardState; snap: Snapshot }) {
  const wd = data.watchdog ?? {};
  const cm = snap.wan.connmon;
  const st = snap.wan.speedtest;
  const fd = snap.security.firewall_drops;
  const sys = snap.system;
  const memPct = sys.mem_total_kb ? Math.round(100 * (1 - (sys.mem_available_kb || sys.mem_free_kb) / sys.mem_total_kb)) : null;
  const outages = (snap.wan as { watchdog_24h?: { outages: number } }).watchdog_24h?.outages ?? 0;
  const banned = fd?.skynet_banned ? Object.values(fd.skynet_banned).reduce((a, b) => a + b, 0) : null;
  const outbound = fd?.outbound?.total ?? 0;
  const online = wd.up !== false;

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 2xl:grid-cols-6">
      <StatTile
        label="Internet"
        value={online ? 'Online' : 'Offline'}
        accent={online ? C.emerald : C.red}
        icon={online ? <Globe size={16} /> : <WifiOff size={16} />}
        sub={
          <>
            <span className={outages ? 'text-amber-300' : 'text-emerald-400'}>
              {outages ? `${outages} drop${outages > 1 ? 's' : ''}` : 'no drops'}
            </span>{' '}
            in 24 h · {snap.wan.proto?.toUpperCase()}
          </>
        }
      />
      <StatTile
        label="Latency"
        value={cm?.ping_ms_avg != null ? cm.ping_ms_avg.toFixed(1) : '—'}
        unit="ms"
        accent={C.sky}
        icon={<Activity size={16} />}
        sub={
          cm ? (
            <>
              jitter {cm.jitter_ms_avg ?? '—'} ms ·{' '}
              <span className={cm.tests_with_loss_24h ? 'text-amber-300' : 'text-emerald-400'}>
                {cm.tests_with_loss_24h ? `${cm.tests_with_loss_24h} lossy tests` : '0% loss'}
              </span>
            </>
          ) : (
            'connmon not reporting'
          )
        }
      />
      <StatTile
        label="Speed"
        value={st?.download_mbps != null ? Math.round(st.download_mbps) : '—'}
        unit="Mbps ↓"
        accent={C.violet}
        icon={<Gauge size={16} />}
        sub={st ? `↑ ${Math.round(st.upload_mbps ?? 0)} Mbps · ${relTime(st.last_at)}` : 'no speedtest yet'}
      />
      <StatTile
        label="Wi-Fi"
        value={snap.wifi.client_count}
        unit={snap.wifi.client_count === 1 ? 'device' : 'devices'}
        accent={C.teal}
        icon={<Wifi size={16} />}
        sub={`2.4 GHz ${snap.wifi.clients_2g.length} · 5 GHz ${snap.wifi.clients_5g.length}${
          snap.wifi.nodes?.length ? ` · ${snap.wifi.nodes.length} nodes` : ''
        }`}
      >
        <BandSplit a={snap.wifi.clients_2g.length} b={snap.wifi.clients_5g.length} />
      </StatTile>
      <StatTile
        label="Threats"
        value={compact(fd?.total ?? 0)}
        unit="blocked"
        accent={outbound ? C.red : C.pink}
        icon={outbound ? <ShieldAlert size={16} /> : <ShieldCheck size={16} />}
        sub={
          outbound ? (
            <span className="text-red-300">{outbound} outbound to blocklisted IPs!</span>
          ) : (
            `${fd?.unique_sources ?? 0} sources · ${banned ? compact(banned) : '—'} IPs banned`
          )
        }
      />
      <StatTile
        label="Router"
        value={sys.temps_c?.cpu != null ? Math.round(sys.temps_c.cpu) : '—'}
        unit="°C CPU"
        accent={C.amber}
        icon={<Cpu size={16} />}
        sub={`mem ${memPct ?? '—'}% · up ${duration(sys.uptime_seconds)}`}
      >
        <Meter pct={memPct ?? 0} from={C.amber} to={C.orange} className="mt-2.5" />
      </StatTile>
    </div>
  );
}

function BandSplit({ a, b }: { a: number; b: number }) {
  const total = a + b;
  if (!total) return <div className="mt-2.5 h-1.5 rounded-full bg-white/[0.06]" />;
  return (
    <div className="mt-2.5 flex h-1.5 gap-0.5 overflow-hidden rounded-full">
      {a > 0 && <div style={{ flex: a, background: C.teal }} />}
      {b > 0 && <div style={{ flex: b, background: C.sky }} />}
    </div>
  );
}

/* ------------------------------------------------------------------ AI briefing */

function Briefing({
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
          Daily analysis {relTime(analysis?.analyzed_at ?? snap.collected_at)} · via {analysis?.source === 'ollama' ? 'Ollama (local fallback)' : analysis?.source === 'gemini' ? 'Gemini' : '—'} ·
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

/* ------------------------------------------------------------------ connection quality */

function ConnectionCard({ snap, className = '' }: { snap: Snapshot; className?: string }) {
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

function MiniStat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className="rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
      <div className="truncate text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-0.5 text-[15px] font-semibold tabular-nums text-white">{value}</div>
      {sub && <div className={`truncate text-[11px] ${tone ?? 'text-slate-500'}`}>{sub}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ uptime */

function UptimeCard({ data, snap }: { data: DashboardState; snap: Snapshot }) {
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

/* ------------------------------------------------------------------ threats */

function ThreatsCard({ snap }: { snap: Snapshot }) {
  const fd = snap.security.firewall_drops;
  const ports = fd?.top_ports.slice(0, 6) ?? [];
  const maxPort = Math.max(1, ...ports.map((p) => p.count));
  const sources = fd?.top_sources.slice(0, 4) ?? [];
  const outbound = fd?.outbound;

  return (
    <Card title="Threats" icon={<ShieldCheck size={15} className="text-pink-400" />} action={<span className="text-[11px] text-slate-500">Skynet</span>}>
      {outbound && outbound.total > 0 && (
        <div className="mb-3 flex items-start gap-2 rounded-xl bg-red-500/10 px-3 py-2 text-xs text-red-200 ring-1 ring-red-500/30">
          <ShieldAlert size={15} className="mt-0.5 shrink-0" />
          <span>
            <b>{outbound.total}</b> outbound connection{outbound.total > 1 ? 's' : ''} to blocklisted addresses from{' '}
            {outbound.by_lan_device.map((d) => `${d.ip} (${d.count})`).join(', ')}
          </span>
        </div>
      )}
      <div className="flex items-baseline gap-1">
        <span className="text-[34px] font-semibold leading-none tabular-nums text-white">{compact(fd?.total ?? 0)}</span>
        <span className="text-sm text-slate-400">inbound blocked</span>
      </div>
      <p className="mt-1 text-[11px] text-slate-500">
        {fd?.window_start ? `${fd.window_start.slice(7, 12)} → ${fd.window_end?.slice(7, 12)}` : ''} · {fd?.unique_sources ?? 0} unique sources · logging is sampled
      </p>

      <div className="mt-4 text-[11px] font-medium uppercase tracking-wider text-slate-500">Most probed ports</div>
      <div className="mt-2 space-y-1.5">
        {ports.length === 0 && <p className="text-xs text-slate-500">Nothing logged yet.</p>}
        {ports.map((p) => (
          <div key={p.port} className="flex items-center gap-2 text-xs">
            <span className="w-[86px] shrink-0 font-mono text-slate-300">{p.port}</span>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
              <div className="h-full rounded-full" style={{ width: `${(100 * p.count) / maxPort}%`, background: `linear-gradient(90deg, ${C.pink}, ${C.violet})` }} />
            </div>
            <span className="w-7 shrink-0 text-right tabular-nums text-slate-400">{p.count}</span>
          </div>
        ))}
      </div>

      {sources.length > 0 && (
        <>
          <div className="mt-4 text-[11px] font-medium uppercase tracking-wider text-slate-500">Top sources</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {sources.map((s) => (
              <span key={s.ip} className="rounded-md bg-white/[0.04] px-2 py-0.5 font-mono text-[11px] text-slate-300 ring-1 ring-white/[0.06]">
                {s.ip} <span className="text-pink-300">×{s.count}</span>
              </span>
            ))}
          </div>
        </>
      )}

      <div className="mt-4 flex flex-wrap gap-1.5">
        {fd?.skynet_banned &&
          Object.entries(fd.skynet_banned).map(([k, v]) => (
            <Pill key={k} tone="info" dot={false}>
              {compact(v)} {k === 'blacklist' ? 'IPs' : 'ranges'} banned
            </Pill>
          ))}
        <Pill tone={snap.security.aiprotection_enabled ? 'ok' : 'neutral'}>AiProtection {snap.security.aiprotection_enabled ? 'on' : 'off'}</Pill>
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------ wifi */

const BAND_STYLE: Record<WifiClient['band'], { label: string; color: string; bg: string }> = {
  '2g': { label: '2.4 GHz', color: C.teal, bg: '#2dd4bf1f' },
  '5g': { label: '5 GHz', color: C.sky, bg: '#38bdf81f' },
  '6g': { label: '6 GHz', color: C.violet, bg: '#a78bfa1f' },
};

const nodeName = (model: string) => model.replace(/_/g, ' ');

function rssiColor(rssi: number) {
  return rssi >= -60 ? C.emerald : rssi >= -75 ? C.amber : C.rose;
}

function WifiCard({ snap, finding }: { snap: Snapshot; finding?: string }) {
  const w = snap.wifi;
  const fresh = new Set(w.new_clients ?? []);
  // snapshots from before AiMesh support only carry per-band MAC lists
  const clients: WifiClient[] =
    w.clients ??
    [
      ...w.clients_2g.map((mac) => ({ mac, band: '2g' as const })),
      ...w.clients_5g.map((mac) => ({ mac, band: '5g' as const })),
    ].map((c) => ({ ...c, node: null, iface: '', ip: null, rssi: null }));
  const nodes = w.nodes ?? [];
  const groups = [
    ...nodes.map((n) => ({ key: n.mac, node: n as MeshNode | null, items: clients.filter((c) => c.node === n.mac) })),
    // clients whose node isn't in the roster (or legacy snapshots)
    { key: 'other', node: null, items: clients.filter((c) => !nodes.some((n) => n.mac === c.node)) },
  ].filter((g) => g.node || g.items.length);

  return (
    <Card
      title="Wi-Fi"
      icon={<Wifi size={15} className="text-teal-400" />}
      action={
        <span className="text-[11px] text-slate-500">
          {clients.length} associated{nodes.length > 1 ? ` · ${nodes.length} nodes` : ''}
        </span>
      }
    >
      <div className="grid grid-cols-2 gap-2">
        <Band name={w.ssid_2g} band="2.4 GHz" count={w.clients_2g.length} color={C.teal} />
        <Band name={w.ssid_5g} band="5 GHz" count={w.clients_5g.length} color={C.sky} />
      </div>
      {nodes.length > 1 && (
        <div className="mt-2 grid grid-cols-2 gap-2">
          {nodes.map((n) => (
            <div key={n.mac} className="rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-[12px] font-medium text-slate-200" title={nodeName(n.model)}>
                  {nodeName(n.model)}
                </span>
                <span className="text-[15px] font-semibold tabular-nums text-white">{n.client_count}</span>
              </div>
              <div className="mt-0.5 text-[10px] text-slate-500">{n.is_main ? 'main router' : n.ip}</div>
              <BandSplit a={n.clients_2g} b={n.clients_5g + n.clients_6g} />
            </div>
          ))}
        </div>
      )}
      <div className="mt-4 text-[11px] font-medium uppercase tracking-wider text-slate-500">Clients</div>
      {clients.length === 0 && <p className="mt-2 text-xs text-slate-500">No wireless clients right now.</p>}
      <div className="mt-2 max-h-[28rem] space-y-3 overflow-y-auto pr-1">
        {groups.map((g) => (
          <div key={g.key}>
            {(nodes.length > 1 || !g.node) && g.items.length > 0 && (
              <div className="mb-1.5 flex items-center gap-1.5 text-[11px] text-slate-400">
                <RouterIcon size={12} className={g.node?.is_main ? 'text-amber-400' : 'text-slate-500'} />
                <span className="font-medium">{g.node ? nodeName(g.node.model) : 'Unknown node'}</span>
                <span className="text-slate-600">· {g.items.length}</span>
              </div>
            )}
            <ul className="space-y-1.5">
              {g.items.map((c) => {
                const band = BAND_STYLE[c.band];
                return (
                  <li key={c.mac} className="flex items-center justify-between gap-2 rounded-lg bg-white/[0.02] px-2.5 py-1.5 ring-1 ring-white/[0.04]">
                    <span className="min-w-0" title={c.mac}>
                      {c.name || c.vendor ? (
                        <span className={`block truncate text-[12.5px] ${c.name ? 'font-medium text-slate-100' : 'italic text-slate-300'}`}>
                          {c.name ?? c.vendor}
                        </span>
                      ) : (
                        <span className="block truncate font-mono text-[12px] text-slate-200">{c.mac}</span>
                      )}
                      <span className="block truncate text-[10px] text-slate-500">
                        {[c.name && c.vendor, (c.name || c.vendor) && c.mac, c.ip].filter(Boolean).join(' · ') || null}
                      </span>
                    </span>
                    <span className="flex shrink-0 items-center gap-1">
                      {fresh.has(c.mac) && <span className="rounded bg-amber-500/15 px-1.5 text-[10px] font-semibold text-amber-300">NEW</span>}
                      {isRandomMac(c.mac) && <span className="rounded bg-violet-500/15 px-1.5 text-[10px] font-medium text-violet-300">private</span>}
                      {c.rssi != null && (
                        <span className="text-[10px] font-medium tabular-nums" style={{ color: rssiColor(c.rssi) }} title="Signal (dBm)">
                          {c.rssi}
                        </span>
                      )}
                      <span className="rounded px-1.5 text-[10px] font-semibold" style={{ color: band.color, background: band.bg }}>
                        {band.label}
                      </span>
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
      {finding && !NOTHING.test(finding.trim()) && <p className="mt-3 text-[12px] leading-relaxed text-slate-400">{finding}</p>}
    </Card>
  );
}

function Band({ name, band, count, color }: { name: string; band: string; count: number; color: string }) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/[0.05] bg-white/[0.02] p-3">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: `linear-gradient(90deg, ${color}, transparent)` }} />
      <div className="text-[11px] font-semibold uppercase tracking-wider" style={{ color }}>
        {band}
      </div>
      <div className="mt-1 text-[22px] font-semibold leading-none tabular-nums text-white">{count}</div>
      <div className="mt-1 truncate text-[11px] text-slate-500">{name || '—'}</div>
    </div>
  );
}

/* ------------------------------------------------------------------ router */

function RouterCard({ snap }: { snap: Snapshot }) {
  const s = snap.system;
  const memPct = s.mem_total_kb ? Math.round(100 * (1 - (s.mem_available_kb || s.mem_free_kb) / s.mem_total_kb)) : 0;
  const temps = [
    { label: 'CPU', v: s.temps_c?.cpu, max: 95 },
    { label: '2.4 GHz radio', v: s.temps_c?.radio_2g, max: 110 },
    { label: '5 GHz radio', v: s.temps_c?.radio_5g, max: 110 },
  ];
  const load = s.loadavg.map(Number);

  return (
    <Card title="Router" icon={<RouterIcon size={15} className="text-amber-400" />} action={<span className="text-[11px] text-slate-500">{s.productid}</span>}>
      <div className="flex items-center gap-2 rounded-xl border border-white/[0.05] bg-gradient-to-r from-amber-500/[0.08] to-transparent px-3 py-2">
        <Zap size={15} className="shrink-0 text-amber-300" />
        <div className="min-w-0">
          <div className="truncate text-[13px] font-semibold text-white">{s.firmware ?? `${s.firmver}.${s.buildno}`}</div>
          <div className="text-[11px] text-slate-500">
            up {duration(s.uptime_seconds)} · custom scripts {s.jffs_scripts_enabled ? 'on' : 'off'}
          </div>
        </div>
      </div>

      <div className="mt-4 space-y-3">
        <div>
          <div className="mb-1 flex justify-between text-xs">
            <span className="text-slate-400">Memory</span>
            <span className="tabular-nums text-slate-200">{memPct}%</span>
          </div>
          <Meter pct={memPct} from={C.amber} to={C.orange} />
        </div>
        {temps.map((t) => (
          <div key={t.label}>
            <div className="mb-1 flex justify-between text-xs">
              <span className="flex items-center gap-1 text-slate-400">
                <Thermometer size={12} />
                {t.label}
              </span>
              <span className="tabular-nums text-slate-200">{t.v != null ? `${Math.round(t.v)}°C` : '—'}</span>
            </div>
            <Meter pct={t.v != null ? (100 * t.v) / t.max : 0} from={C.emerald} to={t.v != null && t.v > t.max * 0.8 ? C.red : C.amber} />
          </div>
        ))}
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2">
        {['1 min', '5 min', '15 min'].map((l, i) => (
          <MiniStat key={l} label={`Load ${l.replace(' min', 'm')}`} value={Number.isFinite(load[i]) ? load[i].toFixed(2) : '—'} />
        ))}
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------ trends */

function TrendsCard({ history, className = '' }: { history: HistoryResponse | null; className?: string }) {
  const snaps = history?.snapshots ?? [];
  const clients = snaps.filter((s) => s.client_count != null);
  const mem = snaps.filter((s) => s.mem_used_pct != null);
  const fmt = (t: number) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });

  return (
    <Card title="Trends · 30 days" icon={<TrendingUp size={15} className="text-violet-400" />} className={className}>
      {!history?.available && <p className="mb-2 text-xs text-slate-500">History archive (Postgres) unreachable - showing live data only.</p>}
      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        <div>
          <div className="mb-1 flex items-center justify-between">
            <Legend items={[{ name: 'Wi-Fi clients', color: C.teal }]} />
          </div>
          <AreaChart
            x={clients.map((s) => new Date(s.collected_at).getTime())}
            series={[{ name: 'Clients', color: C.teal, values: clients.map((s) => s.client_count) }]}
            height={170}
            formatX={fmt}
            empty="Not enough history yet."
          />
        </div>
        <div>
          <div className="mb-1">
            <Legend items={[{ name: 'Memory used', color: C.amber }]} />
          </div>
          <AreaChart
            x={mem.map((s) => new Date(s.collected_at).getTime())}
            series={[{ name: 'Memory', color: C.amber, values: mem.map((s) => s.mem_used_pct), unit: '%' }]}
            yMax={100}
            height={170}
            formatX={fmt}
            empty="Not enough history yet."
          />
        </div>
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------ events */

type Ev = WatchdogEvent & { detail?: Record<string, unknown> };

function describe(e: Ev): { label: string; sub?: string; tone: Tone; icon: typeof Power } {
  const d = { ...(e.detail ?? {}), ...e } as Record<string, unknown>;
  switch (e.event) {
    case 'down_detected':
      return { label: 'Internet outage detected', tone: 'high', icon: ArrowDownRight };
    case 'recovered':
      return { label: 'Connection restored', sub: `down for ${duration(Number(d.downtime_seconds))}`, tone: 'ok', icon: CheckCircle2 };
    case 'restart_triggered':
      return { label: 'Watchdog restarted WAN', tone: 'caution', icon: RefreshCw };
    case 'restart_result':
      return { label: d.ok ? 'WAN restart succeeded' : 'WAN restart failed', tone: d.ok ? 'ok' : 'high', icon: Power };
    default:
      if (e.event.startsWith('router_wan_')) {
        const kind = e.event.slice('router_wan_'.length);
        const tone: Tone = kind === 'connected' ? 'ok' : kind === 'disconnected' || kind === 'stopped' ? 'high' : 'info';
        return { label: `Router: WAN ${kind}`, sub: d.ip ? `IP ${String(d.ip)}` : undefined, tone, icon: RouterIcon };
      }
      return { label: e.event.replace(/_/g, ' '), tone: 'neutral', icon: History };
  }
}

function EventsCard({ data, history }: { data: DashboardState; history: HistoryResponse | null }) {
  const [all, setAll] = useState(false);
  const events: Ev[] = (history?.available && history.watchdog_events.length ? history.watchdog_events : data.watchdog_events) as Ev[];
  const shown = all ? events.slice(0, 60) : events.slice(0, 6);

  return (
    <Card
      title="Events"
      icon={<History size={15} className="text-sky-400" />}
      action={
        events.length > 6 && (
          <button onClick={() => setAll((a) => !a)} className="text-[11px] font-medium text-sky-300 hover:text-sky-200">
            {all ? 'Show less' : `Show all ${events.length}`}
          </button>
        )
      }
    >
      {events.length === 0 ? (
        <p className="text-sm text-slate-500">No connectivity events - smooth sailing.</p>
      ) : (
        <ol className={`relative space-y-3 ${all ? 'max-h-[520px] overflow-y-auto pr-1' : ''}`}>
          <span className="absolute bottom-1 left-[11px] top-1 w-px bg-white/[0.06]" />
          {shown.map((e, i) => {
            const d = describe(e);
            const t = TONE[d.tone];
            return (
              <li key={`${e.ts}-${i}`} className="relative flex gap-3">
                <span className={`relative z-[1] mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full ring-1 ${t.bg} ${t.ring}`}>
                  <d.icon size={12} className={t.text} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="truncate text-[13px] font-medium text-slate-200">{d.label}</span>
                    <span className="shrink-0 text-[11px] tabular-nums text-slate-500" title={e.ts}>
                      {relTime(e.ts)}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {dayClock(e.ts)}
                    {d.sub ? ` · ${d.sub}` : ''}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}

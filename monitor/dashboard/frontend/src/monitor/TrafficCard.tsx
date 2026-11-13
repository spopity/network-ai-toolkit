import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, MessageSquare, Network } from 'lucide-react';
import { AreaChart, Legend } from '../components/AreaChart';
import { C, Card, Segmented, Skeleton } from '../components/ui';
import { useJson } from '../hooks/useJson';
import { bytes, relTime } from '../lib/format';
import { NET_COLOR, NET_ORDER, NetChip, NetDot, Stat } from './DnsCard';

/** Per-device internet usage from the router's Traffic Analyzer archive (/api/traffic/*). */

interface TrafficDevice {
  mac: string;
  device: string;
  network: string;
  ip: string | null;
  rx: number;
  tx: number;
  last_seen: string;
  top_apps: { app: string; bytes: number }[] | null;
}

interface TrafficApp {
  app: string;
  category: string | null;
  rx: number;
  tx: number;
  devices: number;
}

interface TrafficDetail {
  apps: TrafficApp[];
  series: { hour: string; rx: number; tx: number }[];
}

const DOWN = C.sky;
const UP = C.pink;
const ALL = '__all__';

function span(hours: number) {
  return hours === 24 ? 'the last 24h' : `the last ${hours / 24} days`;
}

export function TrafficCard({ onAsk }: { onAsk: (q: string) => void }) {
  const [hours, setHours] = useState(24);
  const [net, setNet] = useState<string>('all');
  const [selected, setSelected] = useState<string>(ALL);

  const { data: devData, error } = useJson<{ devices: TrafficDevice[] }>(`/api/traffic/devices?hours=${hours}`);
  const all = useMemo(() => devData?.devices ?? [], [devData]);
  const nets = useMemo(() => {
    const m = new Map<string, { bytes: number; devices: number }>();
    for (const d of all) {
      const n = m.get(d.network) ?? { bytes: 0, devices: 0 };
      n.bytes += d.rx + d.tx;
      n.devices += 1;
      m.set(d.network, n);
    }
    return NET_ORDER.filter((k) => m.has(k)).map((k) => ({ net: k, ...m.get(k)! }));
  }, [all]);

  const devices = net === 'all' ? all : all.filter((d) => d.network === net);
  const rx = devices.reduce((s, d) => s + d.rx, 0);
  const tx = devices.reduce((s, d) => s + d.tx, 0);
  const maxB = Math.max(1, ...devices.map((d) => d.rx + d.tx));
  const current = devices.find((d) => d.mac === selected) ?? null; // null = whole network (or the chosen one)

  const detailUrl =
    `/api/traffic/detail?hours=${hours}&limit=40` +
    (current ? `&device=${encodeURIComponent(current.mac)}` : net !== 'all' ? `&network=${encodeURIComponent(net)}` : '');
  const { data: detail } = useJson<TrafficDetail>(devData ? detailUrl : null);
  const apps = detail?.apps ?? [];
  const maxA = Math.max(1, ...apps.map((a) => a.rx + a.tx));
  const series = detail?.series ?? [];
  const accent = current ? NET_COLOR[current.network] ?? DOWN : net !== 'all' ? NET_COLOR[net] ?? DOWN : DOWN;

  const title = current ? current.device : net === 'all' ? 'Whole network' : `${net} network`;
  const askAbout = current
    ? `How has ${current.device} (${current.network}, ${current.ip ?? current.mac}) been using the internet over ${span(hours)}? Which apps, and is anything unusual (uploads, odd hours)?`
    : `Which devices${net !== 'all' ? ` on the ${net} network` : ''} used the most internet over ${span(hours)}, and is anything unusual?`;

  return (
    <Card
      title="Internet usage"
      icon={<ArrowUpDown size={15} className="text-sky-400" />}
      action={
        <Segmented
          options={[
            { label: '24h', value: 24 },
            { label: '7d', value: 168 },
            { label: '14d', value: 336 },
          ]}
          value={hours}
          onChange={setHours}
        />
      }
    >
      {error && !all.length ? (
        <p className="text-xs text-slate-500">Traffic archive unavailable: {error}</p>
      ) : !devData ? (
        <div className="grid gap-3 lg:grid-cols-5">
          <Skeleton className="h-64 lg:col-span-2" />
          <Skeleton className="h-64 lg:col-span-3" />
        </div>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-2">
            <Stat label="Download" value={bytes(rx)} accent={DOWN} />
            <Stat label="Upload" value={bytes(tx)} accent={UP} />
            <Stat label="Devices" value={String(devices.length)} sub="used the internet" accent={C.teal} />
          </div>

          <div className="mt-3 flex flex-wrap gap-1.5">
            <NetChip active={net === 'all'} onClick={() => setNet('all')} label="All" count={all.length} />
            {nets.map((n) => (
              <NetChip key={n.net} active={net === n.net} onClick={() => setNet(n.net)} label={n.net} count={n.devices} color={NET_COLOR[n.net]} />
            ))}
          </div>

          <div className="mt-3 grid min-w-0 gap-3 lg:grid-cols-5">
            {/* device list, busiest first */}
            <ul className="max-h-[17rem] min-w-0 space-y-1 overflow-y-auto pr-1 lg:col-span-2 lg:max-h-[30rem]">
              <li>
                <button
                  onClick={() => setSelected(ALL)}
                  className={`flex w-full items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-left ring-1 transition ${
                    !current ? 'bg-sky-500/10 ring-sky-500/30' : 'bg-white/[0.02] ring-white/[0.04] hover:bg-white/[0.05]'
                  }`}
                >
                  <span className="flex items-center gap-1.5 text-[12.5px] font-medium text-slate-100">
                    <Network size={12} className="text-slate-400" />
                    {net === 'all' ? 'Whole network' : `All ${net} devices`}
                  </span>
                  <span className="text-[11px] tabular-nums text-slate-200">{bytes(rx + tx)}</span>
                </button>
              </li>
              {devices.length === 0 && <li className="px-1 py-2 text-xs text-slate-500">No internet traffic in this window.</li>}
              {devices.map((d) => {
                const active = d.mac === current?.mac;
                const total = d.rx + d.tx;
                const color = NET_COLOR[d.network] ?? C.slate;
                return (
                  <li key={d.mac}>
                    <button
                      onClick={() => setSelected(d.mac)}
                      className={`w-full rounded-lg px-2.5 py-1.5 text-left ring-1 transition ${
                        active ? 'bg-sky-500/10 ring-sky-500/30' : 'bg-white/[0.02] ring-white/[0.04] hover:bg-white/[0.05]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex min-w-0 items-center gap-1.5">
                          <NetDot net={d.network} />
                          <span className={`truncate text-[12.5px] ${d.device.startsWith('unnamed') ? 'italic text-slate-300' : 'font-medium text-slate-100'}`}>
                            {d.device}
                          </span>
                        </span>
                        <span className="shrink-0 text-[11px] tabular-nums text-slate-200">{bytes(total)}</span>
                      </div>
                      {/* bar length = share of the busiest device; split download | upload */}
                      <div className="mt-1 flex items-center gap-2">
                        <div className="flex h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                          <div className="h-full" style={{ width: `${(100 * d.rx) / maxB}%`, background: color }} />
                          <div className="h-full" style={{ width: `${(100 * d.tx) / maxB}%`, background: UP, opacity: 0.8 }} />
                        </div>
                        <span className="max-w-[45%] shrink-0 truncate text-[10px] text-slate-500">{d.top_apps?.[0]?.app ?? ''}</span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>

            {/* selection: hourly chart + apps */}
            <div className="min-w-0 rounded-xl border border-white/[0.05] bg-white/[0.02] p-3 lg:col-span-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    {current && <NetDot net={current.network} />}
                    <span className="truncate text-[14px] font-semibold text-white">{title}</span>
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[10.5px] text-slate-500">
                    <span className="flex items-center gap-0.5 text-sky-300">
                      <ArrowDown size={10} />
                      {bytes(current ? current.rx : rx)}
                    </span>
                    <span className="flex items-center gap-0.5 text-pink-300">
                      <ArrowUp size={10} />
                      {bytes(current ? current.tx : tx)}
                    </span>
                    {current && (
                      <span className="truncate">
                        {[current.network, current.ip, current.mac, `active ${relTime(current.last_seen)}`].filter(Boolean).join(' · ')}
                      </span>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => onAsk(askAbout)}
                  className="flex shrink-0 items-center gap-1.5 rounded-lg bg-white/[0.04] px-2.5 py-1 text-[11px] font-medium text-slate-300 ring-1 ring-white/10 transition hover:bg-white/[0.08] hover:text-white"
                >
                  <MessageSquare size={12} /> Ask Tshoot
                </button>
              </div>

              <div className="mt-3">
                <div className="mb-1">
                  <Legend items={[{ name: 'Download', color: accent }, { name: 'Upload', color: UP }]} />
                </div>
                {!detail ? (
                  <Skeleton className="h-[150px]" />
                ) : (
                  <AreaChart
                    x={series.map((s) => new Date(s.hour).getTime())}
                    height={150}
                    series={[
                      { name: 'Download', color: accent, values: series.map((s) => s.rx), area: true },
                      { name: 'Upload', color: UP, values: series.map((s) => s.tx) },
                    ]}
                    formatY={(v) => (v ? bytes(v).replace(/ ?B$/, '').replace(' ', '') : '0')}
                    formatX={(t) =>
                      hours > 24
                        ? new Date(t).toLocaleDateString([], { weekday: 'short', day: 'numeric' })
                        : new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                    }
                    empty="No traffic recorded yet."
                  />
                )}
              </div>

              <div className="mt-3 text-[10.5px] font-medium uppercase tracking-wider text-slate-500">Apps</div>
              <ul className="mt-1.5 max-h-[13rem] space-y-1 overflow-y-auto pr-1">
                {!detail && Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-7" />)}
                {detail && apps.length === 0 && <li className="py-4 text-center text-xs text-slate-500">No traffic in this window.</li>}
                {apps.map((a) => (
                  <li key={a.app} className="relative overflow-hidden rounded-md px-2 py-1">
                    <div
                      className="absolute inset-y-0 left-0 rounded-md opacity-[0.12]"
                      style={{ width: `${Math.max(2, (100 * (a.rx + a.tx)) / maxA)}%`, background: accent }}
                    />
                    <div className="relative flex items-center justify-between gap-2">
                      <span className="min-w-0 truncate text-[12px] text-slate-200" title={a.category ?? undefined}>
                        {a.app}
                        {!current && a.devices > 1 && <span className="ml-1.5 text-[10px] text-slate-500">{a.devices} devices</span>}
                      </span>
                      <span className="flex shrink-0 items-center gap-2 text-[10.5px] tabular-nums">
                        <span className="hidden text-pink-300/80 sm:inline">↑ {bytes(a.tx)}</span>
                        <span className="w-16 text-right text-slate-200">{bytes(a.rx + a.tx)}</span>
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <p className="mt-2 text-[10.5px] text-slate-600">
            Internet traffic only (not between devices at home), as measured by the router's Traffic Analyzer, which records once an hour.
          </p>
        </>
      )}
    </Card>
  );
}

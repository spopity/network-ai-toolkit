import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Eye, EyeOff, Globe, MapPin, Search, Wifi } from 'lucide-react';
import { Segmented, Skeleton } from '../components/ui';
import { relTime } from '../lib/format';
import { NET_COLOR } from '../monitor/DnsCard';
import { TYPE_LABEL } from './icons';
import type { MapDevice, MapNode } from './types';
import { DeviceChip, NodeCard } from './DeviceChip';
import { DeviceDetail } from './DeviceDetail';
import { type Edge, type Pt, LinkLayer, LinkLegend } from './LinkLayer';
import { ServiceRow } from './ServiceRow';
import { useMapData, usePersisted } from './useMapData';

const NETS = ['all', 'LAN', 'IoT', 'Guest', 'VPN'] as const;
type NetFilter = (typeof NETS)[number];
/* ------------------------------------------------------------------ view */

export function NetworkMapView({ refreshKey, onAsk }: { refreshKey?: string | null; onAsk: (q: string) => void }) {
  const { data, error } = useMapData(refreshKey);
  const [net, setNet] = usePersisted<NetFilter>('nai-map-net', 'all');
  const [offline, setOffline] = usePersisted<'0' | '1'>('nai-map-offline', '0');
  const [query, setQuery] = useState('');
  const [hover, setHover] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  const nodeById = useMemo(() => new Map((data?.nodes ?? []).map((n) => [n.id, n])), [data]);
  const devById = useMemo(() => new Map((data?.devices ?? []).map((d) => [d.id, d])), [data]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.devices ?? []).filter(
      (d) =>
        (d.online || offline === '1') &&
        (net === 'all' || d.network === net) &&
        (!q || [d.name, d.ip, d.mac, d.vendor, d.room, d.host, TYPE_LABEL[d.type]].some((v) => v && v.toLowerCase().includes(q))),
    );
  }, [data, net, offline, query]);

  const rooms = useMemo(() => {
    const by = new Map<string, { nodes: MapNode[]; devices: MapDevice[] }>();
    for (const r of data?.rooms ?? []) by.set(r, { nodes: [], devices: [] });
    const room = (r: string) => {
      if (!by.has(r)) by.set(r, { nodes: [], devices: [] });
      return by.get(r)!;
    };
    for (const n of data?.nodes ?? []) room(n.room).nodes.push(n);
    for (const d of visible) room(d.room).devices.push(d);
    return [...by.entries()].filter(([, v]) => v.nodes.length || v.devices.length);
  }, [data, visible]);

  const edges = useMemo(() => {
    const out: Edge[] = [];
    const main = data?.nodes.find((n) => n.is_main);
    if (main) out.push({ id: 'wan', from: 'internet', to: main.id, kind: 'wan' });
    for (const n of data?.nodes ?? []) {
      if (n.uplink?.to) out.push({ id: `up:${n.id}`, from: n.id, to: n.uplink.to, kind: n.uplink.kind === 'wired' ? 'backhaul-wired' : 'backhaul-wireless' });
    }
    for (const d of visible) {
      if (d.link?.to) out.push({ id: `l:${d.id}`, from: d.id, to: d.link.to, kind: d.link.kind, band: d.link.band, inferred: d.link.inferred });
    }
    return out;
  }, [data, visible]);

  // what is "in focus": the hovered/selected device, node (+ everything on it) or room
  const focusId = hover ?? selected;
  const related = useMemo(() => {
    if (!focusId) return null;
    const ids = new Set<string>([focusId]);
    if (focusId.startsWith('room:')) {
      const room = focusId.slice(5);
      for (const [r, v] of rooms) if (r === room) [...v.nodes, ...v.devices].forEach((x) => ids.add(x.id));
    } else if (nodeById.has(focusId)) {
      for (const d of visible) if (d.link?.to === focusId) ids.add(d.id);
      const n = nodeById.get(focusId)!;
      if (n.uplink?.to) ids.add(n.uplink.to);
      for (const m of data?.nodes ?? []) if (m.uplink?.to === focusId) ids.add(m.id);
      if (n.is_main) ids.add('internet');
    } else {
      const d = devById.get(focusId);
      if (d?.link?.to) ids.add(d.link.to);
    }
    return ids;
  }, [focusId, rooms, nodeById, devById, visible, data]);

  // links drawn on top: a device's own link, every link touching a node, a room's outgoing links
  const hot = !related || !focusId
    ? []
    : focusId.startsWith('room:')
      ? edges.filter((e) => related.has(e.from) && e.from !== focusId)
      : edges.filter((e) => e.from === focusId || e.to === focusId);

  // measure every anchor (icon) relative to the canvas; links are drawn between them
  const canvasRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<Record<string, Pt>>({});
  const [size, setSize] = useState({ w: 0, h: 0 });
  const layoutKey = `${rooms.map(([r, v]) => r + v.devices.length + v.nodes.length).join('|')}`;
  useLayoutEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    let raf = 0;
    const measure = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const base = el.getBoundingClientRect();
        const out: Record<string, Pt> = {};
        el.querySelectorAll<HTMLElement>('[data-anchor]').forEach((n) => {
          const r = n.getBoundingClientRect();
          out[n.dataset.anchor!] = { x: r.left - base.left + r.width / 2, y: r.top - base.top + r.height / 2 };
        });
        setPos(out);
        setSize({ w: el.offsetWidth, h: el.offsetHeight });
      });
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    el.querySelectorAll('[data-room]').forEach((r) => ro.observe(r));
    window.addEventListener('resize', measure);
    document.fonts?.ready.then(measure);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [layoutKey, data]);

  const selDevice = selected ? (devById.get(selected) ?? null) : null;
  const selNode = selected ? (nodeById.get(selected) ?? null) : null;
  const toggleSelect = (id: string) => setSelected((s) => (s === id ? null : id));

  if (!data) {
    return (
      <div className="mx-auto max-w-[1600px] space-y-4 p-4 lg:p-6">
        {error ? <p className="text-sm text-red-300">Network map unavailable: {error}</p> : null}
        <Skeleton className="h-12" />
        <div className="grid gap-4 lg:grid-cols-3">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-56" />
          ))}
        </div>
      </div>
    );
  }

  const online = data.devices.filter((d) => d.online).length;
  const offlineCount = data.devices.length - online;
  const nets = NETS.filter((n) => n === 'all' || data.devices.some((d) => d.network === n));

  return (
    <div className="mx-auto max-w-[1700px] p-3 pb-[calc(6rem+env(safe-area-inset-bottom))] sm:p-4 lg:p-6 lg:pb-8">
      {/* toolbar */}
      <div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2.5">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-[15px] font-semibold text-white">
            <MapPin size={16} className="text-sky-300" /> Network map
          </h2>
          <p className="text-[11.5px] text-slate-500">
            {online} online · {data.nodes.length} mesh nodes · {rooms.length} rooms · from the check {relTime(data.collected_at)}
            {error && <span className="text-amber-300"> · refresh failed</span>}
          </p>
        </div>
        <div className="flex flex-1 flex-wrap items-center justify-end gap-2">
          <label className="flex min-w-0 basis-full items-center gap-2 rounded-lg bg-white/[0.04] px-2.5 py-1.5 ring-1 ring-white/[0.06] sm:max-w-[240px] sm:flex-1 sm:basis-auto">
            <Search size={13} className="shrink-0 text-slate-500" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Find name, IP, MAC…"
              className="w-full min-w-0 bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none"
            />
          </label>
          <Segmented options={nets.map((n) => ({ label: n === 'all' ? 'All' : n, value: n }))} value={net} onChange={setNet} />
          <button
            onClick={() => setOffline(offline === '1' ? '0' : '1')}
            className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium ring-1 transition ${
              offline === '1' ? 'bg-white/10 text-white ring-white/15' : 'bg-white/[0.04] text-slate-400 ring-white/[0.06] hover:text-slate-200'
            }`}
          >
            {offline === '1' ? <Eye size={13} /> : <EyeOff size={13} />} Offline ({offlineCount})
          </button>
        </div>
      </div>

      {!data.has_topology && (
        <p className="mb-4 rounded-xl bg-amber-500/10 px-3 py-2 text-xs text-amber-200 ring-1 ring-amber-500/20">
          Wired devices, backhaul and services appear after the next 5-minute check.
        </p>
      )}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        {/* canvas */}
        <div ref={canvasRef} className="relative min-w-0" onMouseLeave={() => setHover(null)}>
          <LinkLayer edges={edges} pos={pos} size={size} highlight={false} />

          <div className="relative z-10">
            {/* the internet, above everything */}
            <div className="mb-10 flex justify-center">
              <div className="flex items-center gap-3 rounded-2xl border border-white/[0.07] bg-ink-900/85 px-3.5 py-2.5 backdrop-blur">
                <div data-anchor="internet" className="grid h-10 w-10 place-items-center rounded-xl bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-400/30">
                  <Globe size={19} />
                </div>
                <div className="leading-tight">
                  <div className="flex items-center gap-1.5 text-[13px] font-semibold text-white">
                    Internet
                    <span className={`h-1.5 w-1.5 rounded-full ${data.wan.up ? 'bg-emerald-400' : 'bg-red-400'}`} />
                  </div>
                  <div className="font-mono text-[10.5px] text-slate-400">
                    {data.wan.ip ?? '—'} · {(data.wan.proto ?? 'wan').toUpperCase()}
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-flow-dense grid-cols-1 items-start gap-x-8 gap-y-6 lg:grid-cols-2 2xl:grid-cols-3">
              {rooms.map(([room, v]) => {
                const big = v.devices.length + v.nodes.length * 2 > 9;
                const guessed = v.devices.length > 0 && v.devices.every((d) => d.room_guessed) && !v.nodes.length;
                const roomDim = related && !related.has(`room:${room}`) && ![...v.nodes, ...v.devices].some((x) => related.has(x.id));
                return (
                  <section
                    key={room}
                    data-room={room}
                    className={`rounded-2xl border border-white/[0.07] bg-ink-900/60 p-3 pl-5 transition ${big ? 'lg:col-span-2' : ''} ${roomDim ? 'opacity-60' : ''}`}
                  >
                    <header
                      className="mb-2 flex cursor-default items-center justify-between gap-2"
                      onMouseEnter={() => setHover(`room:${room}`)}
                      onMouseLeave={() => setHover(null)}
                    >
                      <h3 className="flex items-center gap-2 text-[12px] font-semibold uppercase tracking-wider text-slate-300">
                        {room}
                        {guessed && <span className="rounded bg-white/[0.05] px-1.5 py-px text-[9.5px] font-medium normal-case tracking-normal text-slate-500">guessed</span>}
                      </h3>
                      <span className="flex items-center gap-1 text-[11px] tabular-nums text-slate-500">
                        <Wifi size={11} /> {v.devices.filter((d) => d.online).length}
                      </span>
                    </header>
                    {v.nodes.map((n) => (
                      <NodeCard
                        key={n.id}
                        n={n}
                        dim={Boolean(related && !related.has(n.id))}
                        active={selected === n.id}
                        onHover={setHover}
                        onSelect={toggleSelect}
                      />
                    ))}
                    <div className="grid gap-0.5 [grid-template-columns:repeat(auto-fill,minmax(205px,1fr))]">
                      {v.devices.map((d) => (
                        <DeviceChip
                          key={d.id}
                          d={d}
                          dim={Boolean(related && !related.has(d.id))}
                          active={selected === d.id}
                          onHover={setHover}
                          onSelect={toggleSelect}
                        />
                      ))}
                    </div>
                  </section>
                );
              })}
            </div>
          </div>

          <LinkLayer edges={hot} pos={pos} size={size} highlight />
        </div>

        {/* side column: selection, legend, services */}
        <aside className="space-y-4 xl:sticky xl:top-4 xl:self-start">
          <DeviceDetail d={selDevice} node={selNode} nodeById={nodeById} onClose={() => setSelected(null)} onAsk={onAsk} />

          <section className="rounded-2xl border border-white/[0.06] bg-ink-900/80 p-4">
            <h3 className="mb-3 text-[12px] font-semibold uppercase tracking-wider text-slate-400">Legend</h3>
            <LinkLegend />
            <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1.5 border-t border-white/[0.06] pt-3 text-[11px] text-slate-400">
              {['LAN', 'IoT', 'Guest', 'VPN'].map((n) => (
                <span key={n} className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-[4px]" style={{ background: `${NET_COLOR[n]}55`, boxShadow: `inset 0 0 0 1px ${NET_COLOR[n]}` }} />
                  {n}
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400" /> online
              </span>
            </div>
          </section>

          <section className="rounded-2xl border border-white/[0.06] bg-ink-900/80 p-4">
            <h3 className="mb-1 flex items-center justify-between text-[12px] font-semibold uppercase tracking-wider text-slate-400">
              On the router
              <span className="text-[10.5px] font-medium normal-case tracking-normal text-slate-500">
                {data.services.filter((s) => s.status === 'ok').length}/{data.services.length} running
              </span>
            </h3>
            <ul className="divide-y divide-white/[0.04]">
              {data.services.map((s) => (
                <ServiceRow key={s.id} s={s} />
              ))}
            </ul>
          </section>
        </aside>
      </div>
    </div>
  );
}

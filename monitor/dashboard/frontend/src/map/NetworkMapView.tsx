import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Cable, CircleDot, Eye, EyeOff, Globe, KeyRound, MapPin, MessageSquare, Router as RouterIcon, Search, Wifi, X } from 'lucide-react';
import { C, Segmented, Skeleton } from '../components/ui';
import { relTime } from '../lib/format';
import { NET_COLOR } from '../monitor/DnsCard';
import { BRAND_NAME, BrandLogo, hasLogo, SERVICE_ICON, TYPE_ICON, TYPE_LABEL } from './icons';
import type { MapDevice, MapLink, MapNode, MapService, NetworkMapData, ServiceStatus } from './types';

/**
 * Live map of the network: rooms (from device names), each device linked to the mesh node
 * it is connected to (Wi-Fi band/signal or cable, from the latest 5-minute check), the
 * mesh backhaul, and the router's services. Links sit behind the cards; hovering or
 * selecting a device, node or room draws its links on top.
 */

const POLL_MS = 60_000;
const WIRED = '#cbd5e1';
const BAND_COLOR: Record<string, string> = { '2g': C.amber, '5g': C.sky, '6g': C.violet };
const BAND_LABEL: Record<string, string> = { '2g': '2.4 GHz', '5g': '5 GHz', '6g': '6 GHz' };
const STATUS_COLOR: Record<ServiceStatus, string> = { ok: C.emerald, warn: C.amber, down: C.red, off: C.slate };
const NETS = ['all', 'LAN', 'IoT', 'Guest', 'VPN'] as const;
type NetFilter = (typeof NETS)[number];

/* ------------------------------------------------------------------ data */

function useMapData(refreshKey: string | null | undefined) {
  const [data, setData] = useState<NetworkMapData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/network-map');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);
  useEffect(() => {
    load();
    const t = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(t);
  }, [load, refreshKey]);
  return { data, error };
}

function usePersisted<T extends string>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      return (localStorage.getItem(key) as T) ?? initial;
    } catch {
      return initial;
    }
  });
  return [
    v,
    (nv) => {
      setV(nv);
      try {
        localStorage.setItem(key, nv);
      } catch {
        /* per-viewer convenience only */
      }
    },
  ];
}

/* ------------------------------------------------------------------ links */

interface Edge {
  id: string;
  from: string; // anchor id (device / node / "internet")
  to: string;
  kind: MapLink['kind'] | 'backhaul-wired' | 'backhaul-wireless' | 'wan';
  band?: string | null;
  inferred?: boolean;
}

function edgeStyle(e: Edge): { color: string; width: number; dash?: string; flow?: boolean } {
  switch (e.kind) {
    case 'wan':
      return { color: C.emerald, width: 3, flow: true };
    case 'backhaul-wired':
      return { color: WIRED, width: 3, flow: true };
    case 'backhaul-wireless':
      return { color: C.violet, width: 2.5, dash: '7 5', flow: true };
    case 'wifi':
      return { color: BAND_COLOR[e.band ?? ''] ?? C.sky, width: 1.5, dash: '4 4', flow: true };
    case 'wired':
      return { color: WIRED, width: 1.5, dash: e.inferred ? '2 4' : undefined, flow: !e.inferred };
    case 'vpn':
      return { color: C.amber, width: 1.8, dash: '1 5', flow: true };
    default:
      return { color: C.slate, width: 1.2, dash: '1 5' };
  }
}

type Pt = { x: number; y: number };

function pathFor(a: Pt, b: Pt): string {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  // stacked in the same column (device under its node in one room): bow out to the left
  if (Math.abs(dx) < 40) {
    const bow = Math.min(70, 24 + Math.abs(dy) * 0.12);
    return `M${a.x},${a.y} C${a.x - bow},${a.y} ${b.x - bow},${b.y} ${b.x},${b.y}`;
  }
  if (Math.abs(dy) > Math.abs(dx) * 0.6) {
    return `M${a.x},${a.y} C${a.x},${a.y + dy * 0.5} ${b.x},${b.y - dy * 0.5} ${b.x},${b.y}`;
  }
  return `M${a.x},${a.y} C${a.x + dx * 0.5},${a.y} ${b.x - dx * 0.5},${b.y} ${b.x},${b.y}`;
}

function LinkLayer({ edges, pos, size, highlight }: { edges: Edge[]; pos: Record<string, Pt>; size: { w: number; h: number }; highlight: boolean }) {
  return (
    <svg
      className={`pointer-events-none absolute left-0 top-0 ${highlight ? 'z-20' : 'z-0'}`}
      width={size.w}
      height={size.h}
      aria-hidden="true"
    >
      {edges.map((e) => {
        const a = pos[e.from];
        const b = pos[e.to];
        if (!a || !b) return null;
        const s = edgeStyle(e);
        const d = pathFor(a, b);
        return (
          <g key={e.id}>
            {highlight && <path d={d} fill="none" stroke={s.color} strokeWidth={s.width + 5} strokeOpacity={0.12} strokeLinecap="round" />}
            <path
              d={d}
              fill="none"
              stroke={s.color}
              strokeWidth={highlight ? s.width + 0.5 : s.width}
              strokeOpacity={highlight ? 0.95 : 0.5}
              strokeDasharray={s.dash}
              strokeLinecap="round"
              className={s.flow && s.dash ? 'map-flow' : undefined}
            />
            {/* packets: a sparse dash running along solid (wired) links */}
            {s.flow && !s.dash && (
              <path
                d={d}
                fill="none"
                stroke={highlight ? '#fff' : s.color}
                strokeWidth={s.width}
                strokeOpacity={highlight ? 0.8 : 0.6}
                strokeDasharray="2 22"
                strokeLinecap="round"
                className="map-flow-slow"
              />
            )}
          </g>
        );
      })}
    </svg>
  );
}

/* ------------------------------------------------------------------ pieces */

function signalBars(rssi: number | null | undefined): number {
  if (rssi == null) return 0;
  return rssi > -55 ? 4 : rssi > -65 ? 3 : rssi > -75 ? 2 : 1;
}

function Bars({ rssi, color }: { rssi: number | null | undefined; color: string }) {
  const n = signalBars(rssi);
  return (
    <span className="inline-flex items-end gap-[2px]" title={rssi != null ? `${rssi} dBm` : undefined}>
      {[1, 2, 3, 4].map((i) => (
        <span key={i} className="w-[3px] rounded-sm" style={{ height: 3 + i * 2, background: i <= n ? color : 'rgba(148,163,184,0.22)' }} />
      ))}
    </span>
  );
}

function LinkBadge({ link }: { link: MapLink | null }) {
  if (!link) return null;
  if (link.kind === 'wifi') {
    const color = BAND_COLOR[link.band ?? ''] ?? C.sky;
    return (
      <span className="flex shrink-0 flex-col items-end gap-0.5">
        <Bars rssi={link.rssi} color={color} />
        <span className="text-[9.5px] font-medium tabular-nums" style={{ color }}>
          {link.band === '2g' ? '2.4' : link.band === '6g' ? '6' : '5'}G
        </span>
      </span>
    );
  }
  if (link.kind === 'wired') return <Cable size={13} className="shrink-0 text-slate-400" aria-label="wired" />;
  if (link.kind === 'vpn') return <KeyRound size={13} className="shrink-0 text-amber-300" aria-label="VPN" />;
  return <CircleDot size={12} className="shrink-0 text-slate-500" aria-label="link unknown" />;
}

function DeviceIcon({ d, size = 36, anchor = false }: { d: MapDevice; size?: number; anchor?: boolean }) {
  const Icon = TYPE_ICON[d.type] ?? TYPE_ICON.device;
  const color = NET_COLOR[d.network] ?? C.slate;
  return (
    <div
      data-anchor={anchor ? d.id : undefined}
      className="relative grid shrink-0 place-items-center rounded-xl"
      style={{ width: size, height: size, background: `${color}1f`, boxShadow: `inset 0 0 0 1px ${color}55`, color }}
    >
      <Icon size={Math.round(size * 0.47)} strokeWidth={1.9} />
      {hasLogo(d.brand) && (
        <span className="absolute -bottom-1 -right-1 grid h-[18px] w-[18px] place-items-center rounded-full bg-ink-800 ring-1 ring-white/15">
          <BrandLogo brand={d.brand} size={10} />
        </span>
      )}
      {d.online && (
        <span className="absolute -right-0.5 -top-0.5 flex h-2.5 w-2.5">
          <span className="animate-ping-soft absolute inline-flex h-full w-full rounded-full bg-emerald-400" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400 ring-2 ring-ink-900" />
        </span>
      )}
    </div>
  );
}

function DeviceChip({
  d,
  dim,
  active,
  onHover,
  onSelect,
}: {
  d: MapDevice;
  dim: boolean;
  active: boolean;
  onHover: (id: string | null) => void;
  onSelect: (id: string) => void;
}) {
  return (
    <button
      type="button"
      onMouseEnter={() => onHover(d.id)}
      onMouseLeave={() => onHover(null)}
      onFocus={() => onHover(d.id)}
      onBlur={() => onHover(null)}
      onClick={() => onSelect(d.id)}
      className={`flex w-full min-w-0 items-center gap-2.5 rounded-xl px-2 py-1.5 text-left transition ${
        active ? 'bg-white/[0.07] ring-1 ring-white/15' : 'hover:bg-white/[0.04]'
      } ${dim ? 'opacity-35' : ''} ${d.online ? '' : 'grayscale'}`}
    >
      <DeviceIcon d={d} anchor />
      <div className="min-w-0 flex-1 leading-tight">
        <div className={`truncate text-[12.5px] font-medium ${d.online ? 'text-slate-100' : 'text-slate-400'}`}>{d.name}</div>
        <div className="truncate font-mono text-[10.5px] text-slate-400">{d.ip ?? (d.online ? '—' : `seen ${relTime(d.last_seen)}`)}</div>
        <div className="truncate font-mono text-[10px] text-slate-500">{d.mac ?? d.vendor ?? ''}</div>
      </div>
      <LinkBadge link={d.link} />
    </button>
  );
}

function NodeCard({
  n,
  dim,
  active,
  onHover,
  onSelect,
}: {
  n: MapNode;
  dim: boolean;
  active: boolean;
  onHover: (id: string | null) => void;
  onSelect: (id: string) => void;
}) {
  return (
    <button
      type="button"
      onMouseEnter={() => onHover(n.id)}
      onMouseLeave={() => onHover(null)}
      onFocus={() => onHover(n.id)}
      onBlur={() => onHover(null)}
      onClick={() => onSelect(n.id)}
      className={`mb-2 flex w-full items-center gap-3 rounded-xl border px-2.5 py-2 text-left transition ${
        active ? 'border-sky-400/40 bg-sky-500/[0.08]' : 'border-white/[0.07] bg-white/[0.03] hover:bg-white/[0.05]'
      } ${dim ? 'opacity-40' : ''}`}
    >
      <div
        data-anchor={n.id}
        className="relative grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-sky-400 via-violet-500 to-pink-500 shadow-lg shadow-violet-900/40"
      >
        <RouterIcon size={20} className="text-white" />
        <span className="absolute -bottom-1 -right-1 grid h-[18px] w-[18px] place-items-center rounded-full bg-ink-800 ring-1 ring-white/15">
          <BrandLogo brand="asus" size={11} />
        </span>
      </div>
      <div className="min-w-0 flex-1 leading-tight">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-[13px] font-semibold text-white">{n.model}</span>
          <span className={`rounded px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-wide ${n.is_main ? 'bg-sky-500/15 text-sky-300' : 'bg-violet-500/15 text-violet-300'}`}>
            {n.is_main ? 'main' : 'node'}
          </span>
        </div>
        <div className="truncate font-mono text-[10.5px] text-slate-400">{n.ip}</div>
        <div className="truncate font-mono text-[10px] text-slate-500">{n.mac}</div>
      </div>
      <div className="shrink-0 text-right leading-tight">
        <div className="text-[15px] font-semibold tabular-nums text-white">{n.clients}</div>
        <div className="text-[9.5px] uppercase tracking-wide text-slate-500">devices</div>
      </div>
    </button>
  );
}

function ServiceRow({ s }: { s: MapService }) {
  const Icon = SERVICE_ICON[s.id] ?? CircleDot;
  const color = STATUS_COLOR[s.status];
  return (
    <li className="flex items-start gap-2.5 py-1.5">
      <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-lg bg-white/[0.04] ring-1 ring-white/[0.06]">
        {hasLogo(s.brand) ? <BrandLogo brand={s.brand} size={12} /> : <Icon size={13} className="text-slate-300" />}
      </span>
      <div className="min-w-0 flex-1 leading-tight">
        <div className="flex items-center gap-1.5 text-[12px] font-medium text-slate-200">
          <span className="truncate">{s.name}</span>
        </div>
        {s.detail && <div className="mt-0.5 text-[10.5px] leading-snug text-slate-500">{s.detail}</div>}
      </div>
      <span className="mt-1 flex shrink-0 items-center gap-1 text-[10px] font-medium uppercase" style={{ color }}>
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: color, boxShadow: s.status === 'ok' ? `0 0 6px ${color}` : undefined }} />
        {s.status === 'ok' ? 'on' : s.status}
      </span>
    </li>
  );
}

function LinkLegend() {
  const row = (label: string, color: string, dash?: string, width = 2) => (
    <li className="flex items-center gap-2">
      <svg width="34" height="8" aria-hidden="true">
        <line x1="2" y1="4" x2="32" y2="4" stroke={color} strokeWidth={width} strokeDasharray={dash} strokeLinecap="round" />
      </svg>
      {label}
    </li>
  );
  return (
    <div className="grid grid-cols-1 gap-x-4 gap-y-1.5 text-[11px] text-slate-400 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
      <ul className="space-y-1.5">
        {row('Backhaul (cable)', WIRED, undefined, 3)}
        {row('Backhaul (wireless)', C.violet, '7 5', 2.5)}
        {row('Cable', WIRED)}
        {row('Cable (inferred)', WIRED, '2 4')}
      </ul>
      <ul className="space-y-1.5">
        {row('Wi-Fi 2.4 GHz', C.amber, '4 4')}
        {row('Wi-Fi 5 GHz', C.sky, '4 4')}
        {row('VPN (WireGuard)', C.amber, '1 5')}
        {row('Link unknown', C.slate, '1 5')}
      </ul>
    </div>
  );
}

/* ------------------------------------------------------------------ detail */

function DeviceDetail({
  d,
  node,
  nodeById,
  onClose,
  onAsk,
}: {
  d: MapDevice | null;
  node: MapNode | null;
  nodeById: Map<string, MapNode>;
  onClose: () => void;
  onAsk: (q: string) => void;
}) {
  if (!d && !node) return null;
  const rows: [string, ReactNode][] = [];
  let title = '';
  let subtitle = '';
  let question = '';
  if (d) {
    const via = d.link?.to ? nodeById.get(d.link.to) : null;
    title = d.name;
    subtitle = [TYPE_LABEL[d.type] ?? d.type, d.brand ? (BRAND_NAME[d.brand] ?? d.brand) : null].filter(Boolean).join(' · ');
    rows.push(['IP', <span key="ip" className="font-mono">{d.ip ?? '—'}</span>]);
    if (d.mac) rows.push(['MAC', <span key="mac" className="font-mono">{d.mac}</span>]);
    if (d.vendor) rows.push(['Vendor', d.vendor]);
    if (d.host && d.host !== d.name) rows.push(['Hostname', <span key="host" className="font-mono">{d.host}</span>]);
    rows.push(['Network', <span key="net" style={{ color: NET_COLOR[d.network] ?? undefined }}>{d.network}</span>]);
    rows.push(['Room', `${d.room}${d.room_guessed ? ' (guessed)' : ''}`]);
    if (d.link) {
      const where = via ? `${via.model} (${via.room})` : 'the router';
      rows.push([
        'Connection',
        d.link.kind === 'wifi'
          ? `Wi-Fi ${BAND_LABEL[d.link.band ?? ''] ?? ''} via ${where}${d.link.rssi != null ? `, ${d.link.rssi} dBm` : ''}`
          : d.link.kind === 'wired'
            ? `Cable behind ${where}${d.link.inferred ? ' (inferred: same host as its other VMs)' : ''}`
            : d.link.kind === 'vpn'
              ? `WireGuard VPN${d.last_handshake_s != null ? `, handshake ${d.last_handshake_s} s ago` : ''}`
              : 'Online (answers ARP), but on no mesh node\'s client list',
      ]);
    } else {
      rows.push(['Status', d.last_seen ? `offline, last seen ${relTime(d.last_seen)}` : 'offline (DHCP lease only)']);
    }
    question = `Tell me about the device "${d.name}" (${[d.ip, d.mac].filter(Boolean).join(', ')}): how is it connected, is anything unusual in its DNS lookups or traffic?`;
  } else if (node) {
    const up = node.uplink?.to ? nodeById.get(node.uplink.to) : null;
    title = node.model;
    subtitle = node.is_main ? 'Main router' : 'AiMesh node';
    rows.push(['IP', <span key="ip" className="font-mono">{node.ip}</span>]);
    rows.push(['MAC', <span key="mac" className="font-mono">{node.mac}</span>]);
    rows.push(['Room', `${node.room}${node.room_guessed ? ' (guessed from its devices)' : ''}`]);
    rows.push(['Devices', String(node.clients)]);
    if (node.uplink) rows.push(['Backhaul', `${node.uplink.kind === 'wired' ? 'Cable' : 'Wireless'} to ${up ? up.model : 'the main router'}`]);
    question = `How is the AiMesh node ${node.model} (${node.ip}) doing? Check its clients, signal and backhaul.`;
  }
  const guessed = d ? d.room_guessed : node?.room_guessed;
  return (
    <div className="fixed inset-x-3 bottom-[calc(5rem+env(safe-area-inset-bottom))] z-40 max-h-[60vh] overflow-y-auto rounded-2xl border border-white/10 bg-ink-800/95 p-4 shadow-2xl backdrop-blur-xl xl:static xl:max-h-none xl:bg-ink-900/80 xl:shadow-none">
      <div className="mb-3 flex items-start gap-3">
        {d ? (
          <DeviceIcon d={d} size={44} />
        ) : (
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-sky-400 via-violet-500 to-pink-500">
            <RouterIcon size={20} className="text-white" />
          </div>
        )}
        <div className="min-w-0 flex-1">
          <div className="truncate text-[15px] font-semibold text-white">{title}</div>
          <div className="truncate text-xs text-slate-400">{subtitle}</div>
        </div>
        <button onClick={onClose} className="rounded-lg p-1 text-slate-400 hover:bg-white/[0.06] hover:text-white" aria-label="Close">
          <X size={16} />
        </button>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-[12px]">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-slate-500">{k}</dt>
            <dd className="min-w-0 break-words text-slate-200">{v}</dd>
          </div>
        ))}
      </dl>
      {guessed && (
        <p className="mt-3 rounded-lg bg-white/[0.03] px-2.5 py-2 text-[11px] leading-snug text-slate-400">
          Room guessed. Pin it in <span className="font-mono text-slate-300">config.yml</span> under{' '}
          <span className="font-mono text-slate-300">network_map: rooms:</span> (by name, IP or MAC).
        </p>
      )}
      <button
        onClick={() => onAsk(question)}
        className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-white/[0.05] px-2.5 py-1.5 text-xs font-medium text-slate-200 ring-1 ring-white/10 transition hover:bg-white/[0.09]"
      >
        <MessageSquare size={13} /> Ask Tshoot
      </button>
    </div>
  );
}

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

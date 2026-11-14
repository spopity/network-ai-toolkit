import { Cable, CircleDot, KeyRound, Router as RouterIcon } from 'lucide-react';
import { C } from '../components/ui';
import { relTime } from '../lib/format';
import { NET_COLOR } from '../monitor/DnsCard';
import { BrandLogo, hasLogo, TYPE_ICON } from './icons';
import type { MapDevice, MapLink, MapNode } from './types';

export const BAND_COLOR: Record<string, string> = { '2g': C.amber, '5g': C.sky, '6g': C.violet };
export const BAND_LABEL: Record<string, string> = { '2g': '2.4 GHz', '5g': '5 GHz', '6g': '6 GHz' };
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
export function DeviceIcon({ d, size = 36, anchor = false }: { d: MapDevice; size?: number; anchor?: boolean }) {
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
export function DeviceChip({
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
export function NodeCard({
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

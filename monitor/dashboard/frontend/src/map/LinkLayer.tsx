import { C } from '../components/ui';
import type { MapLink } from './types';
import { BAND_COLOR } from './DeviceChip';

const WIRED = '#cbd5e1';
/* ------------------------------------------------------------------ links */

export interface Edge {
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
export type Pt = { x: number; y: number };
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
export function LinkLayer({ edges, pos, size, highlight }: { edges: Edge[]; pos: Record<string, Pt>; size: { w: number; h: number }; highlight: boolean }) {
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
export function LinkLegend() {
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

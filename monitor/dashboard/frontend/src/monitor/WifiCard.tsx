import { Router as RouterIcon, Wifi } from 'lucide-react';
import type { MeshNode, Snapshot, WifiClient } from '../types';
import { C, Card } from '../components/ui';
import { isRandomMac } from '../lib/format';
import { NOTHING } from './Briefing';
import { BandSplit } from './KpiGrid';

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
export function WifiCard({ snap, finding }: { snap: Snapshot; finding?: string }) {
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

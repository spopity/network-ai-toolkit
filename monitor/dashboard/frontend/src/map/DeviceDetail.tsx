import type { ReactNode } from 'react';
import { MessageSquare, Router as RouterIcon, X } from 'lucide-react';
import { relTime } from '../lib/format';
import { NET_COLOR } from '../monitor/DnsCard';
import { BRAND_NAME, TYPE_LABEL } from './icons';
import type { MapDevice, MapNode } from './types';
import { BAND_LABEL, DeviceIcon } from './DeviceChip';

/* ------------------------------------------------------------------ detail */

export function DeviceDetail({
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

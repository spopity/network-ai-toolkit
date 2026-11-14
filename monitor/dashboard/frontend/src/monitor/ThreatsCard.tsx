import { ShieldAlert, ShieldCheck } from 'lucide-react';
import type { Snapshot } from '../types';
import { C, Card, Pill } from '../components/ui';
import { compact } from '../lib/format';

/* ------------------------------------------------------------------ threats */

export function ThreatsCard({ snap }: { snap: Snapshot }) {
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

import { CircleDot } from 'lucide-react';
import { C } from '../components/ui';
import { BrandLogo, hasLogo, SERVICE_ICON } from './icons';
import type { MapService, ServiceStatus } from './types';

const STATUS_COLOR: Record<ServiceStatus, string> = { ok: C.emerald, warn: C.amber, down: C.red, off: C.slate };
export function ServiceRow({ s }: { s: MapService }) {
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

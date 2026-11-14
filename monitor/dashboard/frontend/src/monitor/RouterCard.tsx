import { Router as RouterIcon, Thermometer, Zap } from 'lucide-react';
import type { Snapshot } from '../types';
import { C, Card, Meter } from '../components/ui';
import { duration } from '../lib/format';
import { MiniStat } from './ConnectionCard';

/* ------------------------------------------------------------------ router */

export function RouterCard({ snap }: { snap: Snapshot }) {
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

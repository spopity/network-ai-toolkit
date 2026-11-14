import { TrendingUp } from 'lucide-react';
import type { HistoryResponse } from '../types';
import { AreaChart, Legend } from '../components/AreaChart';
import { C, Card } from '../components/ui';

/* ------------------------------------------------------------------ trends */

export function TrendsCard({ history, className = '' }: { history: HistoryResponse | null; className?: string }) {
  const snaps = history?.snapshots ?? [];
  const clients = snaps.filter((s) => s.client_count != null);
  const mem = snaps.filter((s) => s.mem_used_pct != null);
  const fmt = (t: number) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });

  return (
    <Card title="Trends · 30 days" icon={<TrendingUp size={15} className="text-violet-400" />} className={className}>
      {!history?.available && <p className="mb-2 text-xs text-slate-500">History archive (Postgres) unreachable - showing live data only.</p>}
      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        <div>
          <div className="mb-1 flex items-center justify-between">
            <Legend items={[{ name: 'Wi-Fi clients', color: C.teal }]} />
          </div>
          <AreaChart
            x={clients.map((s) => new Date(s.collected_at).getTime())}
            series={[{ name: 'Clients', color: C.teal, values: clients.map((s) => s.client_count) }]}
            height={170}
            formatX={fmt}
            empty="Not enough history yet."
          />
        </div>
        <div>
          <div className="mb-1">
            <Legend items={[{ name: 'Memory used', color: C.amber }]} />
          </div>
          <AreaChart
            x={mem.map((s) => new Date(s.collected_at).getTime())}
            series={[{ name: 'Memory', color: C.amber, values: mem.map((s) => s.mem_used_pct), unit: '%' }]}
            yMax={100}
            height={170}
            formatX={fmt}
            empty="Not enough history yet."
          />
        </div>
      </div>
    </Card>
  );
}

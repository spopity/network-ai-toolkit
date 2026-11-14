import type { DashboardState, HistoryResponse } from '../types';
import { Pill, Skeleton } from '../components/ui';
import { DnsCard } from './DnsCard';
import { TrafficCard } from './TrafficCard';
import { Briefing } from './Briefing';
import { ConnectionCard } from './ConnectionCard';
import { EventsCard } from './EventsCard';
import { ReportCard } from './ReportCard';
import { KpiGrid } from './KpiGrid';
import { RouterCard } from './RouterCard';
import { ThreatsCard } from './ThreatsCard';
import { TrendsCard } from './TrendsCard';
import { UptimeCard } from './UptimeCard';
import { WifiCard } from './WifiCard';

interface Props {
  data: DashboardState | null;
  history: HistoryResponse | null;
  error: string | null;
  collecting: boolean;
  onCollect: () => void;
  onAsk: (question: string) => void;
}
export function MonitorView({ data, history, error, collecting, onCollect, onAsk }: Props) {
  const snap = data?.snapshot ?? null;

  if (!snap) {
    return (
      <div className="mx-auto max-w-[1400px] space-y-4 p-4 lg:p-6">
        {error && <Pill tone="high">Dashboard API unreachable: {error}</Pill>}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 2xl:grid-cols-6">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-[118px]" />
          ))}
        </div>
        <Skeleton className="h-[200px]" />
        <Skeleton className="h-[300px]" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1400px] space-y-4 p-4 pb-28 lg:p-6 lg:pb-8">
      <KpiGrid data={data!} snap={snap} />
      <Briefing data={data!} snap={snap} collecting={collecting} onCollect={onCollect} onAsk={onAsk} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ConnectionCard className="lg:col-span-2" snap={snap} />
        <UptimeCard data={data!} snap={snap} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ThreatsCard snap={snap} />
        <WifiCard snap={snap} finding={data?.analysis?.sections?.wifi} />
        <RouterCard snap={snap} />
      </div>
      <TrafficCard onAsk={onAsk} />
      <DnsCard onAsk={onAsk} health={snap?.dns_health} />
      <ReportCard onAsk={onAsk} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 lg:items-start">
        <TrendsCard className="lg:col-span-2" history={history} />
        <EventsCard data={data!} history={history} />
      </div>
    </div>
  );
}

import { useState } from 'react';
import { ArrowDownRight, CheckCircle2, Globe, History, KeyRound, Lock, LockOpen, Power, RefreshCw, Router as RouterIcon, ShieldAlert, ShieldCheck, Wrench } from 'lucide-react';
import type { DashboardState, HistoryResponse, WatchdogEvent } from '../types';
import { Card, TONE, type Tone } from '../components/ui';
import { dayClock, duration, relTime } from '../lib/format';

/* ------------------------------------------------------------------ events */

type Ev = WatchdogEvent & { detail?: Record<string, unknown> };
function describe(e: Ev): { label: string; sub?: string; tone: Tone; icon: typeof Power } {
  const d = { ...(e.detail ?? {}), ...e } as Record<string, unknown>;
  switch (e.event) {
    case 'down_detected':
      return { label: 'Internet outage detected', tone: 'high', icon: ArrowDownRight };
    case 'recovered':
      return { label: 'Connection restored', sub: `down for ${duration(Number(d.downtime_seconds))}`, tone: 'ok', icon: CheckCircle2 };
    case 'restart_triggered':
      return { label: 'Watchdog restarted WAN', tone: 'caution', icon: RefreshCw };
    case 'restart_result':
      return { label: d.ok ? 'WAN restart succeeded' : 'WAN restart failed', tone: d.ok ? 'ok' : 'high', icon: Power };
    default:
      if (e.event.startsWith('dns_')) {
        const st = e.event.slice('dns_'.length);
        const problems = Array.isArray(d.problems) ? (d.problems as string[]) : [];
        if (st === 'ok')
          return { label: 'DNS filtering restored', sub: d.previous ? `was ${String(d.previous)}` : undefined, tone: 'ok', icon: ShieldCheck };
        return {
          label: st === 'down' ? 'DNS not answering' : 'DNS unfiltered (AdGuardHome not serving)',
          sub: problems[0],
          tone: st === 'down' ? 'high' : 'caution',
          icon: ShieldAlert,
        };
      }
      if (e.event === 'anomaly')
        return { label: `Unusual activity: ${String(d.device ?? d.mac)}`, sub: d.summary ? String(d.summary) : undefined, tone: 'caution', icon: ShieldAlert };
      if (e.event === 'monitor_problem')
        return { label: `Monitoring: ${String(d.title ?? d.check)} problem`, sub: d.problem ? String(d.problem) : undefined, tone: 'high', icon: ShieldAlert };
      if (e.event === 'monitor_ok')
        return { label: `Monitoring: ${String(d.title ?? d.check)} OK again`, tone: 'ok', icon: CheckCircle2 };
      if (e.event === 'remedy') {
        const how = d.trigger === 'auto' ? 'automatic' : d.trigger === 'telegram' ? `from Telegram${d.by ? ` (${String(d.by)})` : ''}` : String(d.trigger ?? '');
        return { label: `${d.ok ? 'Fixed' : 'Fix failed'}: ${String(d.title ?? d.fix)}`, sub: [how, d.ok ? undefined : d.detail].filter(Boolean).join(' · ') || undefined, tone: d.ok ? 'ok' : 'high', icon: Wrench };
      }
      if (e.event === 'iot_lan') {
        const targets = Array.isArray(d.targets) ? (d.targets as string[]) : [];
        return { label: `IoT device ${String(d.device ?? d.ip)} tried to reach the LAN`, sub: targets.join(', ') || undefined, tone: 'caution', icon: ShieldAlert };
      }
      if (e.event === 'upnp_new_device') {
        const ports = Array.isArray(d.ports) ? (d.ports as string[]) : [];
        return { label: `${String(d.device ?? d.ip)} opened a port to the internet`, sub: ports.join(', ') || undefined, tone: 'caution', icon: ShieldAlert };
      }
      if (e.event === 'vpn_new_peer')
        return { label: `VPN peer added: ${String(d.peer)}`, sub: d.addr ? String(d.addr) : undefined, tone: 'caution', icon: KeyRound };
      if (e.event === 'vpn_connect') {
        const where = [d.as_org, d.country].filter(Boolean).map(String).join(', ');
        const sub = [d.endpoint, where].filter(Boolean).map(String).join(' · ') || undefined;
        if (d.new_network)
          return { label: `VPN: ${String(d.peer)} ${d.roamed ? 'moved to' : 'connected from'} a new network`, sub, tone: 'caution', icon: ShieldAlert };
        return { label: `VPN: ${String(d.peer)} connected`, sub, tone: 'info', icon: LockOpen };
      }
      if (e.event === 'vpn_disconnect')
        return { label: `VPN: ${String(d.peer)} disconnected`, sub: `after ${duration(Number(d.duration_s ?? 0))}`, tone: 'neutral', icon: Lock };
      if (e.event === 'ddns_mismatch')
        return { label: `DDNS out of date: ${String(d.host)}`, sub: `WAN IP ${String(d.wan_ip)}`, tone: 'high', icon: Globe };
      if (e.event === 'ddns_ok')
        return { label: `DDNS OK again: ${String(d.host)}`, sub: d.ip ? String(d.ip) : undefined, tone: 'ok', icon: Globe };
      if (e.event === 'router_firmware_available')
        return { label: `New firmware available: ${String(d.new)}`, sub: d.current ? `installed ${String(d.current)}` : undefined, tone: 'info', icon: RouterIcon };
      if (e.event.startsWith('router_wan_')) {
        const kind = e.event.slice('router_wan_'.length);
        const tone: Tone = kind === 'connected' ? 'ok' : kind === 'disconnected' || kind === 'stopped' ? 'high' : 'info';
        return { label: `Router: WAN ${kind}`, sub: d.ip ? `IP ${String(d.ip)}` : undefined, tone, icon: RouterIcon };
      }
      return { label: e.event.replace(/_/g, ' '), tone: 'neutral', icon: History };
  }
}
export function EventsCard({ data, history }: { data: DashboardState; history: HistoryResponse | null }) {
  const [all, setAll] = useState(false);
  const events: Ev[] = (history?.available && history.watchdog_events.length ? history.watchdog_events : data.watchdog_events) as Ev[];
  const shown = all ? events.slice(0, 60) : events.slice(0, 6);

  return (
    <Card
      title="Events"
      icon={<History size={15} className="text-sky-400" />}
      action={
        events.length > 6 && (
          <button onClick={() => setAll((a) => !a)} className="text-[11px] font-medium text-sky-300 hover:text-sky-200">
            {all ? 'Show less' : `Show all ${events.length}`}
          </button>
        )
      }
    >
      {events.length === 0 ? (
        <p className="text-sm text-slate-500">No connectivity events - smooth sailing.</p>
      ) : (
        <ol className={`relative space-y-3 ${all ? 'max-h-[520px] overflow-y-auto pr-1' : ''}`}>
          <span className="absolute bottom-1 left-[11px] top-1 w-px bg-white/[0.06]" />
          {shown.map((e, i) => {
            const d = describe(e);
            const t = TONE[d.tone];
            return (
              <li key={`${e.ts}-${i}`} className="relative flex gap-3">
                <span className={`relative z-[1] mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full ring-1 ${t.bg} ${t.ring}`}>
                  <d.icon size={12} className={t.text} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="truncate text-[13px] font-medium text-slate-200">{d.label}</span>
                    <span className="shrink-0 text-[11px] tabular-nums text-slate-500" title={e.ts}>
                      {relTime(e.ts)}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {dayClock(e.ts)}
                    {d.sub ? ` · ${d.sub}` : ''}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}

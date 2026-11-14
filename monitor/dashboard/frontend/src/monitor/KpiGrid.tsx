import { Activity, Cpu, Gauge, Globe, ShieldAlert, ShieldCheck, Wifi, WifiOff } from 'lucide-react';
import type { DashboardState, Snapshot } from '../types';
import { C, Meter, StatTile } from '../components/ui';
import { compact, duration, relTime } from '../lib/format';

/* ------------------------------------------------------------------ KPI tiles */

export function KpiGrid({ data, snap }: { data: DashboardState; snap: Snapshot }) {
  const wd = data.watchdog ?? {};
  const cm = snap.wan.connmon;
  const st = snap.wan.speedtest;
  const fd = snap.security.firewall_drops;
  const sys = snap.system;
  const memPct = sys.mem_total_kb ? Math.round(100 * (1 - (sys.mem_available_kb || sys.mem_free_kb) / sys.mem_total_kb)) : null;
  const outages = (snap.wan as { watchdog_24h?: { outages: number } }).watchdog_24h?.outages ?? 0;
  const banned = fd?.skynet_banned ? Object.values(fd.skynet_banned).reduce((a, b) => a + b, 0) : null;
  const outbound = fd?.outbound?.total ?? 0;
  const online = wd.up !== false;

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 2xl:grid-cols-6">
      <StatTile
        label="Internet"
        value={online ? 'Online' : 'Offline'}
        accent={online ? C.emerald : C.red}
        icon={online ? <Globe size={16} /> : <WifiOff size={16} />}
        sub={
          <>
            <span className={outages ? 'text-amber-300' : 'text-emerald-400'}>
              {outages ? `${outages} drop${outages > 1 ? 's' : ''}` : 'no drops'}
            </span>{' '}
            in 24 h · {snap.wan.proto?.toUpperCase()}
          </>
        }
      />
      <StatTile
        label="Latency"
        value={cm?.ping_ms_avg != null ? cm.ping_ms_avg.toFixed(1) : '—'}
        unit="ms"
        accent={C.sky}
        icon={<Activity size={16} />}
        sub={
          cm ? (
            <>
              jitter {cm.jitter_ms_avg ?? '—'} ms ·{' '}
              <span className={cm.tests_with_loss_24h ? 'text-amber-300' : 'text-emerald-400'}>
                {cm.tests_with_loss_24h ? `${cm.tests_with_loss_24h} lossy tests` : '0% loss'}
              </span>
            </>
          ) : (
            'connmon not reporting'
          )
        }
      />
      <StatTile
        label="Speed"
        value={st?.download_mbps != null ? Math.round(st.download_mbps) : '—'}
        unit="Mbps ↓"
        accent={C.violet}
        icon={<Gauge size={16} />}
        sub={st ? `↑ ${Math.round(st.upload_mbps ?? 0)} Mbps · ${relTime(st.last_at)}` : 'no speedtest yet'}
      />
      <StatTile
        label="Wi-Fi"
        value={snap.wifi.client_count}
        unit={snap.wifi.client_count === 1 ? 'device' : 'devices'}
        accent={C.teal}
        icon={<Wifi size={16} />}
        sub={`2.4 GHz ${snap.wifi.clients_2g.length} · 5 GHz ${snap.wifi.clients_5g.length}${
          snap.wifi.nodes?.length ? ` · ${snap.wifi.nodes.length} nodes` : ''
        }`}
      >
        <BandSplit a={snap.wifi.clients_2g.length} b={snap.wifi.clients_5g.length} />
      </StatTile>
      <StatTile
        label="Threats"
        value={compact(fd?.total ?? 0)}
        unit="blocked"
        accent={outbound ? C.red : C.pink}
        icon={outbound ? <ShieldAlert size={16} /> : <ShieldCheck size={16} />}
        sub={
          outbound ? (
            <span className="text-red-300">{outbound} outbound to blocklisted IPs!</span>
          ) : (
            `${fd?.unique_sources ?? 0} sources · ${banned ? compact(banned) : '—'} IPs banned`
          )
        }
      />
      <StatTile
        label="Router"
        value={sys.temps_c?.cpu != null ? Math.round(sys.temps_c.cpu) : '—'}
        unit="°C CPU"
        accent={C.amber}
        icon={<Cpu size={16} />}
        sub={`mem ${memPct ?? '—'}% · up ${duration(sys.uptime_seconds)}`}
      >
        <Meter pct={memPct ?? 0} from={C.amber} to={C.orange} className="mt-2.5" />
      </StatTile>
    </div>
  );
}
export function BandSplit({ a, b }: { a: number; b: number }) {
  const total = a + b;
  if (!total) return <div className="mt-2.5 h-1.5 rounded-full bg-white/[0.06]" />;
  return (
    <div className="mt-2.5 flex h-1.5 gap-0.5 overflow-hidden rounded-full">
      {a > 0 && <div style={{ flex: a, background: C.teal }} />}
      {b > 0 && <div style={{ flex: b, background: C.sky }} />}
    </div>
  );
}

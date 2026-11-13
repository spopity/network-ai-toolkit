import { useMemo, useState } from "react";
import {
  Ban,
  Globe,
  MessageSquare,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { C, Card, Meter, Segmented, Skeleton } from "../components/ui";
import type { DnsHealth } from "../types";
import { useJson } from "../hooks/useJson";
import { compact, relTime } from "../lib/format";

/** Per-device DNS lookups from the AdGuardHome archive (/api/dns/*). */

interface DnsDevice {
  device_key: string;
  device: string;
  network: string;
  client_ip: string | null;
  mac: string | null;
  queries: number;
  blocked: number;
  domains: number;
  new_domains: number;
  last_seen: string;
}

interface DnsLookup {
  device_key: string;
  device: string;
  network: string;
  domain: string;
  count: number;
  blocked: number;
  rule: string | null;
  last_seen: string;
  new: boolean | null;
}

export const NET_COLOR: Record<string, string> = {
  LAN: C.sky,
  IoT: C.teal,
  Guest: C.violet,
  VPN: C.amber,
  Router: C.slate,
  Other: C.orange,
};
export const NET_ORDER = ["LAN", "IoT", "Guest", "VPN", "Router", "Other"];

type Filter = "all" | "blocked" | "new";

export function NetDot({ net }: { net: string }) {
  return (
    <span
      className="inline-block h-2 w-2 shrink-0 rounded-full"
      style={{ background: NET_COLOR[net] ?? C.slate }}
    />
  );
}

export function DnsCard({
  onAsk,
  health,
}: {
  onAsk: (q: string) => void;
  health?: DnsHealth;
}) {
  const [hours, setHours] = useState(24);
  const [net, setNet] = useState<string>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");

  const { data: devData, error } = useJson<{ devices: DnsDevice[] }>(
    `/api/dns/devices?hours=${hours}`,
  );
  const all = useMemo(() => devData?.devices ?? [], [devData]);
  const nets = useMemo(() => {
    const m = new Map<
      string,
      { queries: number; blocked: number; devices: number }
    >();
    for (const d of all) {
      const n = m.get(d.network) ?? { queries: 0, blocked: 0, devices: 0 };
      n.queries += d.queries;
      n.blocked += d.blocked;
      n.devices += 1;
      m.set(d.network, n);
    }
    return NET_ORDER.filter((k) => m.has(k)).map((k) => ({
      net: k,
      ...m.get(k)!,
    }));
  }, [all]);
  const devices = net === "all" ? all : all.filter((d) => d.network === net);
  const total = all.reduce((s, d) => s + d.queries, 0);
  const blocked = all.reduce((s, d) => s + d.blocked, 0);
  const fresh = all.reduce((s, d) => s + d.new_domains, 0);
  const maxQ = Math.max(1, ...devices.map((d) => d.queries));

  // keep a valid selection: default to the busiest device in view
  const current =
    devices.find((d) => d.device_key === selected) ?? devices[0] ?? null;

  const lookupUrl = current
    ? `/api/dns/lookups?hours=${hours}&device=${encodeURIComponent(current.device_key)}&limit=500` +
      (filter === "blocked" ? "&blocked=1" : filter === "new" ? "&new=1" : "")
    : null;
  const { data: lkData } = useJson<{ lookups: DnsLookup[] }>(lookupUrl);
  const lookups = (lkData?.lookups ?? []).filter(
    (l) =>
      l.device_key === current?.device_key &&
      (!query || l.domain.includes(query.toLowerCase())),
  );
  const maxL = Math.max(1, ...lookups.map((l) => l.count));

  return (
    <Card
      title="DNS lookups"
      icon={<Globe size={15} className="text-sky-400" />}
      action={
        <div className="flex items-center gap-2">
          <HealthPill health={health} />
          <Segmented
            options={[
              { label: "1h", value: 1 },
              { label: "24h", value: 24 },
              { label: "7d", value: 168 },
            ]}
            value={hours}
            onChange={setHours}
          />
        </div>
      }
    >
      {health && health.state !== "ok" && (
        <div
          className={`mb-3 flex items-start gap-2 rounded-xl px-3 py-2 text-xs ring-1 ${health.state === "down" ? "bg-red-500/10 text-red-200 ring-red-500/30" : "bg-amber-500/10 text-amber-100 ring-amber-500/30"}`}
        >
          <ShieldAlert size={14} className="mt-0.5 shrink-0" />
          <div className="min-w-0">
            <div className="font-semibold">
              {health.state === "down"
                ? "The router is not answering DNS"
                : "DNS is working but NOT filtered"}
              {health.since && (
                <span className="font-normal opacity-70">
                  {" "}
                  · since {relTime(health.since)}
                </span>
              )}
            </div>
            <ul className="mt-0.5 space-y-0.5 opacity-80">
              {health.problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
      {error && !all.length ? (
        <p className="text-xs text-slate-500">
          DNS archive unavailable: {error}
        </p>
      ) : !devData ? (
        <div className="grid gap-3 lg:grid-cols-5">
          <Skeleton className="h-64 lg:col-span-2" />
          <Skeleton className="h-64 lg:col-span-3" />
        </div>
      ) : (
        <>
          {/* totals + per-network filter */}
          <div className="grid grid-cols-3 gap-2">
            <Stat label="Lookups" value={compact(total)} accent={C.sky} />
            <Stat
              label="Blocked"
              value={compact(blocked)}
              sub={
                total ? `${((100 * blocked) / total).toFixed(1)}%` : undefined
              }
              accent={C.rose}
            />
            <Stat
              label="New"
              value={String(fresh)}
              sub="first-ever domains"
              accent={C.amber}
            />
          </div>

          <div className="mt-3 flex flex-wrap gap-1.5">
            <NetChip
              active={net === "all"}
              onClick={() => setNet("all")}
              label="All"
              count={all.length}
            />
            {nets.map((n) => (
              <NetChip
                key={n.net}
                active={net === n.net}
                onClick={() => setNet(n.net)}
                label={n.net}
                count={n.devices}
                color={NET_COLOR[n.net]}
              />
            ))}
          </div>

          <div className="mt-3 grid min-w-0 gap-3 lg:grid-cols-5">
            {/* device list */}
            <ul className="max-h-[17rem] min-w-0 space-y-1 overflow-y-auto pr-1 lg:col-span-2 lg:max-h-[26rem]">
              {devices.length === 0 && (
                <li className="text-xs text-slate-500">
                  No lookups in this window.
                </li>
              )}
              {devices.map((d) => {
                const active = d.device_key === current?.device_key;
                return (
                  <li key={d.device_key}>
                    <button
                      onClick={() => setSelected(d.device_key)}
                      className={`w-full rounded-lg px-2.5 py-1.5 text-left ring-1 transition ${
                        active
                          ? "bg-sky-500/10 ring-sky-500/30"
                          : "bg-white/[0.02] ring-white/[0.04] hover:bg-white/[0.05]"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex min-w-0 items-center gap-1.5">
                          <NetDot net={d.network} />
                          <span
                            className={`truncate text-[12.5px] ${d.device.startsWith("unnamed") ? "italic text-slate-300" : "font-medium text-slate-100"}`}
                          >
                            {d.device}
                          </span>
                        </span>
                        <span className="flex shrink-0 items-center gap-1.5 text-[11px] tabular-nums">
                          {d.new_domains > 0 && (
                            <span
                              className="rounded bg-amber-500/15 px-1.5 text-[10px] font-semibold text-amber-300"
                              title="Domains looked up for the first time"
                            >
                              {d.new_domains} new
                            </span>
                          )}
                          {d.blocked > 0 && (
                            <span
                              className="text-rose-300"
                              title="Blocked lookups"
                            >
                              {compact(d.blocked)}⊘
                            </span>
                          )}
                          <span className="text-slate-200">
                            {compact(d.queries)}
                          </span>
                        </span>
                      </div>
                      <div className="mt-1 flex items-center gap-2">
                        <Meter
                          pct={(100 * d.queries) / maxQ}
                          from={NET_COLOR[d.network] ?? C.slate}
                          className="flex-1"
                        />
                        <span className="shrink-0 text-[10px] text-slate-500">
                          {d.domains} domain{d.domains === 1 ? "" : "s"}
                        </span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>

            {/* selected device's domains */}
            <div className="min-w-0 rounded-xl border border-white/[0.05] bg-white/[0.02] p-3 lg:col-span-3">
              {current ? (
                <>
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <NetDot net={current.network} />
                        <span className="truncate text-[14px] font-semibold text-white">
                          {current.device}
                        </span>
                      </div>
                      <div className="mt-0.5 truncate text-[10.5px] text-slate-500">
                        {[
                          current.network,
                          current.client_ip,
                          current.mac,
                          `last lookup ${relTime(current.last_seen)}`,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                      </div>
                    </div>
                    <button
                      onClick={() =>
                        onAsk(
                          `What has ${current.device} (${current.network}, ${current.client_ip}) been looking up in DNS over the last ${hours === 168 ? "7 days" : `${hours}h`}? Anything unusual, new or blocked?`,
                        )
                      }
                      className="flex shrink-0 items-center gap-1.5 rounded-lg bg-white/[0.04] px-2.5 py-1 text-[11px] font-medium text-slate-300 ring-1 ring-white/10 transition hover:bg-white/[0.08] hover:text-white"
                    >
                      <MessageSquare size={12} /> Ask Tshoot
                    </button>
                  </div>

                  <div className="mt-2.5 flex flex-wrap items-center gap-2">
                    <Segmented
                      options={[
                        { label: "All", value: "all" as Filter },
                        {
                          label: (
                            <span className="flex items-center gap-1">
                              <Ban size={11} />
                              Blocked
                            </span>
                          ),
                          value: "blocked" as Filter,
                        },
                        {
                          label: (
                            <span className="flex items-center gap-1">
                              <Sparkles size={11} />
                              New
                            </span>
                          ),
                          value: "new" as Filter,
                        },
                      ]}
                      value={filter}
                      onChange={setFilter}
                    />
                    <label className="flex min-w-0 flex-1 items-center gap-1.5 rounded-lg bg-white/[0.04] px-2 py-1 ring-1 ring-white/[0.06]">
                      <Search size={12} className="shrink-0 text-slate-500" />
                      <input
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Filter domains"
                        className="w-full min-w-0 bg-transparent text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none"
                      />
                    </label>
                  </div>

                  <ul className="mt-2.5 max-h-[19rem] space-y-1 overflow-y-auto pr-1">
                    {!lkData &&
                      Array.from({ length: 4 }, (_, i) => (
                        <Skeleton key={i} className="h-7" />
                      ))}
                    {lkData && lookups.length === 0 && (
                      <li className="py-6 text-center text-xs text-slate-500">
                        {filter === "new"
                          ? "No first-time domains in this window."
                          : filter === "blocked"
                            ? "Nothing blocked in this window."
                            : "No lookups match."}
                      </li>
                    )}
                    {lookups.map((l) => (
                      <li
                        key={l.domain}
                        className="relative overflow-hidden rounded-md px-2 py-1"
                      >
                        <div
                          className="absolute inset-y-0 left-0 rounded-md opacity-[0.12]"
                          style={{
                            width: `${Math.max(2, (100 * l.count) / maxL)}%`,
                            background: l.blocked
                              ? C.rose
                              : (NET_COLOR[current.network] ?? C.sky),
                          }}
                        />
                        <div className="relative flex items-center justify-between gap-2">
                          <span
                            className={`min-w-0 truncate font-mono text-[11.5px] ${l.blocked ? "text-rose-300 line-through decoration-rose-400/40" : "text-slate-200"}`}
                            title={l.rule ? `Blocked by ${l.rule}` : l.domain}
                          >
                            {l.domain}
                          </span>
                          <span className="flex shrink-0 items-center gap-1.5 text-[10.5px] tabular-nums">
                            {l.new && (
                              <span className="rounded bg-amber-500/15 px-1.5 text-[10px] font-semibold text-amber-300">
                                NEW
                              </span>
                            )}
                            {l.blocked > 0 && (
                              <span className="rounded bg-rose-500/15 px-1.5 text-[10px] font-medium text-rose-300">
                                blocked
                              </span>
                            )}
                            <span className="hidden text-slate-500 sm:inline">
                              {relTime(l.last_seen)}
                            </span>
                            <span className="w-9 text-right text-slate-200">
                              {compact(l.count)}
                            </span>
                          </span>
                        </div>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="text-xs text-slate-500">Select a device.</p>
              )}
            </div>
          </div>
        </>
      )}
    </Card>
  );
}

export function Stat({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string;
  sub?: string;
  accent: string;
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
      <div
        className="absolute inset-x-0 top-0 h-0.5"
        style={{ background: `linear-gradient(90deg, ${accent}, transparent)` }}
      />
      <div className="text-[10.5px] font-medium uppercase tracking-wider text-slate-500">
        {label}
      </div>
      <div className="mt-0.5 flex items-baseline gap-1.5">
        <span className="text-[18px] font-semibold tabular-nums text-white">
          {value}
        </span>
        {sub && (
          <span className="truncate text-[10.5px] text-slate-500">{sub}</span>
        )}
      </div>
    </div>
  );
}

export function NetChip({
  active,
  onClick,
  label,
  count,
  color,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
  color?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11.5px] font-medium ring-1 transition ${
        active
          ? "bg-white/10 text-white ring-white/20"
          : "bg-white/[0.03] text-slate-400 ring-white/[0.06] hover:text-slate-200"
      }`}
    >
      {color && (
        <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      )}
      {label}
      <span className="text-slate-500">{count}</span>
    </button>
  );
}

function HealthPill({ health }: { health?: DnsHealth }) {
  if (!health) return null;
  const warn = health.state === "ok" && health.problems.length > 0; // e.g. supervisor missing
  const look =
    health.state === "down"
      ? { cls: "bg-red-500/10 text-red-300 ring-red-500/30", label: "DNS down" }
      : health.state === "unfiltered"
        ? {
            cls: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
            label: "Unfiltered",
          }
        : warn
          ? {
              cls: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
              label: "Filtering · check",
            }
          : {
              cls: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
              label: "Filtering",
            };
  const title = [
    `AdGuardHome ${health.agh_version ?? ""}`.trim(),
    `port 53: ${(health.owners_53 ?? []).join(", ") || "unknown"}`,
    health.probe_ms != null ? `answer ${health.probe_ms} ms` : null,
    `checked ${relTime(health.checked_at)}`,
    ...health.problems,
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <span
      title={title}
      className={`hidden items-center gap-1 rounded-lg px-2 py-1 text-[11px] font-medium ring-1 sm:flex ${look.cls}`}
    >
      {health.state === "ok" ? (
        <ShieldCheck size={12} />
      ) : (
        <ShieldAlert size={12} />
      )}
      {look.label}
    </span>
  );
}

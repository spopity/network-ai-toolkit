export interface SystemInfo {
  productid: string;
  firmver: string;
  buildno: string;
  extendno?: string;
  firmware_variant?: 'merlin' | 'stock';
  firmware?: string;
  jffs_scripts_enabled?: boolean;
  temps_c?: { cpu: number | null; radio_2g: number | null; radio_5g: number | null };
  uptime_seconds: number | null;
  mem_total_kb: number;
  mem_free_kb: number;
  mem_available_kb?: number;
  loadavg: string[];
}

export interface WanInfo {
  state: string;
  ip: string;
  proto: string;
  pppd_running: boolean;
  router_events_24h?: { ts: string; event: string; state?: string; ip?: string }[];
  watchdog_24h?: { outages: number; total_downtime_s: number; longest_s: number; auto_restarts: number } | null;
  connmon?: {
    tests_24h: number;
    ping_ms_avg: number | null;
    ping_ms_max: number | null;
    jitter_ms_avg: number | null;
    line_quality_min_pct: number | null;
    tests_with_loss_24h: number;
    ping_ms_avg_7d: number | null;
  } | null;
  speedtest?: {
    last_at: string | null;
    download_mbps: number | null;
    upload_mbps: number | null;
    latency_ms: number | null;
    server: string | null;
    download_mbps_avg_7d: number | null;
  } | null;
}

export interface FirewallDrops {
  total: number;
  window_start: string | null;
  window_end: string | null;
  unique_sources: number;
  top_ports: { port: string; count: number }[];
  top_sources: { ip: string; count: number }[];
  by_kind?: Record<string, number>;
  outbound?: {
    total: number;
    by_lan_device: { ip: string; count: number }[];
    top_destinations: { dest: string; count: number }[];
  };
  skynet_banned?: Record<string, number> | null;
}

export interface SecurityInfo {
  syslog_tail: string;
  security_log_tail: string;
  aae_log_tail: string;
  firewall_drops?: FirewallDrops;
  aiprotection_enabled: boolean;
  malware_block_enabled: boolean;
}

export interface MeshNode {
  mac: string;
  model: string;
  ip: string;
  is_main: boolean;
  clients_2g: number;
  clients_5g: number;
  clients_6g: number;
  client_count: number;
}

export interface WifiClient {
  mac: string;
  node: string | null;
  band: '2g' | '5g' | '6g';
  iface: string;
  ip: string | null;
  rssi: number | null;
  name?: string | null; // router-UI name, else networkmap's learned hostname
  vendor?: string | null;
}

export interface WifiInfo {
  ssid_2g: string;
  ssid_5g: string;
  clients_2g: string[];
  clients_5g: string[];
  clients_6g?: string[];
  client_count: number;
  new_clients?: string[] | null;
  // mesh-wide detail; absent in snapshots collected before AiMesh support
  clients?: WifiClient[];
  nodes?: MeshNode[];
}

export interface Snapshot {
  router: string;
  host: string;
  collected_at: string;
  system: SystemInfo;
  wan: WanInfo;
  security: SecurityInfo;
  wifi: WifiInfo;
}

export interface AnalysisSections {
  security?: string;
  wifi?: string;
  system?: string;
  overall?: string;
  unstructured?: boolean;
}

export interface Analysis {
  source: 'gemini' | 'ollama' | 'none';
  sections?: AnalysisSections;
  error?: string;
  // the analysis runs once a day; 5-minute checks carry it forward
  analyzed_at?: string;
  window?: [string, string];
}

export interface WatchdogHistoryPoint {
  ts: string;
  up: boolean;
}

export interface WatchdogStatus {
  up?: boolean;
  checked_at?: string;
  down_since?: string | null;
  last_restart_at?: string | null;
  history?: WatchdogHistoryPoint[];
}

export interface WatchdogEvent {
  ts: string;
  event: string;
  [key: string]: unknown;
}

export interface DashboardState {
  snapshot: Snapshot | null;
  analysis: Analysis | null;
  watchdog: WatchdogStatus;
  watchdog_events: WatchdogEvent[];
}

export interface SnapshotHistoryPoint {
  collected_at: string;
  client_count: number | null;
  mem_used_pct: number | null;
  uptime_seconds: number | null;
  wan_up: boolean | null;
  analysis_source: string | null;
}

export interface HistoryResponse {
  snapshots: SnapshotHistoryPoint[];
  watchdog_events: WatchdogEvent[];
  available: boolean;
  error?: string;
}

export interface CollectStatus {
  running: boolean;
  started_at: string | null;
  finished_at: string | null;
  last_result: 'ok' | 'error' | null;
}

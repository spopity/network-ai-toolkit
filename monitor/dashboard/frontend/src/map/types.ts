/** /api/network-map payload (router_agent/netmap.py build_map). */

export type LinkKind = 'wifi' | 'wired' | 'vpn' | 'seen';

export interface MapLink {
  to: string | null;
  kind: LinkKind;
  band?: '2g' | '5g' | '6g' | null;
  rssi?: number | null;
  inferred?: boolean;
}

export interface MapDevice {
  id: string;
  mac: string | null;
  ip: string | null;
  name: string;
  host: string | null;
  vendor: string | null;
  type: string;
  brand: string | null;
  network: string;
  room: string;
  room_guessed: boolean;
  online: boolean;
  link: MapLink | null;
  last_seen?: string | null;
  last_handshake_s?: number | null;
}

export interface MapNode {
  id: string;
  mac: string;
  ip: string;
  model: string;
  is_main: boolean;
  room: string;
  room_guessed: boolean;
  uplink: { to: string | null; kind: 'wired' | 'wireless' } | null;
  clients: number;
  brand: string;
}

export type ServiceStatus = 'ok' | 'warn' | 'down' | 'off';

export interface MapService {
  id: string;
  name: string;
  status: ServiceStatus;
  detail: string;
  brand: string | null;
}

export interface NetworkMapData {
  collected_at: string | null;
  generated_at: string;
  router: { name: string | null; firmware: string | null };
  wan: { ip: string | null; up: boolean; proto: string | null };
  rooms: string[];
  nodes: MapNode[];
  devices: MapDevice[];
  services: MapService[];
  has_topology: boolean;
}

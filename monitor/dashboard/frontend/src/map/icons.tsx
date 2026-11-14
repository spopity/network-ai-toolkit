import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  Bot,
  Cctv,
  CircleHelp,
  Clock,
  CookingPot,
  Cpu,
  Fan,
  Film,
  Flame,
  FolderOpen,
  Gauge,
  Globe,
  HardDrive,
  KeyRound,
  Laptop,
  Lightbulb,
  LockKeyhole,
  Monitor,
  MonitorSmartphone,
  Network,
  Plug,
  Radio,
  ScrollText,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Speaker,
  Sprout,
  Tablet,
  Terminal,
  Tv,
  Utensils,
  WashingMachine,
  Wind,
  Zap,
} from 'lucide-react';
import {
  siAdguard,
  siApple,
  siAsus,
  siBosch,
  siDenon,
  siEspressif,
  siGoogle,
  siIrobot,
  siLetsencrypt,
  siProxmox,
  siSamsung,
  siShelly,
  siSynology,
  siWireguard,
  siXiaomi,
} from 'simple-icons';

/** Device type (netmap.py classify_type) -> icon. */
export const TYPE_ICON: Record<string, LucideIcon> = {
  camera: Cctv,
  nas: HardDrive,
  server: Server,
  computer: Monitor,
  tv: Tv,
  display: MonitorSmartphone,
  speaker: Speaker,
  phone: Smartphone,
  tablet: Tablet,
  laptop: Laptop,
  dishwasher: Utensils,
  washer: WashingMachine,
  dryer: Wind,
  purifier: Fan,
  vacuum: Bot,
  heating: Flame,
  appliance: CookingPot,
  light: Lightbulb,
  plug: Plug,
  garden: Sprout,
  vpn: KeyRound,
  iot: Cpu,
  device: CircleHelp,
};

export const TYPE_LABEL: Record<string, string> = {
  camera: 'Camera',
  nas: 'NAS',
  server: 'Server / VM',
  computer: 'Computer',
  tv: 'TV',
  display: 'Smart display',
  speaker: 'Speaker',
  phone: 'Phone',
  tablet: 'Tablet',
  laptop: 'Laptop',
  dishwasher: 'Dishwasher',
  washer: 'Washer',
  dryer: 'Dryer',
  purifier: 'Air purifier',
  vacuum: 'Robot vacuum',
  heating: 'Heating',
  appliance: 'Appliance',
  light: 'Light',
  plug: 'Smart plug',
  garden: 'Garden',
  vpn: 'VPN client',
  iot: 'Smart device',
  device: 'Device',
};

/** Router service id (netmap.py _services) -> icon. */
export const SERVICE_ICON: Record<string, LucideIcon> = {
  wan: Globe,
  skynet: Shield,
  adguard: ShieldCheck,
  dnsmasq: Network,
  ntp: Clock,
  wireguard: KeyRound,
  aiprotection: ShieldAlert,
  qos: Gauge,
  connmon: Activity,
  spdmerlin: Zap,
  scribe: ScrollText,
  letsencrypt: LockKeyhole,
  ssh: Terminal,
  samba: FolderOpen,
  minidlna: Film,
  avahi: Radio,
};

interface SimpleIcon {
  title: string;
  hex: string;
  path: string;
}

/** Brand slug -> logo. Brands without a logo (Reolink, Tuya, Meross, ...) show the type icon only. */
const BRANDS: Record<string, SimpleIcon> = {
  apple: siApple,
  samsung: siSamsung,
  google: siGoogle,
  bosch: siBosch,
  xiaomi: siXiaomi,
  irobot: siIrobot,
  shelly: siShelly,
  denon: siDenon,
  synology: siSynology,
  proxmox: siProxmox,
  asus: siAsus,
  espressif: siEspressif,
  wireguard: siWireguard,
  adguard: siAdguard,
  letsencrypt: siLetsencrypt,
};

export const BRAND_NAME: Record<string, string> = {
  reolink: 'Reolink',
  tuya: 'Tuya',
  meross: 'Meross',
  viessmann: 'Viessmann',
  hisense: 'Hisense',
  gardena: 'Gardena',
  wiz: 'WiZ',
  ...Object.fromEntries(Object.entries(BRANDS).map(([k, v]) => [k, v.title])),
};

/** Brand colour, lifted when it would vanish on the dark surface (Apple/ASUS are #000). */
function brandColor(hex: string): string {
  const n = parseInt(hex, 16);
  const lum = (0.2126 * ((n >> 16) & 255) + 0.7152 * ((n >> 8) & 255) + 0.0722 * (n & 255)) / 255;
  return lum < 0.35 ? '#e2e8f0' : `#${hex}`;
}

export function hasLogo(brand: string | null | undefined): boolean {
  return Boolean(brand && BRANDS[brand]);
}

export function BrandLogo({ brand, size = 12, mono = false }: { brand: string | null | undefined; size?: number; mono?: boolean }) {
  const icon = brand ? BRANDS[brand] : undefined;
  if (!icon) return null;
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} role="img" aria-label={icon.title} className="shrink-0">
      <title>{icon.title}</title>
      <path d={icon.path} fill={mono ? 'currentColor' : brandColor(icon.hex)} />
    </svg>
  );
}

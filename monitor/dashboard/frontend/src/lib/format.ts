export function relTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return `${d} d ago`;
}

export function clock(iso: string | number | null | undefined): string {
  if (iso == null) return '—';
  const d = typeof iso === 'number' ? new Date(iso * 1000) : new Date(iso);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function dayClock(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
}

export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return '—';
  if (seconds < 90) return `${Math.round(seconds)} s`;
  const m = seconds / 60;
  if (m < 90) return `${Math.round(m)} min`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)} h`;
  return `${Math.round(h / 24)} d`;
}

export function compact(n: number | null | undefined): string {
  if (n == null) return '—';
  if (n >= 10_000) return `${(n / 1000).toFixed(n >= 100_000 ? 0 : 1)}k`;
  return n.toLocaleString();
}

export function today(): string {
  return new Date().toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
}

/** Locally-administered bit set -> randomized/private MAC (phones, laptops). */
export function isRandomMac(mac: string): boolean {
  return mac.length > 1 && '26AEae'.includes(mac[1]);
}

import type { ReactNode } from 'react';

/** Accent palette (same hues as the AI Coach app). */
export const C = {
  sky: '#38bdf8',
  pink: '#f472b6',
  amber: '#fbbf24',
  violet: '#a78bfa',
  rose: '#fb7185',
  teal: '#2dd4bf',
  emerald: '#34d399',
  orange: '#fb923c',
  slate: '#64748b',
  red: '#f87171',
  grid: 'rgba(148,163,184,0.10)',
  axis: '#64748b',
};

export type Tone = 'ok' | 'caution' | 'high' | 'info' | 'neutral';

export const TONE: Record<Tone, { color: string; bg: string; ring: string; text: string; dot: string; glow: string }> = {
  ok: { color: C.emerald, bg: 'bg-emerald-500/10', ring: 'ring-emerald-500/30', text: 'text-emerald-300', dot: 'bg-emerald-400', glow: 'from-emerald-400' },
  caution: { color: C.amber, bg: 'bg-amber-500/10', ring: 'ring-amber-500/30', text: 'text-amber-300', dot: 'bg-amber-400', glow: 'from-amber-400' },
  high: { color: C.red, bg: 'bg-red-500/10', ring: 'ring-red-500/30', text: 'text-red-300', dot: 'bg-red-400', glow: 'from-red-400' },
  info: { color: C.sky, bg: 'bg-sky-500/10', ring: 'ring-sky-500/30', text: 'text-sky-300', dot: 'bg-sky-400', glow: 'from-sky-400' },
  neutral: { color: C.slate, bg: 'bg-white/[0.04]', ring: 'ring-white/10', text: 'text-slate-300', dot: 'bg-slate-400', glow: 'from-slate-400' },
};

interface CardProps {
  title?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}

export function Card({ title, icon, action, className = '', children }: CardProps) {
  return (
    <section
      className={`animate-rise rounded-2xl border border-white/[0.06] bg-ink-900/80 p-3.5 shadow-[0_1px_0_rgba(255,255,255,0.03)_inset,0_10px_30px_-12px_rgba(0,0,0,0.6)] backdrop-blur sm:p-4 ${className}`}
    >
      {(title || action) && (
        <header className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-slate-400">
            {icon}
            {title}
          </h2>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

interface StatProps {
  label: string;
  value: ReactNode;
  unit?: string;
  sub?: ReactNode;
  accent: string;
  icon: ReactNode;
  children?: ReactNode;
}

export function StatTile({ label, value, unit, sub, accent, icon, children }: StatProps) {
  return (
    <div className="animate-rise relative overflow-hidden rounded-2xl border border-white/[0.06] bg-ink-900/80 p-4">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: `linear-gradient(90deg, ${accent}, transparent)` }} />
      <div className="pointer-events-none absolute -right-6 -top-6 h-20 w-20 rounded-full opacity-20 blur-2xl" style={{ background: accent }} />
      <div className="flex items-center justify-between text-[12px] font-medium uppercase tracking-wider text-slate-400">
        {label}
        <span style={{ color: accent }}>{icon}</span>
      </div>
      <div className="mt-2 flex items-baseline gap-1">
        <span className="truncate text-[28px] font-semibold leading-none tabular-nums text-white">{value}</span>
        {unit && <span className="text-sm text-slate-400">{unit}</span>}
      </div>
      {sub && <div className="mt-1.5 text-xs text-slate-400">{sub}</div>}
      {children}
    </div>
  );
}

export function Segmented<T extends string | number>({
  options,
  value,
  onChange,
}: {
  options: { label: ReactNode; value: T }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex rounded-lg bg-white/[0.04] p-0.5 text-xs">
      {options.map((o) => (
        <button
          key={String(o.value)}
          onClick={() => onChange(o.value)}
          className={`rounded-md px-2.5 py-1 font-medium transition ${
            o.value === value ? 'bg-white/10 text-white shadow' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-xl bg-white/[0.04] ${className}`} />;
}

export function Pill({ tone, children, dot = true }: { tone: Tone; children: ReactNode; dot?: boolean }) {
  const t = TONE[tone];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium ring-1 ${t.bg} ${t.ring} ${t.text}`}>
      {dot && <span className={`h-2 w-2 shrink-0 rounded-full ${t.dot}`} />}
      {children}
    </span>
  );
}

/** Thin progress bar with an accent gradient (like the coach's weekly-load bar). */
export function Meter({ pct, from, to, className = '' }: { pct: number; from: string; to?: string; className?: string }) {
  const w = Math.max(0, Math.min(100, pct));
  return (
    <div className={`h-1.5 overflow-hidden rounded-full bg-white/[0.06] ${className}`}>
      <div className="h-full rounded-full transition-[width] duration-700" style={{ width: `${w}%`, background: `linear-gradient(90deg, ${from}, ${to ?? from})` }} />
    </div>
  );
}

export function IconBadge({ children, gradient }: { children: ReactNode; gradient: string }) {
  return <div className={`rounded-xl bg-gradient-to-br p-1.5 shadow-lg ${gradient}`}>{children}</div>;
}

import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { C } from './ui';

export interface Series {
  name: string;
  color: string;
  values: (number | null)[];
  unit?: string;
  area?: boolean;
  /** draw on a second (right) axis scaled 0..max of this series */
  rightAxis?: boolean;
  bars?: boolean;
}

interface Props {
  x: number[]; // unix ms
  series: Series[];
  height?: number;
  yMin?: number;
  /** fixed top of the left axis (e.g. 100 for percentages) */
  yMax?: number;
  formatX?: (t: number) => string;
  formatY?: (v: number) => string;
  /** x positions (unix ms) to mark with a red dot on the baseline, e.g. packet loss */
  markers?: { t: number; label: string }[];
  empty?: string;
}

const PAD = { l: 38, r: 12, t: 10, b: 24 };

function smoothPath(pts: [number, number][]): string {
  if (pts.length === 0) return '';
  if (pts.length === 1) return `M${pts[0][0]},${pts[0][1]}`;
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] ?? pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] ?? p2;
    const t = 0.18; // Catmull-Rom tension -> cubic bezier
    const c1x = p1[0] + (p2[0] - p0[0]) * t;
    const c1y = p1[1] + (p2[1] - p0[1]) * t;
    const c2x = p2[0] - (p3[0] - p1[0]) * t;
    const c2y = p2[1] - (p3[1] - p1[1]) * t;
    d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / exp;
  const step = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((n) => f <= n) ?? 10;
  return step * exp;
}

export function AreaChart({ x, series, height = 200, yMin = 0, yMax, formatX, formatY, markers = [], empty = 'No data yet.' }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);
  const gid = useId().replace(/:/g, '');

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(200, e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const fx = formatX ?? ((t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  const fy = formatY ?? ((v: number) => (Math.abs(v) >= 100 ? v.toFixed(0) : v.toFixed(v % 1 ? 1 : 0)));

  const geo = useMemo(() => {
    if (x.length === 0) return null;
    const left = series.filter((s) => !s.rightAxis);
    const right = series.filter((s) => s.rightAxis);
    const maxOf = (ss: Series[]) => Math.max(0, ...ss.flatMap((s) => s.values.filter((v): v is number => v != null)));
    const yMaxL = yMax ?? niceMax(maxOf(left) * 1.12);
    const yMaxR = niceMax(maxOf(right) * 1.12);
    const t0 = x[0];
    const t1 = x[x.length - 1] === t0 ? t0 + 1 : x[x.length - 1];
    const iw = width - PAD.l - PAD.r;
    const ih = height - PAD.t - PAD.b;
    const px = (t: number) => PAD.l + ((t - t0) / (t1 - t0)) * iw;
    const pyL = (v: number) => PAD.t + ih - ((v - yMin) / (yMaxL - yMin)) * ih;
    const pyR = (v: number) => PAD.t + ih - (v / yMaxR) * ih;
    const paths = series.map((s) => {
      const py = s.rightAxis ? pyR : pyL;
      const pts: [number, number][] = [];
      s.values.forEach((v, i) => {
        if (v != null) pts.push([px(x[i]), py(v)]);
      });
      const line = smoothPath(pts);
      const area = pts.length > 1 ? `${line} L${pts[pts.length - 1][0].toFixed(1)},${PAD.t + ih} L${pts[0][0].toFixed(1)},${PAD.t + ih} Z` : '';
      return { s, pts, line, area, py };
    });
    const ticksY = [0, 0.25, 0.5, 0.75, 1].map((f) => yMin + f * (yMaxL - yMin));
    const nX = Math.max(2, Math.min(6, Math.floor(iw / 110)));
    const ticksX = Array.from({ length: nX }, (_, i) => t0 + ((t1 - t0) * i) / (nX - 1));
    return { px, pyL, paths, ticksY, ticksX, iw, ih, t0, t1, yMaxR, hasRight: right.length > 0 };
  }, [x, series, width, height, yMin, yMax]);

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    if (!geo) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    let best = 0;
    let bd = Infinity;
    x.forEach((t, i) => {
      const d = Math.abs(geo.px(t) - mx);
      if (d < bd) {
        bd = d;
        best = i;
      }
    });
    setHover(best);
  }

  return (
    <div ref={wrapRef} className="relative w-full">
      {!geo ? (
        <div className="flex items-center justify-center text-sm text-slate-500" style={{ height }}>
          {empty}
        </div>
      ) : (
        <>
          <svg width={width} height={height} onMouseMove={onMove} onMouseLeave={() => setHover(null)} className="block">
            <defs>
              {geo.paths.map(({ s }, i) => (
                <linearGradient key={i} id={`${gid}-g${i}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={s.color} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={s.color} stopOpacity={0} />
                </linearGradient>
              ))}
            </defs>
            {geo.ticksY.map((v, i) => (
              <g key={i}>
                <line x1={PAD.l} x2={width - PAD.r} y1={geo.pyL(v)} y2={geo.pyL(v)} stroke={C.grid} />
                <text x={PAD.l - 8} y={geo.pyL(v) + 3.5} textAnchor="end" fontSize={11} fill={C.axis}>
                  {fy(v)}
                </text>
              </g>
            ))}
            {geo.ticksX.map((t, i) => (
              <text
                key={i}
                x={geo.px(t)}
                y={height - 6}
                textAnchor={i === 0 ? 'start' : i === geo.ticksX.length - 1 ? 'end' : 'middle'}
                fontSize={11}
                fill={C.axis}
              >
                {fx(t)}
              </text>
            ))}
            {geo.paths.map(({ s, pts, area, line, py }, i) =>
              s.bars ? (
                pts.map(([bx, by], j) => (
                  <rect key={`${i}-${j}`} x={bx - 2} y={by} width={4} height={Math.max(0, py(0) - by)} rx={1.5} fill={s.color} opacity={0.35} />
                ))
              ) : (
                <g key={i}>
                  {s.area !== false && area && <path d={area} fill={`url(#${gid}-g${i})`} />}
                  <path d={line} fill="none" stroke={s.color} strokeWidth={2.25} strokeLinecap="round" strokeLinejoin="round" />
                  {pts.length === 1 && <circle cx={pts[0][0]} cy={pts[0][1]} r={3.5} fill={s.color} />}
                </g>
              ),
            )}
            {markers.map((m, i) => (
              <circle key={i} cx={geo.px(m.t)} cy={PAD.t + geo.ih} r={3.5} fill={C.red}>
                <title>{m.label}</title>
              </circle>
            ))}
            {hover != null && (
              <g>
                <line x1={geo.px(x[hover])} x2={geo.px(x[hover])} y1={PAD.t} y2={PAD.t + geo.ih} stroke="rgba(148,163,184,0.35)" strokeDasharray="3 3" />
                {geo.paths.map(({ s, py }, i) => {
                  const v = s.values[hover];
                  return v == null || s.bars ? null : (
                    <circle key={i} cx={geo.px(x[hover])} cy={py(v)} r={4} fill={s.color} stroke="#0b1020" strokeWidth={2} />
                  );
                })}
              </g>
            )}
          </svg>
          {hover != null && (
            <div
              className="pointer-events-none absolute top-0 z-10 min-w-[130px] rounded-lg border border-slate-400/20 bg-slate-900/95 px-2.5 py-1.5 text-xs text-slate-200 shadow-xl"
              style={{
                left: Math.min(Math.max(geo.px(x[hover]) + 12, 0), width - 150),
              }}
            >
              <div className="mb-1 text-[11px] text-slate-400">{fx(x[hover])}</div>
              {series.map((s) => (
                <div key={s.name} className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-sm" style={{ background: s.color }} />
                    {s.name}
                  </span>
                  <span className="font-semibold tabular-nums text-white">
                    {s.values[hover] == null ? '—' : `${fy(s.values[hover] as number)}${s.unit ?? ''}`}
                  </span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export function Legend({ items }: { items: { name: string; color: string }[] }) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-xs text-slate-300">
      {items.map((i) => (
        <span key={i.name} className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-[3px]" style={{ background: i.color }} />
          {i.name}
        </span>
      ))}
    </div>
  );
}

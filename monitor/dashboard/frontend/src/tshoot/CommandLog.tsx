import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, Loader2, Terminal } from 'lucide-react';
import type { CommandEntry } from './types';
import { Segmented } from '../components/ui';
import { clock } from '../lib/format';

const KIND: Record<CommandEntry['kind'], { label: string; className: string; prompt: string }> = {
  read: { label: 'read', className: 'bg-sky-500/10 text-sky-300 ring-sky-500/25', prompt: 'text-emerald-400' },
  write: { label: 'change', className: 'bg-amber-500/10 text-amber-300 ring-amber-500/25', prompt: 'text-amber-400' },
  blocked: { label: 'blocked', className: 'bg-rose-500/10 text-rose-300 ring-rose-500/25', prompt: 'text-rose-400' },
  refused: { label: 'refused', className: 'bg-slate-500/15 text-slate-300 ring-slate-500/25', prompt: 'text-slate-500' },
};

function exitTone(c: CommandEntry) {
  if (c.error || c.timed_out) return 'text-rose-300';
  if (c.exit_code === 0) return 'text-emerald-300';
  return 'text-amber-300';
}

function CommandRow({ c, defaultOpen }: { c: CommandEntry; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const kind = KIND[c.kind] ?? KIND.write;
  const hasBody = c.status === 'done' || c.reason;

  return (
    <li className="min-w-0 overflow-hidden rounded-xl border border-white/[0.06] bg-black/25">
      <button
        onClick={() => hasBody && setOpen((o) => !o)}
        className="flex w-full min-w-0 items-start gap-2 px-3 py-2.5 text-left transition hover:bg-white/[0.03]"
      >
        <ChevronRight size={14} className={`mt-0.5 shrink-0 text-slate-500 transition ${open ? 'rotate-90' : ''} ${hasBody ? '' : 'opacity-0'}`} />
        <div className="min-w-0 flex-1">
          <code className="block break-all font-mono text-[12.5px] leading-snug text-slate-100">
            <span className={`mr-1.5 select-none ${kind.prompt}`}>$</span>
            {c.command}
          </code>
          {c.purpose && <div className="mt-1 truncate text-[11px] text-slate-500">{c.purpose}</div>}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <span className={`rounded-full px-1.5 py-px text-[10px] font-semibold ring-1 ${kind.className}`}>{kind.label}</span>
          {c.status === 'running' ? (
            <Loader2 size={12} className="animate-spin text-sky-300" />
          ) : c.status === 'done' ? (
            <span className={`font-mono text-[10.5px] ${exitTone(c)}`}>
              {c.timed_out ? 'timeout' : c.error ? 'error' : `exit ${c.exit_code ?? '?'}`} · {((c.duration_ms ?? 0) / 1000).toFixed(1)}s
            </span>
          ) : null}
        </div>
      </button>
      {open && hasBody && (
        <div className="min-w-0 border-t border-white/[0.06] px-3 py-2">
          {c.reason && <p className="mb-1.5 text-[11.5px] text-rose-200">{c.reason}</p>}
          {c.error && <p className="mb-1.5 text-[11.5px] text-rose-200">{c.error}</p>}
          {c.status === 'done' && (
            <pre className="max-h-96 max-w-full overflow-auto whitespace-pre rounded-lg bg-black/50 p-2.5 font-mono text-[11.5px] leading-relaxed text-emerald-100/80 ring-1 ring-white/[0.04]">
              {c.output?.trim() ? c.output : '(no output)'}
            </pre>
          )}
          {c.truncated && <p className="mt-1 text-[10.5px] text-slate-500">Output was truncated.</p>}
          <p className="mt-1 text-[10.5px] text-slate-600">{clock(new Date(c.ts).toISOString())}</p>
        </div>
      )}
    </li>
  );
}

type Filter = 'all' | 'read' | 'write';

/** Every command Tshoot ran over SSH - the left pane of the Tshoot view. */
export function CommandLog({ commands }: { commands: CommandEntry[] }) {
  const [filter, setFilter] = useState<Filter>('all');
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }), [commands.length]);
  const lastId = commands[commands.length - 1]?.id;

  const counts = useMemo(
    () => ({
      read: commands.filter((c) => c.kind === 'read').length,
      write: commands.filter((c) => c.kind !== 'read').length,
      failed: commands.filter((c) => c.status === 'done' && (c.error || c.timed_out || (c.exit_code ?? 0) !== 0)).length,
    }),
    [commands],
  );
  const shown = filter === 'all' ? commands : filter === 'read' ? commands.filter((c) => c.kind === 'read') : commands.filter((c) => c.kind !== 'read');

  return (
    <section className="flex h-full min-h-0 w-full min-w-0 flex-col overflow-hidden rounded-2xl border border-white/[0.06] bg-ink-900/80 shadow-[0_1px_0_rgba(255,255,255,0.03)_inset,0_10px_30px_-12px_rgba(0,0,0,0.6)] backdrop-blur">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="rounded-xl bg-gradient-to-br from-emerald-400 to-teal-600 p-1.5 shadow-lg shadow-emerald-950/40">
            <Terminal size={16} className="text-white" />
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-white">Router console</h2>
            <p className="truncate text-[11px] text-slate-500">Every command Tshoot ran over SSH on the RT-AX88U Pro</p>
          </div>
        </div>
        <Segmented
          options={[
            { label: `All ${commands.length}`, value: 'all' as Filter },
            { label: `Reads ${counts.read}`, value: 'read' as Filter },
            { label: `Changes ${counts.write}`, value: 'write' as Filter },
          ]}
          value={filter}
          onChange={setFilter}
        />
      </header>

      {/* fake terminal title bar */}
      <div className="flex items-center gap-1.5 border-b border-white/[0.04] bg-black/20 px-4 py-1.5">
        <span className="h-2.5 w-2.5 rounded-full bg-rose-400/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" />
        <span className="ml-2 truncate font-mono text-[11px] text-slate-500">router:~ · ssh</span>
        {counts.failed > 0 && <span className="ml-auto shrink-0 font-mono text-[10.5px] text-amber-300">{counts.failed} non-zero exit</span>}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden p-3">
        {shown.length === 0 ? (
          <div className="mt-16 text-center">
            <Terminal size={28} className="mx-auto text-slate-700" />
            <p className="mt-3 font-mono text-xs text-slate-500">
              <span className="text-emerald-400">$</span> waiting for Tshoot…
              <span className="ml-0.5 inline-block h-3.5 w-1.5 translate-y-0.5 animate-pulse bg-emerald-400/70" />
            </p>
            <p className="mt-2 text-[11px] text-slate-600">Commands appear here live as Tshoot investigates.</p>
          </div>
        ) : (
          <ul className="min-w-0 space-y-2">
            {shown.map((c) => (
              <CommandRow key={c.id} c={c} defaultOpen={c.id === lastId} />
            ))}
          </ul>
        )}
        <div ref={endRef} />
      </div>
    </section>
  );
}

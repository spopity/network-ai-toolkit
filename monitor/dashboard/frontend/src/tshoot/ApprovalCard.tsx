import { useState } from 'react';
import { AlertTriangle, Check, CheckCircle2, Clock, ShieldAlert, Undo2, X, XCircle } from 'lucide-react';
import type { ApprovalStatus, ChatItem } from './types';

type Approval = Extract<ChatItem, { kind: 'approval' }>;

const RISK: Record<Approval['risk'], { label: string; className: string }> = {
  low: { label: 'Low risk', className: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30' },
  medium: { label: 'Medium risk', className: 'bg-amber-500/10 text-amber-300 ring-amber-500/30' },
  high: { label: 'High risk', className: 'bg-rose-500/10 text-rose-300 ring-rose-500/30' },
};

const STATUS: Record<Exclude<ApprovalStatus, 'pending'>, { label: string; icon: typeof Check; className: string }> = {
  approved: { label: 'Approved and executed', icon: CheckCircle2, className: 'text-emerald-300' },
  rejected: { label: 'Rejected', icon: XCircle, className: 'text-rose-300' },
  superseded: { label: 'Skipped - you sent a new message', icon: Clock, className: 'text-slate-400' },
  expired: { label: 'Expired', icon: Clock, className: 'text-slate-400' },
  blocked: { label: 'Blocked by safety policy', icon: ShieldAlert, className: 'text-rose-300' },
};

interface Props {
  approval: Approval;
  busy: boolean;
  onDecide: (id: string, decision: 'approve' | 'reject', note: string) => void;
}

export function ApprovalCard({ approval: a, busy, onDecide }: Props) {
  const [note, setNote] = useState('');
  const pending = a.status === 'pending';
  const risk = RISK[a.risk] ?? RISK.medium;
  const done = a.status === 'pending' ? null : STATUS[a.status];

  return (
    <div
      className={`ml-8 overflow-hidden rounded-2xl border ${
        pending ? 'border-amber-500/30 bg-gradient-to-br from-amber-500/[0.07] to-transparent shadow-lg shadow-amber-950/20' : 'border-white/[0.06] bg-white/[0.02]'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-3.5 py-2">
        <div className="flex items-center gap-2 text-[12px] font-semibold text-amber-200">
          <ShieldAlert size={14} />
          Change needs your approval
        </div>
        <span className={`rounded-full px-2 py-0.5 text-[10.5px] font-semibold ring-1 ${risk.className}`}>{risk.label}</span>
      </div>

      <div className="space-y-2.5 px-3.5 py-3 text-[13px]">
        <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-black/40 px-3 py-2 font-mono text-[12.5px] text-amber-100">
          {a.command}
        </pre>
        {a.reason && <p className="text-slate-200">{a.reason}</p>}
        {a.expected_effect && (
          <p className="text-slate-400">
            <span className="font-medium text-slate-300">Effect: </span>
            {a.expected_effect}
          </p>
        )}
        {a.rollback && (
          <p className="flex items-start gap-1.5 text-slate-400">
            <Undo2 size={13} className="mt-0.5 shrink-0" />
            <span>
              <span className="font-medium text-slate-300">Rollback: </span>
              <code className="font-mono text-[12px] text-slate-300">{a.rollback}</code>
            </span>
          </p>
        )}
        {a.warnings.map((w) => (
          <p key={w} className="flex items-start gap-1.5 rounded-lg bg-rose-500/10 px-2.5 py-1.5 text-[12.5px] text-rose-200 ring-1 ring-rose-500/20">
            <AlertTriangle size={13} className="mt-0.5 shrink-0" />
            {w}
          </p>
        ))}
      </div>

      <div className="border-t border-white/[0.06] px-3.5 py-2.5">
        {pending ? (
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Optional note for Tshoot"
              className="min-w-0 flex-1 basis-full rounded-lg border border-white/10 sm:basis-auto bg-black/30 px-2.5 py-1.5 text-[12.5px] text-slate-200 outline-none placeholder:text-slate-500 focus:border-sky-500/50"
            />
            <button
              disabled={busy}
              onClick={() => onDecide(a.id, 'reject', note)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-[12.5px] font-semibold text-rose-200 transition hover:bg-rose-500/20 disabled:opacity-40"
            >
              <X size={14} /> Reject
            </button>
            <button
              disabled={busy}
              onClick={() => onDecide(a.id, 'approve', note)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-br from-emerald-500 to-teal-600 px-3 py-1.5 text-[12.5px] font-semibold text-white shadow-lg shadow-emerald-950/40 transition hover:brightness-110 disabled:opacity-40"
            >
              <Check size={14} /> Approve &amp; run
            </button>
          </div>
        ) : (
          done && (
            <div className={`flex items-center gap-1.5 text-[12px] font-medium ${done.className}`}>
              <done.icon size={14} />
              {done.label}
            </div>
          )
        )}
      </div>
    </div>
  );
}

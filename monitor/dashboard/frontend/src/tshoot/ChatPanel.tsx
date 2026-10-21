import { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Bot, Cpu, Loader2, RotateCcw, SendHorizontal, ShieldCheck, Square, Stethoscope, User } from 'lucide-react';
import type { useTshootChat } from './useTshootChat';
import { ApprovalCard } from './ApprovalCard';

const SUGGESTIONS = [
  'My internet keeps dropping - find out why.',
  'Which channel and width is the 5 GHz radio on, and is there interference?',
  'A device on Wi-Fi is slow. Check signal and link rates of all clients.',
  'What has Skynet blocked in the last hour, and is any LAN device talking to bad IPs?',
];

type Chat = ReturnType<typeof useTshootChat>;

function ModelBadge({ model }: { model: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-violet-500/10 px-1.5 py-px text-[10px] font-medium text-violet-300">
      <Cpu size={10} />
      {model}
    </span>
  );
}

/** Tshoot conversation. Lives in the right-hand panel on desktop (like the AI Coach chat). */
export function ChatPanel({ chat, focusKey }: { chat: Chat; focusKey?: number }) {
  const [draft, setDraft] = useState('');
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }), [chat.items, chat.progress]);
  useEffect(() => {
    if (focusKey) inputRef.current?.focus();
  }, [focusKey]);

  function submit() {
    if (!draft.trim() || chat.busy) return;
    chat.send(draft);
    setDraft('');
  }

  const pending = chat.items.some((i) => i.kind === 'approval' && i.status === 'pending');

  return (
    <div className="flex h-full min-h-0 w-full min-w-0 flex-col">
      <header className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-4 pb-3 pt-[max(0.75rem,env(safe-area-inset-top))] lg:pt-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="rounded-xl bg-gradient-to-br from-sky-500 to-violet-500 p-1.5 shadow-lg shadow-sky-900/40">
            <Stethoscope size={16} className="text-white" />
          </div>
          <div className="min-w-0">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-white">
              Tshoot
              {chat.busy && <span className="rounded-full bg-sky-500/15 px-1.5 py-px text-[10px] font-medium text-sky-300">working</span>}
              {pending && <span className="rounded-full bg-amber-500/15 px-1.5 py-px text-[10px] font-medium text-amber-300">needs approval</span>}
            </h2>
            <p className="truncate text-[11px] text-slate-500">Reads the router freely · asks before changing anything</p>
          </div>
        </div>
        <button
          onClick={chat.reset}
          title="New conversation"
          disabled={chat.busy || chat.items.length === 0}
          className="rounded-lg p-2 text-slate-400 transition hover:bg-white/5 hover:text-white disabled:opacity-40"
        >
          <RotateCcw size={17} />
        </button>
      </header>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overflow-x-hidden px-4 py-4">
        {chat.items.length === 0 && (
          <div className="mx-auto mt-6 max-w-md text-center">
            <div className="relative mx-auto mb-4 w-fit">
              <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-sky-500 to-violet-500 opacity-40 blur-xl" />
              <div className="relative rounded-2xl bg-gradient-to-br from-sky-500/25 to-violet-500/25 p-3 ring-1 ring-white/10">
                <Stethoscope size={26} className="text-sky-200" />
              </div>
            </div>
            <p className="text-sm text-slate-300">Describe the problem - Tshoot investigates on the router.</p>
            <p className="mt-1 text-xs text-slate-500">Diagnostics run automatically. Fixes wait for your approval.</p>
            <div className="mt-5 space-y-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => chat.send(s)}
                  className="block w-full rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-left text-xs text-slate-300 transition hover:border-sky-500/30 hover:bg-sky-500/5"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {chat.items.map((it) =>
          it.kind === 'user' ? (
            <div key={it.id} className="flex justify-end gap-2">
              <div className="min-w-0 max-w-[85%] whitespace-pre-wrap break-words rounded-2xl rounded-tr-sm bg-gradient-to-br from-sky-600 to-blue-700 px-3.5 py-2 text-[13.5px] text-white shadow-lg shadow-blue-950/40">
                {it.content}
              </div>
              <div className="mt-1 h-fit rounded-full bg-white/5 p-1 text-slate-400">
                <User size={13} />
              </div>
            </div>
          ) : it.kind === 'assistant' ? (
            <div key={it.id} className="flex gap-2">
              <div className={`mt-1 h-fit shrink-0 rounded-full p-1 ${it.error ? 'bg-rose-500/15 text-rose-300' : 'bg-sky-500/15 text-sky-300'}`}>
                <Bot size={13} />
              </div>
              <div className="min-w-0 max-w-[92%]">
                <div className={`mb-1 flex items-center gap-1.5 text-[11px] font-semibold ${it.error ? 'text-rose-300' : 'text-sky-300'}`}>
                  {it.error ? 'Error' : 'Tshoot'}
                  {it.model && !it.error && <ModelBadge model={it.model} />}
                </div>
                <div
                  className={`prose-chat rounded-2xl rounded-tl-sm border px-3.5 py-2 ${
                    it.error ? 'border-rose-500/20 bg-rose-500/5' : 'border-white/[0.06] bg-white/[0.03]'
                  }`}
                >
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{it.content}</ReactMarkdown>
                </div>
              </div>
            </div>
          ) : (
            <ApprovalCard key={it.id} approval={it} busy={chat.busy} onDecide={chat.decide} />
          ),
        )}

        {chat.busy && (
          <div className="flex gap-2">
            <div className="mt-1 h-fit rounded-full bg-sky-500/15 p-1 text-sky-300">
              <Loader2 size={13} className="animate-spin" />
            </div>
            <div className="min-w-0 space-y-1 rounded-2xl rounded-tl-sm border border-white/[0.06] bg-white/[0.02] px-3.5 py-2">
              {chat.progress.length === 0 && <p className="text-xs text-slate-400">Thinking…</p>}
              {chat.progress.map((p, i) => (
                <p key={i} className={`break-words text-xs ${i === chat.progress.length - 1 ? 'text-slate-200' : 'text-slate-500'}`}>
                  {p}
                </p>
              ))}
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      <footer className="border-t border-white/[0.06] p-3 pb-[max(0.75rem,env(safe-area-inset-bottom))]">
        <div className="mb-2 flex items-center gap-2 text-[11px] text-slate-500">
          <ShieldCheck size={12} className="text-emerald-400" />
          Safety policy: reads run, changes need approval, factory reset &amp; flash writes blocked
        </div>
        <div className="flex items-end gap-2 rounded-2xl border border-white/10 bg-black/20 p-1.5 focus-within:border-sky-500/40">
          <textarea
            ref={inputRef}
            value={draft}
            rows={1}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                submit();
              }
            }}
            placeholder="Ask Tshoot to check something…"
            className="max-h-40 min-h-[38px] min-w-0 flex-1 resize-none bg-transparent px-2.5 py-2 text-[13.5px] text-slate-100 outline-none placeholder:text-slate-500"
          />
          {chat.busy ? (
            <button
              onClick={chat.stop}
              title="Stop"
              className="rounded-xl bg-rose-500/15 p-2.5 text-rose-300 ring-1 ring-rose-500/30 transition hover:bg-rose-500/25"
            >
              <Square size={16} />
            </button>
          ) : (
            <button
              onClick={submit}
              disabled={!draft.trim()}
              title="Send"
              className="rounded-xl bg-gradient-to-br from-sky-500 to-violet-500 p-2.5 text-white shadow-lg shadow-sky-900/40 transition hover:brightness-110 disabled:opacity-40"
            >
              <SendHorizontal size={16} />
            </button>
          )}
        </div>
      </footer>
    </div>
  );
}

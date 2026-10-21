import { useEffect, useState } from 'react';
import { LayoutDashboard, MessageSquare, PanelRightClose, PanelRightOpen, RefreshCw, Router as RouterIcon, Stethoscope, Terminal } from 'lucide-react';
import { useDashboardState } from './hooks/useDashboardState';
import { useHistory } from './hooks/useHistory';
import { useCollectTrigger } from './hooks/useCollectTrigger';
import { MonitorView } from './monitor/MonitorView';
import { ChatPanel } from './tshoot/ChatPanel';
import { CommandLog } from './tshoot/CommandLog';
import { useTshootChat } from './tshoot/useTshootChat';
import { relTime, today } from './lib/format';
import './tshoot/tshoot.css';

/** monitor = dashboard; tshoot = console + chat on desktop, chat on mobile; console = mobile console pane */
type Tab = 'monitor' | 'tshoot' | 'console';

function readHash(): Tab {
  const h = window.location.hash;
  return h === '#/tshoot' ? 'tshoot' : h === '#/console' ? 'console' : 'monitor';
}

function useHashTab(): [Tab, (t: Tab) => void] {
  const [tab, setTab] = useState<Tab>(readHash);
  useEffect(() => {
    const onHash = () => setTab(readHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  return [tab, (t) => (window.location.hash = t === 'monitor' ? '#/' : `#/${t}`)];
}

function usePersistentFlag(key: string, initial: boolean): [boolean, (v: boolean) => void] {
  const [v, setV] = useState(() => {
    try {
      const s = localStorage.getItem(key);
      return s == null ? initial : s === '1';
    } catch {
      return initial;
    }
  });
  return [
    v,
    (nv) => {
      setV(nv);
      try {
        localStorage.setItem(key, nv ? '1' : '0');
      } catch {
        /* per-viewer convenience only */
      }
    },
  ];
}

export default function App() {
  const [tab, setTab] = useHashTab();
  const chat = useTshootChat();
  const { data, error, refresh } = useDashboardState();
  const { data: history, refresh: refreshHistory } = useHistory(30);
  const collect = useCollectTrigger(() => {
    refresh();
    refreshHistory();
  });
  const [asideOpen, setAsideOpen] = usePersistentFlag('nai-chat-aside', true);
  const [focusKey, setFocusKey] = useState(0);
  const [toast, setToast] = useState<string | null>(null);

  const snap = data?.snapshot ?? null;
  const collecting = Boolean(collect.status?.running) || collect.triggering;
  const pendingApproval = chat.items.some((i) => i.kind === 'approval' && i.status === 'pending');

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 3500);
    return () => window.clearTimeout(t);
  }, [toast]);

  function ask(question: string) {
    chat.send(question);
    if (window.matchMedia('(min-width: 1280px)').matches) setAsideOpen(true);
    else setTab('tshoot');
    setFocusKey((k) => k + 1);
    setToast('Sent to Tshoot');
  }

  function runCheck() {
    if (collect.disabled) {
      setToast(collecting ? 'A check is already running' : 'Just checked - try again in a moment');
      return;
    }
    collect.trigger();
    setToast('Collecting router logs and analyzing…');
  }

  const onTshoot = tab === 'tshoot' || tab === 'console';
  // The chat panel sits on the right on desktop (like the AI Coach chat): always for the
  // Tshoot view, optional on Monitor. On mobile it is the full-screen "Tshoot" tab.
  const asideClass =
    tab === 'tshoot'
      ? 'flex w-full lg:w-[min(560px,44vw)] lg:border-l lg:border-white/[0.06]'
      : tab === 'console'
        ? 'hidden lg:flex lg:w-[min(560px,44vw)] lg:border-l lg:border-white/[0.06]'
        : asideOpen
          ? 'hidden xl:flex xl:w-[400px] 2xl:w-[440px] xl:border-l xl:border-white/[0.06]'
          : 'hidden';

  return (
    <div className="flex h-full overflow-hidden">
      <div className={`min-w-0 flex-1 flex-col ${tab === 'tshoot' ? 'hidden lg:flex' : 'flex'}`}>
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-white/[0.06] bg-ink-950/70 px-4 pb-3 pt-[max(0.75rem,env(safe-area-inset-top))] backdrop-blur-xl lg:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <div className="rounded-xl bg-gradient-to-br from-sky-400 via-violet-500 to-pink-500 p-2 shadow-lg shadow-violet-900/40">
              <RouterIcon size={18} className="text-white" />
            </div>
            <div className="min-w-0">
              <h1 className="text-[15px] font-semibold leading-tight text-white">Network AI</h1>
              <p className="truncate text-[11px] text-slate-500">
                {snap ? (
                  <>
                    {today()} · {snap.system.firmware ?? snap.system.productid} · checked {relTime(snap.collected_at)}
                  </>
                ) : error ? (
                  `API unreachable: ${error}`
                ) : (
                  'Loading…'
                )}
              </p>
            </div>
          </div>

          <nav className="hidden items-center rounded-xl bg-white/[0.04] p-1 ring-1 ring-white/[0.06] lg:flex">
            {(
              [
                { id: 'monitor', label: 'Monitor', icon: LayoutDashboard },
                { id: 'tshoot', label: 'Tshoot', icon: Stethoscope },
              ] as const
            ).map(({ id, label, icon: Icon }) => {
              const active = id === 'monitor' ? tab === 'monitor' : onTshoot;
              return (
                <button
                  key={id}
                  onClick={() => setTab(id)}
                  className={`relative inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-[13px] font-medium transition ${
                    active ? 'bg-gradient-to-br from-sky-500 to-violet-500 text-white shadow-lg shadow-sky-900/40' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Icon size={14} />
                  {label}
                  {id === 'tshoot' && pendingApproval && !active && (
                    <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-amber-400 ring-2 ring-ink-950" />
                  )}
                </button>
              );
            })}
          </nav>

          <div className="flex items-center gap-2 lg:gap-3">
            <span className="hidden text-xs text-slate-500 2xl:inline">
              {collecting ? 'Checking…' : collect.status?.finished_at ? `Last check ${relTime(collect.status.finished_at)}` : ''}
            </span>
            <button
              onClick={runCheck}
              title="Collect router logs now (no AI -- the AI briefing runs once a day at 03:00 UTC)"
              className="flex items-center gap-2 whitespace-nowrap rounded-xl bg-white/[0.04] px-3 py-1.5 text-xs font-medium text-slate-200 ring-1 ring-white/10 transition hover:bg-white/[0.08]"
            >
              <RefreshCw size={14} className={collecting ? 'animate-spin-fast text-sky-300' : ''} />
              <span className="hidden sm:inline">{collecting ? 'Checking…' : 'Check now'}</span>
            </button>
            {tab === 'monitor' && (
              <button
                onClick={() => setAsideOpen(!asideOpen)}
                title={asideOpen ? 'Hide Tshoot chat' : 'Show Tshoot chat'}
                className="hidden rounded-xl p-2 text-slate-400 ring-1 ring-white/10 transition hover:bg-white/[0.06] hover:text-white xl:block"
              >
                {asideOpen ? <PanelRightClose size={16} /> : <PanelRightOpen size={16} />}
              </button>
            )}
          </div>
        </header>

        <main
          className={`min-h-0 flex-1 ${onTshoot ? 'overflow-hidden p-3 pb-[calc(5rem+env(safe-area-inset-bottom))] lg:p-4' : 'overflow-y-auto'}`}
        >
          {onTshoot ? (
            <CommandLog commands={chat.commands} />
          ) : (
            <MonitorView data={data} history={history} error={error} collecting={collecting} onCollect={runCheck} onAsk={ask} />
          )}
        </main>
      </div>

      <aside
        className={`${asideClass} h-full min-w-0 shrink-0 flex-col bg-ink-900/70 pb-[calc(4rem+env(safe-area-inset-bottom))] backdrop-blur-xl lg:pb-0`}
      >
        <ChatPanel chat={chat} focusKey={focusKey} />
      </aside>

      {/* mobile tab bar (coach style) */}
      <nav className="fixed inset-x-0 bottom-0 z-30 border-t border-white/[0.06] bg-ink-900/90 pb-[env(safe-area-inset-bottom)] backdrop-blur-xl lg:hidden">
        <div className="grid h-16 grid-cols-3">
          {(
            [
              { id: 'monitor', label: 'Monitor', icon: LayoutDashboard },
              { id: 'console', label: 'Console', icon: Terminal },
              { id: 'tshoot', label: 'Tshoot', icon: MessageSquare },
            ] as const
          ).map(({ id, label, icon: Icon }) => {
            const active = tab === id;
            return (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`relative flex flex-col items-center justify-center gap-1 text-[11px] font-medium transition ${active ? 'text-white' : 'text-slate-500'}`}
              >
                {active && <span className="absolute top-0 h-0.5 w-12 rounded-full bg-gradient-to-r from-sky-400 to-violet-500" />}
                <span className={`relative ${active ? 'text-sky-300' : ''}`}>
                  <Icon size={20} />
                  {id === 'tshoot' && pendingApproval && (
                    <span className="absolute -right-1 -top-0.5 h-2.5 w-2.5 rounded-full bg-amber-400 ring-2 ring-ink-900" />
                  )}
                  {id === 'console' && chat.busy && <span className="absolute -right-1 -top-0.5 h-2.5 w-2.5 rounded-full bg-sky-400 ring-2 ring-ink-900" />}
                </span>
                {label}
              </button>
            );
          })}
        </div>
      </nav>

      {toast && (
        <div className="fixed bottom-[calc(5rem+env(safe-area-inset-bottom))] left-1/2 z-50 w-[calc(100%-2rem)] max-w-md -translate-x-1/2 rounded-xl border border-white/10 bg-ink-800/95 px-4 py-2.5 text-center text-sm text-slate-200 shadow-2xl backdrop-blur lg:bottom-5 lg:w-auto">
          {toast}
        </div>
      )}
    </div>
  );
}

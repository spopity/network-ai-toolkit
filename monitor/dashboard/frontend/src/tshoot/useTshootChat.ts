import { useEffect, useRef, useState } from 'react';
import { resetTshoot, streamTshoot } from './api';
import type { ChatItem, CommandEntry, TshootEvent } from './types';

const STORE_KEY = 'tshoot-chat-v1';
const MAX_ITEMS = 50;
const MAX_COMMANDS = 100;

interface Stored {
  sessionId: string;
  items: ChatItem[];
  commands: CommandEntry[];
}

const uid = () => Math.random().toString(36).slice(2, 12) + Date.now().toString(36);

function load(): Stored {
  try {
    const s = JSON.parse(localStorage.getItem(STORE_KEY) ?? 'null') as Stored | null;
    if (s?.sessionId) {
      // a turn interrupted by a reload can leave "running" commands behind
      s.commands = s.commands.map((c) => (c.status === 'running' ? { ...c, status: 'done', error: c.error ?? 'interrupted' } : c));
      return s;
    }
  } catch {
    /* fall through to a fresh conversation */
  }
  return { sessionId: uid(), items: [], commands: [] };
}

export function useTshootChat() {
  const [state, setState] = useState<Stored>(load);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(
        STORE_KEY,
        JSON.stringify({ ...state, items: state.items.slice(-MAX_ITEMS), commands: state.commands.slice(-MAX_COMMANDS) }),
      );
    } catch {
      /* storage full or blocked: the conversation still works for this tab */
    }
  }, [state]);

  const pushProgress = (line: string) => setProgress((p) => (p[p.length - 1] === line ? p : [...p.slice(-3), line]));

  function handle(e: TshootEvent, gotFinal: { v: boolean }) {
    switch (e.type) {
      case 'status':
        pushProgress(e.content);
        break;
      case 'note':
        pushProgress(e.content.length > 160 ? `${e.content.slice(0, 160)}…` : e.content);
        break;
      case 'command':
        if (e.status === 'running') pushProgress(`Running ${e.command.length > 70 ? `${e.command.slice(0, 70)}…` : e.command}`);
        setState((s) => ({
          ...s,
          commands: [
            ...s.commands,
            {
              id: e.id,
              command: e.command,
              kind: e.kind,
              purpose: e.purpose,
              status: e.status === 'running' ? 'running' : (e.status as CommandEntry['status']),
              reason: e.reason,
              ts: Date.now(),
            },
          ],
        }));
        break;
      case 'command_result':
        setState((s) => ({
          ...s,
          commands: s.commands.map((c) => (c.id === e.id ? { ...c, ...e, kind: c.kind, status: 'done' } : c)),
        }));
        break;
      case 'approval': {
        const { type: _t, ...req } = e;
        void _t;
        setState((s) => ({ ...s, items: [...s.items, { kind: 'approval', status: 'pending', ...req }] }));
        break;
      }
      case 'approval_update':
        setState((s) => ({
          ...s,
          items: s.items.map((it) => (it.kind === 'approval' && it.id === e.id ? { ...it, status: e.status } : it)),
        }));
        break;
      case 'final':
        gotFinal.v = true;
        setState((s) => {
          // keep the approval card *after* the message that introduces it
          const items = [...s.items];
          const msg: ChatItem = { kind: 'assistant', id: uid(), content: e.content, model: e.model, error: e.agent === 'error' };
          const last = items[items.length - 1];
          if (e.awaiting_approval && last?.kind === 'approval' && last.id === e.awaiting_approval) items.splice(items.length - 1, 0, msg);
          else items.push(msg);
          return { ...s, items };
        });
        break;
      case 'error':
        gotFinal.v = true;
        setState((s) => ({ ...s, items: [...s.items, { kind: 'assistant', id: uid(), content: e.content, error: true }] }));
        break;
    }
  }

  async function run(path: 'chat' | 'approve', body: Record<string, unknown>) {
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setBusy(true);
    setProgress([path === 'chat' ? 'Tshoot is analyzing…' : 'Applying your decision…']);
    const gotFinal = { v: false };
    try {
      await streamTshoot(path, { session_id: state.sessionId, ...body }, (e) => handle(e, gotFinal), ctrl.signal);
      if (!gotFinal.v) throw new Error('No answer came back - please try again.');
    } catch (err) {
      const aborted = (err as Error).name === 'AbortError';
      setState((s) => ({
        ...s,
        items: [
          ...s.items,
          { kind: 'assistant', id: uid(), error: true, content: aborted ? 'Stopped.' : `Something went wrong: ${(err as Error).message}` },
        ],
      }));
    } finally {
      setBusy(false);
      setProgress([]);
      abortRef.current = null;
    }
  }

  function send(text: string) {
    const message = text.trim();
    if (!message || busy) return;
    const history = state.items
      .filter((i): i is Extract<ChatItem, { kind: 'user' | 'assistant' }> => (i.kind === 'user' || i.kind === 'assistant') && !('error' in i && i.error))
      .slice(-12)
      .map((i) => ({ role: i.kind, content: i.content }));
    setState((s) => ({ ...s, items: [...s.items, { kind: 'user', id: uid(), content: message }] }));
    void run('chat', { message, history });
  }

  function decide(approvalId: string, decision: 'approve' | 'reject', note = '') {
    if (busy) return;
    void run('approve', { approval_id: approvalId, decision, note });
  }

  function stop() {
    abortRef.current?.abort();
  }

  function reset() {
    if (busy) return;
    void resetTshoot(state.sessionId);
    setState({ sessionId: uid(), items: [], commands: [] });
  }

  return { ...state, busy, progress, send, decide, stop, reset };
}

import type { TshootEvent } from './types';

/** POST to a Tshoot endpoint and feed each Server-Sent Event to `onEvent` (same wire format as the AI Coach chat). */
export async function streamTshoot(
  path: 'chat' | 'approve',
  body: Record<string, unknown>,
  onEvent: (e: TshootEvent) => void,
  signal: AbortSignal,
) {
  const res = await fetch(`/api/tshoot/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok || !res.body) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.error ?? `Tshoot request failed: ${res.status}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf('\n\n')) >= 0) {
      const block = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const line = block.split('\n').find((l) => l.startsWith('data: '));
      if (line) onEvent(JSON.parse(line.slice(6)) as TshootEvent);
    }
  }
}

export async function resetTshoot(sessionId: string) {
  await fetch('/api/tshoot/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  }).catch(() => undefined);
}

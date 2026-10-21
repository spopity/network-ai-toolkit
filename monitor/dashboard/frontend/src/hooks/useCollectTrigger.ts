import { useCallback, useEffect, useRef, useState } from 'react';
import type { CollectStatus } from '../types';

const POLL_WHILE_RUNNING_MS = 3000;
const COOLDOWN_MS = 30_000;

export function useCollectTrigger(onComplete?: () => void) {
  const [status, setStatus] = useState<CollectStatus | null>(null);
  const [triggering, setTriggering] = useState(false);
  const [cooldownActive, setCooldownActive] = useState(false);
  const pollRef = useRef<number | null>(null);

  const fetchStatus = useCallback(async () => {
    const res = await fetch('/api/collect-status');
    const json = (await res.json()) as CollectStatus;
    setStatus(json);
    return json;
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  useEffect(() => {
    if (!status?.running) return;
    pollRef.current = window.setInterval(async () => {
      const s = await fetchStatus();
      if (!s.running && pollRef.current) {
        window.clearInterval(pollRef.current);
        setCooldownActive(true);
        window.setTimeout(() => setCooldownActive(false), COOLDOWN_MS);
        onComplete?.();
      }
    }, POLL_WHILE_RUNNING_MS);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.running, fetchStatus]);

  const trigger = useCallback(async () => {
    setTriggering(true);
    try {
      await fetch('/api/collect-now', { method: 'POST' });
      await fetchStatus();
    } finally {
      setTriggering(false);
    }
  }, [fetchStatus]);

  const disabled = triggering || Boolean(status?.running) || cooldownActive;

  return { status, trigger, triggering, disabled, cooldownActive };
}

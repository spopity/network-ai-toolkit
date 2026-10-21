import { useEffect, useRef, useState } from 'react';
import type { DashboardState } from '../types';

const POLL_MS = 30_000;

export function useDashboardState() {
  const [data, setData] = useState<DashboardState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  async function fetchOnce() {
    try {
      const res = await fetch('/api/state');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = (await res.json()) as DashboardState;
      setData(json);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    fetchOnce();
    timer.current = window.setInterval(fetchOnce, POLL_MS);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, []);

  return { data, error, refresh: fetchOnce };
}

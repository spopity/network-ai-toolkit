import { useEffect, useState } from 'react';

export interface ConnmonPoint {
  ts: number; // unix seconds
  ping: number;
  jitter: number;
  quality: number;
}

export function useConnmon(hours: number) {
  const [points, setPoints] = useState<ConnmonPoint[] | null>(null);
  const [available, setAvailable] = useState(true);

  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const r = await fetch(`/api/connmon?hours=${hours}`);
        const j = await r.json();
        if (!alive) return;
        setPoints(j.points ?? []);
        setAvailable(j.available !== false);
      } catch {
        if (alive) {
          setPoints([]);
          setAvailable(false);
        }
      }
    }
    setPoints(null);
    load();
    const t = window.setInterval(load, 5 * 60_000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [hours]);

  return { points, available };
}

import { useEffect, useState } from 'react';

/** Fetch JSON from an /api endpoint and re-poll it; `available: false` responses surface as `error`. */
export function useJson<T>(url: string | null, refreshMs = 5 * 60_000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!url) {
      setData(null);
      return;
    }
    let alive = true;
    async function load() {
      try {
        const j = await (await fetch(url!)).json();
        if (!alive) return;
        if (j.available === false) setError(j.error ?? 'archive unavailable');
        else setError(null);
        setData(j);
      } catch (e) {
        if (alive) setError(String(e));
      }
    }
    setData(null);
    load();
    const t = window.setInterval(load, refreshMs);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [url, refreshMs]);
  return { data, error };
}

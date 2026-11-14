import { useCallback, useEffect, useState } from 'react';
import type { NetworkMapData } from './types';

/**
 * Live map of the network: rooms (from device names), each device linked to the mesh node
 * it is connected to (Wi-Fi band/signal or cable, from the latest 5-minute check), the
 * mesh backhaul, and the router's services. Links sit behind the cards; hovering or
 * selecting a device, node or room draws its links on top.
 */

const POLL_MS = 60_000;
/* ------------------------------------------------------------------ data */

export function useMapData(refreshKey: string | null | undefined) {
  const [data, setData] = useState<NetworkMapData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/network-map');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);
  useEffect(() => {
    load();
    const t = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(t);
  }, [load, refreshKey]);
  return { data, error };
}
export function usePersisted<T extends string>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      return (localStorage.getItem(key) as T) ?? initial;
    } catch {
      return initial;
    }
  });
  return [
    v,
    (nv) => {
      setV(nv);
      try {
        localStorage.setItem(key, nv);
      } catch {
        /* per-viewer convenience only */
      }
    },
  ];
}

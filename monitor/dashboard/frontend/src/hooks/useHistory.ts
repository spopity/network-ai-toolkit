import { useEffect, useState } from 'react';
import type { HistoryResponse } from '../types';

export function useHistory(days = 30) {
  const [data, setData] = useState<HistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);

  async function fetchOnce() {
    setLoading(true);
    try {
      const res = await fetch(`/api/history?days=${days}`);
      const json = (await res.json()) as HistoryResponse;
      setData(json);
    } catch {
      setData({ snapshots: [], watchdog_events: [], available: false, error: 'request failed' });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchOnce();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days]);

  return { data, loading, refresh: fetchOnce };
}

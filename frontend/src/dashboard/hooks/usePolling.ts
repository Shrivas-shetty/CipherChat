import { useCallback, useEffect, useRef, useState } from "react";

export function usePolling<T>(fetcher: (signal: AbortSignal) => Promise<T>, intervalMs: number, paused = false, filterKey = "") {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const controller = useRef<AbortController | null>(null);
  const busy = useRef(false);

  const refresh = useCallback(async () => {
    if (document.visibilityState !== "visible") return;
    if (busy.current) { controller.current?.abort(); busy.current = false; }
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    busy.current = true;
    try {
      const result = await fetcher(current.signal);
      if (!current.signal.aborted) { setData(result); setError(null); }
    } catch (err) {
      if (!current.signal.aborted) setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      if (!current.signal.aborted) { setLoading(false); busy.current = false; }
    }
  }, [fetcher]);

  useEffect(() => {
    setData(null); setError(null); setLoading(true);
    if (paused) return () => controller.current?.abort();
    void refresh();
    const timer = window.setInterval(() => void refresh(), intervalMs);
    const onVisibility = () => { if (document.visibilityState === "visible") void refresh(); };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
      controller.current?.abort();
      busy.current = false;
    };
  }, [refresh, intervalMs, paused, filterKey]);

  return { data, error, loading, refresh };
}

import { useState, useEffect, useRef, useCallback } from 'react';
import { getScan } from '../api/scans';
import { listEvents } from '../api/events';
import { ScanEvent, ScanResponse, ScanStatus } from '../types/api';
import { ApiError } from '../api/client';

const TERMINAL_STATUSES: Set<ScanStatus> = new Set([
  'completed',
  'partial',
  'failed',
  'canceled',
  'skipped',
]);

export interface UseScanWatcherResult {
  scan: ScanResponse | null;
  events: ScanEvent[];
  isLoading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
  isPolling: boolean;
  eventHistoryTruncated: boolean;
  expiredEventCount: number;
}

export function useScanWatcher(scanId: string | null): UseScanWatcherResult {
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [eventHistoryTruncated, setEventHistoryTruncated] = useState<boolean>(false);
  const [expiredEventCount, setExpiredEventCount] = useState<number>(0);

  const cursorRef = useRef<number>(0);
  const isMountedRef = useRef<boolean>(true);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    };
  }, []);

  const fetchScanAndEvents = useCallback(async (currentScanId: string) => {
    try {
      const detail = await getScan(currentScanId);
      if (!isMountedRef.current) return detail;
      setScan(detail);
      setError(null);

      // Fetch incremental events starting from cursor
      let currentCursor = cursorRef.current;
      let hasMore = true;
      const accumulatedNewEvents: ScanEvent[] = [];

      while (hasMore && isMountedRef.current) {
        const page = await listEvents(currentScanId, currentCursor, 100);
        if (page.items && page.items.length > 0) {
          accumulatedNewEvents.push(...page.items);
        }
        currentCursor = page.next_cursor;
        cursorRef.current = currentCursor;
        hasMore = page.has_more;

        if (page.history_truncated) {
          setEventHistoryTruncated(true);
        }
        if (page.expired_event_count > 0) {
          setExpiredEventCount(page.expired_event_count);
        }
      }

      if (accumulatedNewEvents.length > 0 && isMountedRef.current) {
        setEvents((prev) => {
          const existingIds = new Set(prev.map((e) => e.event_id ?? e.id));
          const toAdd = accumulatedNewEvents.filter(
            (e) => !existingIds.has(e.event_id ?? e.id)
          );
          return [...prev, ...toAdd];
        });
      }

      return detail;
    } catch (err: any) {
      if (isMountedRef.current) {
        setError(err);
      }
      throw err;
    }
  }, []);

  // Main polling loop effect
  useEffect(() => {
    if (!scanId) {
      setScan(null);
      setEvents([]);
      setError(null);
      cursorRef.current = 0;
      setIsPolling(false);
      setEventHistoryTruncated(false);
      setExpiredEventCount(0);
      return;
    }

    // Reset when scanId changes
    cursorRef.current = 0;
    setEvents([]);
    setIsLoading(true);
    setError(null);
    setIsPolling(true);
    setEventHistoryTruncated(false);
    setExpiredEventCount(0);

    let active = true;

    async function poll() {
      if (!active || !isMountedRef.current) return;

      try {
        const detail = await fetchScanAndEvents(scanId!);
        setIsLoading(false);

        if (!active || !isMountedRef.current) return;

        if (TERMINAL_STATUSES.has(detail.status)) {
          setIsPolling(false);
          return; // Stop polling when terminal
        }

        // Schedule next poll in 2000ms
        timerRef.current = window.setTimeout(poll, 2000);
      } catch (err) {
        setIsLoading(false);
        if (!active || !isMountedRef.current) return;
        if (err instanceof ApiError && err.status === 401) {
          setIsPolling(false);
          return;
        }
        setIsPolling(true);
        timerRef.current = window.setTimeout(poll, 2000);
      }
    }

    poll();

    return () => {
      active = false;
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    };
  }, [scanId, fetchScanAndEvents]);

  const refresh = useCallback(async () => {
    if (!scanId) return;
    try {
      await fetchScanAndEvents(scanId);
    } catch {
      // already set in state
    }
  }, [scanId, fetchScanAndEvents]);

  return {
    scan,
    events,
    isLoading,
    error,
    refresh,
    isPolling,
    eventHistoryTruncated,
    expiredEventCount,
  };
}

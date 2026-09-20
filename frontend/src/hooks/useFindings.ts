import { useState, useEffect, useCallback } from 'react';
import { listFindings } from '../api/findings';
import { FindingResponse } from '../types/api';

export interface UseFindingsOptions {
  severity?: string;
  category?: string;
  pageSize?: number;
  initialPage?: number;
}

export function useFindings(scanId: string | null, options: UseFindingsOptions = {}) {
  const { severity, category, pageSize = 50, initialPage = 1 } = options;

  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(initialPage);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);

  // When severity or category filter changes, reset to page 1
  useEffect(() => {
    setPage(1);
  }, [severity, category]);

  const fetchFindings = useCallback(async () => {
    if (!scanId) {
      setFindings([]);
      setTotal(0);
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      const offset = (page - 1) * pageSize;
      const res = await listFindings(scanId, {
        severity: severity || undefined,
        category: category || undefined,
        limit: pageSize,
        offset,
      });
      setFindings(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err);
    } finally {
      setIsLoading(false);
    }
  }, [scanId, severity, category, page, pageSize]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return {
    findings,
    total,
    page,
    setPage,
    pageSize,
    totalPages,
    isLoading,
    error,
    refetch: fetchFindings,
  };
}

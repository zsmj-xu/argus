import { useState, useEffect, useCallback } from 'react';
import { getReadyz, getHealthz } from '../api/system';
import { ReadyzResponse } from '../types/api';

export function useSystemStatus() {
  const [readyz, setReadyz] = useState<ReadyzResponse | null>(null);
  const [isHealthy, setIsHealthy] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const checkStatus = useCallback(async () => {
    try {
      const readyRes = await getReadyz();
      setReadyz(readyRes);
      setIsHealthy(readyRes.status === 'ready');
    } catch {
      try {
        await getHealthz();
        setReadyz({ status: 'not_ready', detail: '服务正在启动或尚未就绪' });
        setIsHealthy(false);
      } catch {
        setReadyz({ status: 'not_ready', detail: '后端 API 服务无法连接' });
        setIsHealthy(false);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkStatus();
    const timer = setInterval(checkStatus, 15000);
    return () => clearInterval(timer);
  }, [checkStatus]);

  return { readyz, isHealthy, isLoading, checkStatus };
}

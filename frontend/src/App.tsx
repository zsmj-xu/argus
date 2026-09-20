import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/layout/Header';
import { AuthModal } from './components/layout/AuthModal';
import { ScanCreateModal } from './components/scan/ScanCreateModal';
import { ScanList } from './components/scan/ScanList';
import { ScanDetailView } from './components/detail/ScanDetailView';
import { listScans } from './api/scans';
import { ScanResponse } from './types/api';
import { authStore } from './store/auth';
import { Search, RotateCw, KeyRound, AlertCircle } from 'lucide-react';

export const App: React.FC = () => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [, setTotal] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [isAuthOpen, setIsAuthOpen] = useState<boolean>(false);
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [searchFilter, setSearchFilter] = useState<string>('');

  const [hasAuth, setHasAuth] = useState<boolean>(!!authStore.getApiKey());

  useEffect(() => {
    return authStore.subscribe((key) => {
      setHasAuth(!!key);
      if (key) {
        fetchScanList();
      }
    });
  }, []);

  const fetchScanList = useCallback(async () => {
    if (!authStore.getApiKey()) {
      setIsAuthOpen(true);
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      const res = await listScans(50, 0);
      setScans(res.items);
      setTotal(res.total);
    } catch (err: any) {
      if (err.status === 401) {
        setIsAuthOpen(true);
      } else {
        setError(err.message || '获取扫描任务列表失败');
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (authStore.getApiKey()) {
      fetchScanList();
    }
  }, [fetchScanList]);

  const filteredScans = scans.filter((s) => {
    if (!searchFilter.trim()) return true;
    const q = searchFilter.toLowerCase();
    return (
      s.repository_url.toLowerCase().includes(q) ||
      (s.ref && s.ref.toLowerCase().includes(q)) ||
      s.id.toLowerCase().includes(q)
    );
  });

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans">
      <Header
        onOpenNewScan={() => {
          if (!hasAuth) setIsAuthOpen(true);
          else setIsCreateOpen(true);
        }}
        onOpenAuth={() => setIsAuthOpen(true)}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {!hasAuth ? (
          <div className="py-24 text-center max-w-md mx-auto space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mx-auto">
              <KeyRound className="w-7 h-7" />
            </div>
            <h2 className="text-lg font-bold text-zinc-100">请配置 Argus 服务访问凭据</h2>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Argus 是内部 API Key 保护的白盒扫描服务。输入您的 API Key
              以建立受保护的安全会话（密钥仅在当前内存中短暂驻留）。
            </p>
            <button
              onClick={() => setIsAuthOpen(true)}
              className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg shadow-lg shadow-emerald-950 transition-all"
            >
              配置 API Key
            </button>
          </div>
        ) : selectedScanId ? (
          <ScanDetailView
            scanId={selectedScanId}
            onBack={() => setSelectedScanId(null)}
          />
        ) : (
          <div className="space-y-6 animate-in fade-in duration-150">
            {/* Action & Filter Bar */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div>
                <h1 className="text-xl font-bold text-zinc-100 tracking-tight">
                  白盒扫描任务看板
                </h1>
                <p className="text-xs text-zinc-400 mt-0.5">
                  所有通过 OpenCodeReview 执行的白盒静态源码审查任务历史
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    placeholder="按仓库地址 / 分支 / ID 搜索..."
                    className="pl-9 pr-3.5 py-1.5 bg-zinc-900 border border-zinc-800 rounded-lg text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 w-64"
                  />
                </div>

                <button
                  onClick={fetchScanList}
                  disabled={isLoading}
                  className="p-2 bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
                  title="刷新列表"
                >
                  <RotateCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>

            {error && (
              <div className="p-3.5 bg-rose-950/40 border border-rose-800/50 rounded-xl text-xs text-rose-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Scans List Table/Cards */}
            <ScanList
              scans={filteredScans}
              selectedScanId={selectedScanId}
              onSelectScan={(id) => setSelectedScanId(id)}
              onRefresh={fetchScanList}
              isLoading={isLoading}
            />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-900 py-6 text-center text-xs text-zinc-600 font-mono">
        Argus White-box Scan Service · Powered by OpenCodeReview · Strict In-Memory Security
      </footer>

      {/* Modals */}
      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onSuccess={() => fetchScanList()}
      />

      <ScanCreateModal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        onCreated={(newId) => {
          fetchScanList();
          setSelectedScanId(newId);
        }}
        onRequireAuth={() => setIsAuthOpen(true)}
      />
    </div>
  );
};

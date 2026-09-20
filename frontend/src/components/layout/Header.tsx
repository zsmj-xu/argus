import React, { useState, useEffect } from 'react';
import { Shield, Key, Plus, Activity, CheckCircle2, AlertCircle } from 'lucide-react';
import { authStore } from '../../store/auth';
import { useSystemStatus } from '../../hooks/useSystemStatus';

interface HeaderProps {
  onOpenNewScan: () => void;
  onOpenAuth: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenNewScan, onOpenAuth }) => {
  const [hasKey, setHasKey] = useState<boolean>(!!authStore.getApiKey());
  const { readyz, isHealthy } = useSystemStatus();

  useEffect(() => {
    return authStore.subscribe((key) => {
      setHasKey(!!key);
    });
  }, []);

  return (
    <header className="sticky top-0 z-40 bg-zinc-950/80 backdrop-blur border-b border-zinc-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Left: Brand */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-zinc-100 tracking-tight text-lg">ARGUS</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                White-box
              </span>
            </div>
            <p className="text-xs text-zinc-400">OpenCodeReview 白盒代码静态审查</p>
          </div>
        </div>

        {/* Right: Status & Actions */}
        <div className="flex items-center gap-4">
          {/* System Readyz Status */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-zinc-900 border border-zinc-800 text-xs">
            <Activity className="w-3.5 h-3.5 text-zinc-400" />
            {isHealthy ? (
              <span className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                OCR & LLM 就绪
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-rose-400" title={readyz?.detail}>
                <AlertCircle className="w-3.5 h-3.5" />
                服务未就绪
              </span>
            )}
          </div>

          {/* Auth Key Button */}
          <button
            onClick={onOpenAuth}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              hasKey
                ? 'bg-zinc-900 border-zinc-700 text-zinc-300 hover:border-zinc-500'
                : 'bg-amber-500/10 border-amber-500/40 text-amber-300 hover:bg-amber-500/20'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            {hasKey ? '已连接 (API Key)' : '未输入 API Key'}
          </button>

          {/* New Scan Button */}
          <button
            onClick={onOpenNewScan}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg shadow-sm shadow-emerald-950 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>新建扫描</span>
          </button>
        </div>
      </div>
    </header>
  );
};

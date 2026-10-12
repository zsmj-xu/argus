import React, { useState, useEffect } from 'react';
import {
  Key,
  Plus,
  Activity,
  AlertCircle,
  ChevronRight,
  FolderGit2,
  Terminal,
} from 'lucide-react';
import { authStore } from '../../store/auth';
import { useSystemStatus } from '../../hooks/useSystemStatus';
import { ArgusLogo } from '../common/ArgusLogo';

interface HeaderProps {
  currentProjectId?: string | null;
  currentProjectName?: string | null;
  currentScanId?: string | null;
  onNavigateHome: () => void;
  onNavigateProject?: (projectId: string) => void;
  onOpenNewProject: () => void;
  onOpenAuth: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentProjectId,
  currentProjectName,
  currentScanId,
  onNavigateHome,
  onNavigateProject,
  onOpenNewProject,
  onOpenAuth,
}) => {
  const [hasKey, setHasKey] = useState<boolean>(!!authStore.getApiKey());
  const { readyz, isHealthy } = useSystemStatus();

  useEffect(() => {
    return authStore.subscribe((key) => {
      setHasKey(!!key);
    });
  }, []);

  return (
    <header className="sticky top-0 z-40 bg-obsidian-950/85 backdrop-blur-md border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Left: Brand & Breadcrumbs */}
        <div className="flex items-center gap-4 min-w-0">
          <button
            onClick={onNavigateHome}
            className="flex items-center text-left hover:opacity-90 transition-opacity focus:outline-none"
          >
            <ArgusLogo size="md" showText={true} />
          </button>

          {/* Breadcrumbs Trail */}
          {(currentProjectId || currentScanId) && (
            <div className="hidden md:flex items-center gap-1.5 text-xs text-slate-400 pl-4 border-l border-slate-800">
              <button
                onClick={onNavigateHome}
                className="hover:text-slate-200 transition-colors flex items-center gap-1"
              >
                <span>项目库</span>
              </button>

              {currentProjectId && (
                <>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
                  <button
                    onClick={() => onNavigateProject?.(currentProjectId)}
                    className={`flex items-center gap-1 max-w-[180px] truncate ${
                      !currentScanId ? 'text-brand-400 font-medium' : 'hover:text-slate-200'
                    }`}
                    title={currentProjectName || currentProjectId}
                  >
                    <FolderGit2 className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    <span className="truncate">{currentProjectName || currentProjectId.slice(0, 8)}</span>
                  </button>
                </>
              )}

              {currentScanId && (
                <>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
                  <span className="flex items-center gap-1 text-cyber-cyan font-mono font-medium">
                    <Terminal className="w-3.5 h-3.5 text-cyber-cyan/70" />
                    <span>#{currentScanId.slice(0, 8)}</span>
                  </span>
                </>
              )}
            </div>
          )}
        </div>

        {/* Right: Engine Status, Auth, Action */}
        <div className="flex items-center gap-3 shrink-0">
          {/* Engine Live Status */}
          <div
            className={`hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full text-xs border font-mono transition-colors ${
              isHealthy
                ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/50'
                : 'bg-rose-950/40 text-rose-400 border-rose-800/50'
            }`}
            title={isHealthy ? 'OpenCodeReview & LLM 运行中' : readyz?.detail || '引擎或模型未就绪'}
          >
            <Activity className="w-3.5 h-3.5" />
            {isHealthy ? (
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                OCR & LLM 就绪
              </span>
            ) : (
              <span className="flex items-center gap-1">
                <AlertCircle className="w-3.5 h-3.5" />
                服务未就绪
              </span>
            )}
          </div>

          {/* API Key Status Pill */}
          <button
            onClick={onOpenAuth}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all duration-150 ${
              hasKey
                ? 'bg-obsidian-900 border-slate-700/80 text-slate-300 hover:border-slate-500 hover:text-white'
                : 'bg-amber-500/10 border-amber-500/40 text-amber-300 hover:bg-amber-500/20 shadow-sm animate-pulse'
            }`}
            title="管理 Argus Bearer API Key"
          >
            <Key className="w-3.5 h-3.5 text-amber-400" />
            <span>{hasKey ? '凭据已连接' : '输入 API Key'}</span>
          </button>

          {/* New Project Primary CTA */}
          <button
            onClick={onOpenNewProject}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-brand-600 hover:bg-brand-500 active:bg-brand-700 text-white text-xs sm:text-sm font-medium rounded-lg shadow-glow-sm hover:shadow-glow-md transition-all duration-150"
          >
            <Plus className="w-4 h-4" />
            <span className="font-sans">新建项目</span>
          </button>
        </div>
      </div>
    </header>
  );
};

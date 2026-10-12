import React, { useState } from 'react';
import {
  FolderGit2,
  GitBranch,
  GitCommit,
  Plus,
  Search,
  RefreshCw,
  ArrowRight,
  ShieldAlert,
  Activity,
  Layers,
  Copy,
  Check,
} from 'lucide-react';
import { Project } from '../../types/api';

interface ProjectsDashboardProps {
  projects: Project[];
  total: number;
  page: number;
  pageSize: number;
  isLoading: boolean;
  onPageChange: (page: number) => void;
  onSelectProject: (projectId: string) => void;
  onOpenCreateModal: () => void;
  onRefresh: () => void;
}

export const ProjectsDashboard: React.FC<ProjectsDashboardProps> = ({
  projects,
  total,
  page,
  pageSize,
  isLoading,
  onPageChange,
  onSelectProject,
  onOpenCreateModal,
  onRefresh,
}) => {
  const [search, setSearch] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Filter projects by search
  const filtered = projects.filter((p) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return p.name.toLowerCase().includes(q) || p.repository_url.toLowerCase().includes(q) || p.branch.toLowerCase().includes(q);
  });

  const handleCopyUrl = (e: React.MouseEvent, url: string, id: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(url);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const totalVulns = projects.reduce((acc, p) => acc + (p.vulnerability_count || 0), 0);
  const activeScansCount = projects.filter((p) => !!p.active_scan_id).length;

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Metric Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Repositories */}
        <div className="argus-panel p-5 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">接入项目资产</span>
            <div className="w-8 h-8 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400">
              <FolderGit2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-slate-100">{total}</span>
            <span className="text-xs text-slate-400">个白盒仓库分支</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-brand-400" />
            <span>基于 OpenCodeReview 引擎</span>
          </div>
        </div>

        {/* Card 2: Vulnerabilities */}
        <div className="argus-panel p-5 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">已知发现漏洞</span>
            <div className="w-8 h-8 rounded-lg bg-cyber-amber/10 border border-cyber-amber/20 flex items-center justify-center text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-300">{totalVulns}</span>
            <span className="text-xs text-slate-400">处安全/质量告警</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            跨项目自动去重与状态跟踪
          </div>
        </div>

        {/* Card 3: Active Scans */}
        <div className="argus-panel p-5 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">运行中审查任务</span>
            <div className="w-8 h-8 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/20 flex items-center justify-center text-cyan-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-300">{activeScansCount}</span>
            <span className="text-xs text-slate-400">个队列/分析进程</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500 flex items-center gap-1">
            {activeScansCount > 0 ? (
              <span className="flex items-center gap-1 text-cyan-400">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                正在执行审查流水线
              </span>
            ) : (
              <span>单机执行槽位空闲</span>
            )}
          </div>
        </div>

        {/* Card 4: Baseline Coverage */}
        <div className="argus-panel p-5 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">基线分析机制</span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-indigo-300">
              {projects.filter((p) => !!p.baseline_commit).length}
            </span>
            <span className="text-xs text-slate-400">/ {projects.length} 已建立基准</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            仅完整扫描成功后推进基线
          </div>
        </div>
      </div>

      {/* Toolbar: Search, Filters & Actions */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索项目名称、Git 仓库地址或分支..."
            className="w-full pl-10 pr-4 py-2 bg-obsidian-900 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 font-mono transition-colors"
          />
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-2 bg-obsidian-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs text-slate-300 hover:text-white transition-colors"
            title="刷新项目列表"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>刷新</span>
          </button>

          <button
            onClick={onOpenCreateModal}
            className="flex items-center gap-1.5 px-4 py-2 bg-brand-600 hover:bg-brand-500 active:bg-brand-700 text-white rounded-xl text-xs font-medium shadow-glow-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>新建项目</span>
          </button>
        </div>
      </div>

      {/* Project Cards Grid */}
      {filtered.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filtered.map((p) => {
            const hasBaseline = !!p.baseline_commit;
            const isScanning = !!p.active_scan_id;

            return (
              <div
                key={p.id}
                onClick={() => onSelectProject(p.id)}
                className="argus-panel-interactive p-5 flex flex-col justify-between cursor-pointer group hover:border-brand-500/40 relative overflow-hidden"
              >
                {/* Active scan subtle top indicator bar */}
                {isScanning && (
                  <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-brand-400 via-cyber-cyan to-indigo-500 animate-pulse" />
                )}

                <div>
                  {/* Top: Title & Active Badge */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <FolderGit2 className="w-4 h-4 text-brand-400 shrink-0" />
                        <h3 className="font-semibold text-sm text-slate-100 truncate group-hover:text-brand-300 transition-colors">
                          {p.name}
                        </h3>
                      </div>
                    </div>

                    {isScanning && (
                      <span className="argus-badge bg-cyan-950/50 text-cyan-400 border-cyan-800/60 shrink-0">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                        审查中
                      </span>
                    )}
                  </div>

                  {/* Repository URL */}
                  <div className="mt-2.5 flex items-center justify-between gap-2 text-xs font-mono text-slate-400 bg-obsidian-950/70 px-2.5 py-1.5 rounded-lg border border-slate-800/80">
                    <span className="truncate" title={p.repository_url}>
                      {p.repository_url}
                    </span>
                    <button
                      onClick={(e) => handleCopyUrl(e, p.repository_url, p.id)}
                      className="text-slate-500 hover:text-slate-300 p-0.5 rounded transition-colors"
                      title="复制仓库地址"
                    >
                      {copiedId === p.id ? (
                        <Check className="w-3.5 h-3.5 text-brand-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>

                  {/* Branch & Baseline Status */}
                  <div className="mt-3 flex items-center gap-2 flex-wrap text-xs">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60 font-mono">
                      <GitBranch className="w-3 h-3 text-slate-400" />
                      {p.branch}
                    </span>

                    {hasBaseline ? (
                      <span
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/50 font-mono"
                        title={`已固化完整基线: ${p.baseline_commit}`}
                      >
                        <GitCommit className="w-3 h-3 text-emerald-500" />
                        基线: {p.baseline_commit?.slice(0, 7)}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 font-mono">
                        待首次全仓扫描
                      </span>
                    )}
                  </div>

                  {/* Business Background snippet if present */}
                  {p.background && (
                    <p className="mt-3 text-xs text-slate-400 line-clamp-2 italic bg-obsidian-950/40 p-2 rounded-md border border-slate-800/50">
                      “{p.background}”
                    </p>
                  )}
                </div>

                {/* Bottom: Vulnerabilities Count & Enter Arrow */}
                <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5">
                    <span className="text-slate-400">漏洞数:</span>
                    <span
                      className={`font-mono font-semibold ${
                        (p.vulnerability_count || 0) > 0 ? 'text-amber-400' : 'text-slate-400'
                      }`}
                    >
                      {p.vulnerability_count || 0}
                    </span>
                  </div>

                  <span className="text-brand-400 flex items-center gap-1 group-hover:translate-x-0.5 transition-transform font-medium">
                    <span>进入控制台</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* Empty State */
        <div className="argus-panel p-16 text-center space-y-5 max-w-xl mx-auto">
          <div className="w-16 h-16 rounded-2xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 mx-auto shadow-glow-sm">
            <FolderGit2 className="w-8 h-8" />
          </div>
          <div className="space-y-1.5">
            <h3 className="text-lg font-semibold text-slate-100">
              {search ? '未找到符合条件的仓库项目' : '尚未接入任何代码项目'}
            </h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
              {search
                ? '尝试更换搜索关键词，或清除搜索框。'
                : 'Argus 通过白盒语法树与 OpenCodeReview 深度审查代码。输入 Git 仓库与分支，开始自动化安全扫描。'}
            </p>
          </div>
          {search ? (
            <button
              onClick={() => setSearch('')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 rounded-xl transition-colors font-mono"
            >
              清除搜索
            </button>
          ) : (
            <button
              onClick={onOpenCreateModal}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-brand-600 hover:bg-brand-500 text-white rounded-xl text-xs font-medium shadow-glow-sm transition-all"
            >
              <Plus className="w-4 h-4" />
              <span>添加第一个代码仓库</span>
            </button>
          )}
        </div>
      )}

      {/* Pagination */}
      {total > pageSize && (
        <div className="flex items-center justify-between pt-4 border-t border-slate-800 text-xs text-slate-400 font-mono">
          <span>
            显示 {(page - 1) * pageSize + 1} - {Math.min(page * pageSize, total)} 共 {total} 条
          </span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => onPageChange(page - 1)}
              className="px-3 py-1.5 bg-obsidian-900 border border-slate-800 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              上一页
            </button>
            <button
              disabled={page * pageSize >= total}
              onClick={() => onPageChange(page + 1)}
              className="px-3 py-1.5 bg-obsidian-900 border border-slate-800 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              下一页
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

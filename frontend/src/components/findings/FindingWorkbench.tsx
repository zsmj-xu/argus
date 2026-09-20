import React, { useState, useEffect } from 'react';
import {
  Shield,
  Search,
  FileCode2,
  ChevronRight,
  ChevronLeft,
} from 'lucide-react';
import { useFindings } from '../../hooks/useFindings';
import {
  CodeEvidenceViewer,
  SEVERITY_CONFIG,
  getCategoryLabel,
} from './CodeEvidenceViewer';

interface FindingWorkbenchProps {
  scanId: string;
}

const SEVERITY_TABS = [
  { key: 'all', label: '全部' },
  { key: 'critical', label: '严重 (Critical)' },
  { key: 'high', label: '高危 (High)' },
  { key: 'medium', label: '中危 (Medium)' },
  { key: 'low', label: '低危 (Low)' },
  { key: 'unknown', label: '未知 (Unknown)' },
] as const;

export const FindingWorkbench: React.FC<FindingWorkbenchProps> = ({ scanId }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [isMobileDrawerOpen, setIsMobileDrawerOpen] = useState(false);

  const {
    findings,
    total,
    page,
    setPage,
    pageSize,
    totalPages,
    isLoading,
  } = useFindings(scanId, {
    severity: selectedSeverity === 'all' ? undefined : selectedSeverity,
    pageSize: 50,
  });

  // Filter on current loaded page
  const filteredFindings = findings.filter((f) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      (f.title && f.title.toLowerCase().includes(q)) ||
      (f.rule_id && f.rule_id.toLowerCase().includes(q)) ||
      (f.file && f.file.toLowerCase().includes(q)) ||
      (f.message && f.message.toLowerCase().includes(q)) ||
      (f.category && f.category.toLowerCase().includes(q))
    );
  });

  // Ensure active finding is always valid
  const activeFinding =
    filteredFindings.find((f) => f.id === selectedFindingId) ||
    filteredFindings[0] ||
    null;

  // Handle ESC key for mobile drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isMobileDrawerOpen) {
        setIsMobileDrawerOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMobileDrawerOpen]);

  // Lock body scroll when mobile drawer is open
  useEffect(() => {
    if (isMobileDrawerOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isMobileDrawerOpen]);

  const handleSelectFinding = (id: string) => {
    setSelectedFindingId(id);
    // On small screen, open mobile drawer
    if (window.innerWidth < 768) {
      setIsMobileDrawerOpen(true);
    }
  };

  const handleSeverityChange = (sev: string) => {
    setSelectedSeverity(sev);
    setSelectedFindingId(null);
    setSearchQuery('');
  };

  const startRecord = total > 0 ? (page - 1) * pageSize + 1 : 0;
  const endRecord = Math.min(page * pageSize, total);

  return (
    <div className="space-y-4">
      {/* Header & Filter Toolbar */}
      <div className="flex items-center justify-between gap-4 flex-wrap bg-zinc-900/60 p-4 rounded-xl border border-zinc-800">
        <div className="flex items-center gap-2 flex-wrap">
          <Shield className="w-5 h-5 text-emerald-400" />
          <h3 className="font-semibold text-sm text-zinc-100">
            静态发现工作台 (Static Findings)
          </h3>
          <span className="text-xs font-mono text-zinc-400 bg-zinc-800 px-2 py-0.5 rounded">
            共 {total} 处告警
          </span>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Search bar */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="搜索标题/规则/文件/说明..."
              className="pl-8 pr-3 py-1 bg-zinc-950 border border-zinc-800 rounded-lg text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 w-52 font-mono"
            />
          </div>

          {/* Severity Tabs with Chinese Labels */}
          <div
            className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs overflow-x-auto"
            role="tablist"
            aria-label="按风险等级筛选"
          >
            {SEVERITY_TABS.map((tab) => {
              const isSelected = selectedSeverity === tab.key;
              return (
                <button
                  key={tab.key}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  onClick={() => handleSeverityChange(tab.key)}
                  className={`px-3 py-1 rounded whitespace-nowrap font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 ${
                    isSelected
                      ? 'bg-zinc-800 text-zinc-100 shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Search Scope Notice */}
      {searchQuery.trim() && (
        <div className="px-4 py-2 bg-zinc-950/80 border border-zinc-800/80 rounded-lg text-xs text-zinc-400 flex items-center justify-between gap-2 flex-wrap">
          <span>
            当前第 <span className="font-mono text-zinc-200">{page}</span> 页匹配到{' '}
            <span className="font-mono text-emerald-400 font-bold">
              {filteredFindings.length}
            </span>{' '}
            条（本页已加载 {findings.length} 条，扫描总计 {total} 条）
          </span>
          {totalPages > 1 && (
            <span className="text-[11px] text-zinc-500">
              提示：搜索作用于当前已加载页。若未检索到，可切换下方页码查看。
            </span>
          )}
        </div>
      )}

      {/* Main Split View (768px md:grid-cols-12 Dual Column) */}
      {filteredFindings.length === 0 && !isLoading ? (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl bg-zinc-900/30 space-y-2">
          <FileCode2 className="w-10 h-10 text-zinc-600 mx-auto mb-1" />
          <p className="text-sm font-medium text-zinc-300">当前筛选条件下未找到静态发现</p>
          <p className="text-xs text-zinc-500">
            {searchQuery
              ? '尝试修改或清空搜索关键词'
              : '当前风险等级下没有记录，可切换至“全部”查看'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-start">
          {/* Left Column: Finding Cards List (md:col-span-5) */}
          <div className="md:col-span-5 space-y-3">
            <div
              className="space-y-2.5 max-h-[720px] overflow-y-auto pr-1"
              role="tablist"
              aria-label="静态告警发现列表"
            >
              {filteredFindings.map((finding) => {
                const isSelected = activeFinding?.id === finding.id;
                const sevKey = (finding.severity || 'unknown').toLowerCase();
                const sevCfg = SEVERITY_CONFIG[sevKey] || SEVERITY_CONFIG.unknown;
                const catInfo = getCategoryLabel(finding.category);

                return (
                  <button
                    key={finding.id}
                    type="button"
                    role="tab"
                    id={`finding-tab-${finding.id}`}
                    aria-selected={isSelected}
                    aria-controls="finding-detail-pane"
                    tabIndex={0}
                    onClick={() => handleSelectFinding(finding.id)}
                    className={`text-left w-full block p-3.5 rounded-xl border transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 ${
                      isSelected
                        ? 'bg-zinc-900 border-emerald-500/60 ring-1 ring-emerald-500/20 shadow-md'
                        : 'bg-zinc-900/40 border-zinc-800/80 hover:bg-zinc-900/80 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <span
                        className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border font-mono ${sevCfg.color}`}
                      >
                        {sevCfg.badge}
                      </span>
                      <span className="text-[11px] font-mono text-zinc-500 truncate max-w-[150px]">
                        {finding.rule_id}
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-zinc-200 line-clamp-2 mb-1.5 leading-snug">
                      {finding.title}
                    </h4>

                    <div className="flex items-center justify-between text-[11px] text-zinc-400 font-mono mt-2">
                      <span className="truncate max-w-[200px]" title={finding.file || ''}>
                        {finding.file || '跨文件/架构发现'}
                        {finding.start_line ? `:${finding.start_line}` : ''}
                      </span>
                      <span className="text-[10px] text-zinc-500 bg-zinc-950 px-1.5 py-0.5 rounded border border-zinc-800">
                        {catInfo.display}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Pagination Controls */}
            {total > pageSize && (
              <div className="flex items-center justify-between bg-zinc-900/60 border border-zinc-800 rounded-lg p-2.5 text-xs text-zinc-400 font-mono">
                <span>
                  显示 {startRecord}-{endRecord} 条，共 {total} 条
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    disabled={page <= 1 || isLoading}
                    onClick={() => {
                      setPage(page - 1);
                      setSelectedFindingId(null);
                    }}
                    className="p-1.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    title="上一页"
                    aria-label="上一页"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <span className="px-2 font-medium text-zinc-200">
                    {page} / {totalPages}
                  </span>
                  <button
                    type="button"
                    disabled={page >= totalPages || isLoading}
                    onClick={() => {
                      setPage(page + 1);
                      setSelectedFindingId(null);
                    }}
                    className="p-1.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    title="下一页"
                    aria-label="下一页"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Active Finding Detail (Desktop/Tablet >= 768px) */}
          <div
            id="finding-detail-pane"
            role="tabpanel"
            aria-labelledby={activeFinding ? `finding-tab-${activeFinding.id}` : undefined}
            className="hidden md:block md:col-span-7 sticky top-20"
          >
            {activeFinding ? (
              <CodeEvidenceViewer finding={activeFinding} />
            ) : (
              <div className="text-center py-24 text-zinc-500 text-xs bg-zinc-900/40 rounded-xl border border-zinc-800">
                请在左侧列表选择要查看的告警详情
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mobile Drawer / Dialog (< 768px) */}
      {isMobileDrawerOpen && activeFinding && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`告警详情：${activeFinding.title}`}
          className="fixed inset-0 z-50 md:hidden flex items-end sm:items-center justify-center bg-black/80 backdrop-blur-sm p-2 sm:p-4 animate-in fade-in duration-200"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setIsMobileDrawerOpen(false);
            }
          }}
        >
          <div className="w-full max-h-[85vh] bg-zinc-900 border border-zinc-800 rounded-t-2xl sm:rounded-2xl shadow-2xl overflow-y-auto p-1 animate-in slide-in-from-bottom-5 duration-200">
            <CodeEvidenceViewer
              finding={activeFinding}
              onClose={() => setIsMobileDrawerOpen(false)}
            />
          </div>
        </div>
      )}
    </div>
  );
};

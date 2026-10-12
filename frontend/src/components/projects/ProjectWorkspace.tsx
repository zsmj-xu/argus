import React, { useState } from 'react';
import {
  FolderGit2,
  GitBranch,
  GitCommit,
  Play,
  RotateCw,
  Settings,
  Download,
  ShieldCheck,
  ShieldAlert,
  Search,
  ChevronDown,
  ChevronRight,
  Code2,
  FileCode,
  Wrench,
  Check,
  Copy,
  Terminal,
  Clock,
  Layers,
  Ban,
} from 'lucide-react';
import {
  Project,
  ScanResponse,
  Vulnerability,
  VulnerabilityStatus,
  ReportFormat,
} from '../../types/api';
import { StatusBadge } from '../scan/ScanList';
import { formatDate, truncateSha } from '../../lib/utils';
import { SEVERITY_CONFIG } from '../findings/CodeEvidenceViewer';

interface ProjectWorkspaceProps {
  project: Project;
  scans: ScanResponse[];
  scansTotal: number;
  scanPage: number;
  vulnerabilities: Vulnerability[];
  vulnsTotal: number;
  vulnPage: number;
  isLoading: boolean;
  busy: boolean;
  activeTab: 'vulnerabilities' | 'scans' | 'scope';
  onTabChange: (tab: 'vulnerabilities' | 'scans' | 'scope') => void;
  onScanPageChange: (page: number) => void;
  onVulnPageChange: (page: number) => void;
  onFilterChange: (filters: {
    status?: string;
    severity?: string;
    category?: string;
    search?: string;
  }) => void;
  onStartScan: (mode: 'auto' | 'full') => Promise<void>;
  onCancelScan: (scanId: string) => Promise<void>;
  onRetryScan: (scanId: string) => Promise<void>;
  onSelectScan: (scanId: string) => void;
  onUpdateVulnStatus: (vulnId: string, status: VulnerabilityStatus) => Promise<void>;
  onOpenEditModal: () => void;
  onDownloadReport: (format: ReportFormat) => Promise<void>;
  onRefresh: () => void;
}

const STATUS_LABELS: Record<VulnerabilityStatus, { label: string; color: string }> = {
  open: { label: '待处理 (Open)', color: 'text-rose-400 bg-rose-950/40 border-rose-800' },
  in_progress: { label: '处理中 (In Progress)', color: 'text-sky-400 bg-sky-950/40 border-sky-800' },
  fixed: { label: '已修复 (Fixed)', color: 'text-emerald-400 bg-emerald-950/40 border-emerald-800' },
  false_positive: { label: '误报 (False Positive)', color: 'text-slate-400 bg-slate-900 border-slate-700' },
  accepted_risk: { label: '接受风险 (Accepted)', color: 'text-purple-400 bg-purple-950/40 border-purple-800' },
};

const CATEGORY_NAMES: Record<string, string> = {
  security: '安全缺陷',
  correctness: '正确性逻辑',
  performance: '性能损耗',
  maintainability: '代码可维护性',
  style: '规范风格',
};

export const ProjectWorkspace: React.FC<ProjectWorkspaceProps> = ({
  project,
  scans,
  scansTotal,
  scanPage,
  vulnerabilities,
  vulnsTotal,
  vulnPage,
  isLoading,
  busy,
  activeTab,
  onTabChange,
  onScanPageChange,
  onVulnPageChange,
  onFilterChange,
  onStartScan,
  onCancelScan,
  onRetryScan,
  onSelectScan,
  onUpdateVulnStatus,
  onOpenEditModal,
  onDownloadReport,
  onRefresh,
}) => {
  const [disclosureConfirmed, setDisclosureConfirmed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [expandedVulnId, setExpandedVulnId] = useState<string | null>(null);
  const [copiedRemediationId, setCopiedRemediationId] = useState<string | null>(null);
  const [isExportMenuOpen, setIsExportMenuOpen] = useState(false);

  const hasBaseline = !!project.baseline_commit;
  const isScanning = !!project.active_scan_id;

  const handleFilterUpdate = (newFilters: {
    status?: string;
    severity?: string;
    category?: string;
    search?: string;
  }) => {
    onFilterChange({
      status: newFilters.status !== undefined ? newFilters.status : statusFilter,
      severity: newFilters.severity !== undefined ? newFilters.severity : severityFilter,
      category: newFilters.category !== undefined ? newFilters.category : categoryFilter,
      search: newFilters.search !== undefined ? newFilters.search : searchQuery,
    });
  };

  const handleCopyRemediation = (e: React.MouseEvent, id: string, text: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedRemediationId(id);
    setTimeout(() => setCopiedRemediationId(null), 2000);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Project Hero Header */}
      <div className="argus-panel p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-xl sm:text-2xl font-bold text-slate-100 flex items-center gap-2">
                <FolderGit2 className="w-6 h-6 text-brand-400 shrink-0" />
                <span>{project.name}</span>
              </h1>

              {isScanning && (
                <span className="argus-badge bg-cyan-950/60 text-cyan-400 border-cyan-800/80">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                  分析执行中
                </span>
              )}
            </div>

            {/* Git Metadata Line */}
            <div className="flex items-center gap-2.5 text-xs font-mono text-slate-400 flex-wrap">
              <span className="text-slate-300 bg-obsidian-950 px-2.5 py-1 rounded-md border border-slate-800 select-all">
                {project.repository_url}
              </span>

              <span className="inline-flex items-center gap-1 bg-obsidian-950 px-2 py-1 rounded-md border border-slate-800 text-slate-300">
                <GitBranch className="w-3.5 h-3.5 text-brand-400" />
                {project.branch}
              </span>

              {hasBaseline ? (
                <span
                  className="inline-flex items-center gap-1 bg-emerald-950/40 text-emerald-300 px-2 py-1 rounded-md border border-emerald-800/50"
                  title="只有完整无跳过、无失败的扫描才会推进基线。增量扫描仅对基线与最新提交的累积 diff 进行审查。"
                >
                  <GitCommit className="w-3.5 h-3.5 text-emerald-400" />
                  基线: {truncateSha(project.baseline_commit)}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 bg-obsidian-950 text-slate-400 px-2 py-1 rounded-md border border-slate-800">
                  待首次全仓扫描
                </span>
              )}
            </div>
          </div>

          {/* Top Actions: Settings & Export Report */}
          <div className="flex items-center gap-2.5 self-start lg:self-center shrink-0">
            <button
              onClick={onOpenEditModal}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-obsidian-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs text-slate-300 hover:text-white transition-colors"
            >
              <Settings className="w-3.5 h-3.5 text-slate-400" />
              <span>项目配置</span>
            </button>

            {/* Export Dropdown */}
            <div className="relative">
              <button
                onClick={() => setIsExportMenuOpen(!isExportMenuOpen)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-obsidian-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-xs text-slate-300 hover:text-white transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-slate-400" />
                <span>导出项目报告</span>
                <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
              </button>

              {isExportMenuOpen && (
                <div className="absolute right-0 mt-2 w-48 bg-obsidian-900 border border-slate-700/80 rounded-xl shadow-xl py-1.5 z-20 text-xs animate-in fade-in duration-100">
                  {(['markdown', 'sarif', 'json'] as ReportFormat[]).map((fmt) => (
                    <button
                      key={fmt}
                      disabled={busy}
                      onClick={() => {
                        setIsExportMenuOpen(false);
                        void onDownloadReport(fmt);
                      }}
                      className="w-full text-left px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-800/80 transition-colors flex items-center justify-between"
                    >
                      <span className="capitalize">{fmt === 'markdown' ? 'Markdown (.md)' : fmt.toUpperCase()}</span>
                      <Download className="w-3 h-3 text-slate-500" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Business background if present */}
        {project.background && (
          <div className="text-xs text-slate-300 bg-obsidian-950/70 p-3 rounded-xl border border-slate-800/80 leading-relaxed">
            <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">
              业务背景与审查提示 (Context)
            </span>
            {project.background}
          </div>
        )}

        {/* Scan Trigger Bar */}
        <div className="pt-4 border-t border-slate-800/80 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-obsidian-950/40 -mx-6 -mb-6 p-4 rounded-b-xl">
          {/* Disclosure Checkbox */}
          <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={disclosureConfirmed}
              onChange={(e) => setDisclosureConfirmed(e.target.checked)}
              className="mt-0.5 rounded border-slate-700 bg-obsidian-950 text-brand-500 focus:ring-brand-500/30"
            />
            <span className="leading-snug">
              我已获准将本次选中的源码文件发送给服务配置的 LLM 模型 (Source Disclosure Authorization)
            </span>
          </label>

          {/* Trigger Buttons */}
          <div className="flex items-center gap-2.5 self-end md:self-auto shrink-0">
            {isScanning ? (
              <span className="text-xs text-cyan-400 font-mono flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/60">
                <RotateCw className="w-3.5 h-3.5 animate-spin" />
                正在执行审查流水线
              </span>
            ) : (
              <>
                <button
                  disabled={!disclosureConfirmed || busy}
                  onClick={() => onStartScan('auto')}
                  className="flex items-center gap-1.5 px-4 py-2 bg-brand-600 hover:bg-brand-500 active:bg-brand-700 text-white rounded-xl text-xs font-medium shadow-glow-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  title={
                    !disclosureConfirmed
                      ? '请先勾选代码披露授权'
                      : hasBaseline
                      ? '对比最新提交与已建立的基线，仅审查增量变更'
                      : '首次分析分支最新提交'
                  }
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{hasBaseline ? '增量分析 (推荐)' : '首次全仓分析'}</span>
                </button>

                {hasBaseline && (
                  <button
                    disabled={!disclosureConfirmed || busy}
                    onClick={() => onStartScan('full')}
                    className="flex items-center gap-1.5 px-3 py-2 bg-obsidian-900 hover:bg-slate-800 border border-slate-700/80 rounded-xl text-xs text-slate-300 hover:text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    title="重新全仓分析并刷新基线"
                  >
                    <span>重新全仓分析</span>
                  </button>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Main Tabs Navigation */}
      <div className="flex items-center justify-between gap-4 border-b border-slate-800">
        <div className="flex items-center gap-1">
          <button
            onClick={() => onTabChange('vulnerabilities')}
            className={`flex items-center gap-2 px-5 py-3 text-xs font-semibold border-b-2 transition-all ${
              activeTab === 'vulnerabilities'
                ? 'border-brand-500 text-brand-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>项目漏洞治理库</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-300">
              {vulnsTotal}
            </span>
          </button>

          <button
            onClick={() => onTabChange('scans')}
            className={`flex items-center gap-2 px-5 py-3 text-xs font-semibold border-b-2 transition-all ${
              activeTab === 'scans'
                ? 'border-brand-500 text-brand-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>扫描历史记录</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-300">
              {scansTotal}
            </span>
          </button>

          <button
            onClick={() => onTabChange('scope')}
            className={`flex items-center gap-2 px-5 py-3 text-xs font-semibold border-b-2 transition-all ${
              activeTab === 'scope'
                ? 'border-brand-500 text-brand-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>扫描范围与配置</span>
          </button>
        </div>

        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="p-1.5 text-slate-400 hover:text-slate-200 transition-colors"
          title="刷新项目数据"
        >
          <RotateCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Tab 1: Vulnerabilities Backlog */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="argus-panel p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2.5 flex-1 max-w-sm">
              <div className="relative w-full">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    handleFilterUpdate({ search: e.target.value });
                  }}
                  placeholder="搜索漏洞标题、规则或代码文件..."
                  className="w-full pl-9 pr-3 py-1.5 bg-obsidian-950 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-brand-500 font-mono"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {/* Status Filter */}
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  handleFilterUpdate({ status: e.target.value });
                }}
                className="bg-obsidian-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-brand-500"
              >
                <option value="">全部处理状态</option>
                {Object.entries(STATUS_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v.label}
                  </option>
                ))}
              </select>

              {/* Severity Filter */}
              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  handleFilterUpdate({ severity: e.target.value });
                }}
                className="bg-obsidian-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-brand-500"
              >
                <option value="">全部风险等级</option>
                {Object.entries(SEVERITY_CONFIG).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v.label}
                  </option>
                ))}
              </select>

              {/* Category Filter */}
              <select
                value={categoryFilter}
                onChange={(e) => {
                  setCategoryFilter(e.target.value);
                  handleFilterUpdate({ category: e.target.value });
                }}
                className="bg-obsidian-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-brand-500"
              >
                <option value="">全部缺陷分类</option>
                {Object.entries(CATEGORY_NAMES).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v} ({k})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Vulnerability Items List */}
          {vulnerabilities.length > 0 ? (
            <div className="space-y-3">
              {vulnerabilities.map((v) => {
                const isExpanded = expandedVulnId === v.id;
                const sevKey = (v.severity || 'unknown').toLowerCase();
                const sevInfo = SEVERITY_CONFIG[sevKey] || SEVERITY_CONFIG.unknown;
                const statusInfo = STATUS_LABELS[v.status] || STATUS_LABELS.open;
                const categoryLabel = CATEGORY_NAMES[v.category?.toLowerCase()] || v.category || '常规';

                return (
                  <div
                    key={v.id}
                    className={`argus-panel transition-all ${
                      isExpanded ? 'border-brand-500/40 bg-obsidian-900' : 'hover:border-slate-700/80'
                    }`}
                  >
                    {/* Item Row Header */}
                    <div
                      onClick={() => setExpandedVulnId(isExpanded ? null : v.id)}
                      className="p-4 cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                    >
                      <div className="flex items-start gap-3 min-w-0 flex-1">
                        <ChevronRight
                          className={`w-4 h-4 text-slate-500 shrink-0 mt-0.5 transition-transform duration-200 ${
                            isExpanded ? 'rotate-90 text-brand-400' : ''
                          }`}
                        />
                        <div className="space-y-1.5 min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap text-xs">
                            <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${sevInfo.color}`}>
                              {sevInfo.badge}
                            </span>
                            <span className="text-slate-400 bg-obsidian-950 px-2 py-0.5 rounded border border-slate-800 font-mono text-[11px]">
                              {categoryLabel}
                            </span>
                            {v.file && (
                              <span className="font-mono text-[11px] text-brand-400 flex items-center gap-1 truncate max-w-md">
                                <FileCode className="w-3 h-3 text-slate-500 shrink-0" />
                                <span>
                                  {v.file}
                                  {v.start_line ? `:${v.start_line}` : ''}
                                </span>
                              </span>
                            )}
                          </div>
                          <h4 className="font-semibold text-sm text-slate-100 leading-snug break-words">
                            {v.title}
                          </h4>
                        </div>
                      </div>

                      {/* Right: Triaging Status Select Dropdown */}
                      <div
                        className="flex items-center gap-2 shrink-0 self-end sm:self-auto"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <select
                          value={v.status}
                          disabled={busy}
                          onChange={(e) =>
                            void onUpdateVulnStatus(v.id, e.target.value as VulnerabilityStatus)
                          }
                          className={`text-xs font-mono font-medium rounded-lg px-2.5 py-1 border transition-colors focus:outline-none ${statusInfo.color}`}
                        >
                          {Object.entries(STATUS_LABELS).map(([statusKey, cfg]) => (
                            <option key={statusKey} value={statusKey} className="bg-obsidian-950 text-slate-200">
                              {cfg.label}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    {/* Expandable Code Evidence & Remediation Drawer */}
                    {isExpanded && (
                      <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 space-y-4 bg-obsidian-950/60 rounded-b-xl animate-in fade-in duration-150">
                        {/* Message Description */}
                        {v.message && (
                          <div className="space-y-1">
                            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                              漏洞说明与影响
                            </div>
                            <p className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed bg-obsidian-950 p-3 rounded-lg border border-slate-800">
                              {v.message}
                            </p>
                          </div>
                        )}

                        {/* Code Evidence snippet */}
                        {v.evidence ? (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                              <span className="flex items-center gap-1.5">
                                <Code2 className="w-3.5 h-3.5 text-cyber-cyan" />
                                <span>静态源码证据</span>
                              </span>
                              {v.start_line && (
                                <span className="font-mono text-slate-500 text-[10px]">
                                  行号: {v.start_line}
                                  {v.end_line && v.end_line !== v.start_line ? ` - ${v.end_line}` : ''}
                                </span>
                              )}
                            </div>
                            <pre className="p-3.5 bg-obsidian-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
                              <code>{v.evidence}</code>
                            </pre>
                          </div>
                        ) : null}

                        {/* Remediation Guide */}
                        {v.remediation ? (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-brand-400">
                              <span className="flex items-center gap-1.5">
                                <Wrench className="w-3.5 h-3.5" />
                                <span>修复建议与参考实现</span>
                              </span>
                              <button
                                onClick={(e) => handleCopyRemediation(e, v.id, v.remediation)}
                                className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 bg-obsidian-900 px-2 py-0.5 rounded border border-slate-800 transition-colors"
                              >
                                {copiedRemediationId === v.id ? (
                                  <>
                                    <Check className="w-3 h-3 text-brand-400" />
                                    <span className="text-brand-400">已复制</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    <span>复制建议</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <pre className="p-3.5 bg-brand-950/20 rounded-lg border border-brand-800/30 text-xs font-mono text-brand-200/90 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                              <code>{v.remediation}</code>
                            </pre>
                          </div>
                        ) : null}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="argus-panel p-12 text-center space-y-3">
              <ShieldCheck className="w-10 h-10 text-brand-400 mx-auto" />
              <h4 className="text-sm font-semibold text-slate-200">暂无符合条件的漏洞项</h4>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                {searchQuery || statusFilter || severityFilter
                  ? '当前筛选条件未匹配到告警项，请尝试清除过滤器。'
                  : '项目暂未记录到开放漏洞。完成一次白盒审查后漏洞将自动归档于此。'}
              </p>
            </div>
          )}

          {/* Vulnerability Pagination */}
          {vulnsTotal > 20 && (
            <div className="flex items-center justify-between pt-4 border-t border-slate-800 text-xs text-slate-400 font-mono">
              <span>
                显示 {(vulnPage - 1) * 20 + 1} - {Math.min(vulnPage * 20, vulnsTotal)} 共 {vulnsTotal} 条
              </span>
              <div className="flex gap-2">
                <button
                  disabled={vulnPage <= 1}
                  onClick={() => onVulnPageChange(vulnPage - 1)}
                  className="px-3 py-1.5 bg-obsidian-900 border border-slate-800 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-40"
                >
                  上一页
                </button>
                <button
                  disabled={vulnPage * 20 >= vulnsTotal}
                  onClick={() => onVulnPageChange(vulnPage + 1)}
                  className="px-3 py-1.5 bg-obsidian-900 border border-slate-800 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-40"
                >
                  下一页
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Scan History */}
      {activeTab === 'scans' && (
        <div className="space-y-4">
          {scans.length > 0 ? (
            <div className="space-y-3">
              {scans.map((s) => {
                const isActive = ['queued', 'running'].includes(s.status);
                const canCancel = isActive;
                const canRetry = ['failed', 'partial', 'canceled'].includes(s.status);

                return (
                  <div
                    key={s.id}
                    onClick={() => onSelectScan(s.id)}
                    className="argus-panel-interactive p-4 cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 group hover:border-brand-500/40"
                  >
                    <div className="space-y-2 min-w-0 flex-1">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <StatusBadge status={s.status} phase={s.observation?.stage || s.phase} />

                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-obsidian-950 text-slate-400 border border-slate-800">
                          {s.scan_type === 'incremental' ? '增量分析' : '全仓分析'}
                        </span>

                        <span className="text-xs font-mono text-slate-500">
                          ID: <span className="text-slate-400">{s.id.slice(0, 8)}</span>
                        </span>
                      </div>

                      {/* Commit Range */}
                      <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                        <GitCommit className="w-3.5 h-3.5 text-slate-500" />
                        <span>
                          {s.base_commit ? truncateSha(s.base_commit) : '全仓起点'} →{' '}
                          {s.commit_sha ? truncateSha(s.commit_sha) : '待拉取最新版本'}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 text-xs text-slate-500">
                        <span>{formatDate(s.created_at)}</span>
                        <span>·</span>
                        <span className="font-mono text-slate-400">
                          发现 {s.finding_count} 处告警
                        </span>
                      </div>
                    </div>

                    {/* Actions on Scan Row */}
                    <div
                      className="flex items-center gap-2 shrink-0 self-end sm:self-auto"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {canCancel && (
                        <button
                          onClick={() => onCancelScan(s.id)}
                          className="flex items-center gap-1 px-3 py-1 bg-rose-950/40 border border-rose-800 text-rose-300 text-xs rounded-lg hover:bg-rose-900/50 transition-colors"
                        >
                          <Ban className="w-3.5 h-3.5" />
                          <span>取消</span>
                        </button>
                      )}

                      {canRetry && (
                        <button
                          onClick={() => onRetryScan(s.id)}
                          className="flex items-center gap-1 px-3 py-1 bg-obsidian-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded-lg transition-colors"
                        >
                          <RotateCw className="w-3.5 h-3.5 text-brand-400" />
                          <span>重试</span>
                        </button>
                      )}

                      <button
                        onClick={() => onSelectScan(s.id)}
                        className="flex items-center gap-1 px-3 py-1 bg-brand-600 hover:bg-brand-500 text-white text-xs font-medium rounded-lg transition-colors"
                      >
                        <Terminal className="w-3.5 h-3.5" />
                        <span>查看实时详情</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="argus-panel p-12 text-center space-y-3">
              <Clock className="w-10 h-10 text-slate-500 mx-auto" />
              <h4 className="text-sm font-semibold text-slate-200">暂无扫描执行记录</h4>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                确认源码披露授权后，点击上方“首次全仓分析”启动初次审查。
              </p>
            </div>
          )}

          {/* Scan Pagination */}
          {scansTotal > 20 && (
            <div className="flex items-center justify-between pt-4 border-t border-slate-800 text-xs text-slate-400 font-mono">
              <span>
                显示 {(scanPage - 1) * 20 + 1} - {Math.min(scanPage * 20, scansTotal)} 共 {scansTotal} 条
              </span>
              <div className="flex gap-2">
                <button
                  disabled={scanPage <= 1}
                  onClick={() => onScanPageChange(scanPage - 1)}
                  className="px-3 py-1.5 bg-obsidian-900 border border-slate-800 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-40"
                >
                  上一页
                </button>
                <button
                  disabled={scanPage * 20 >= scansTotal}
                  onClick={() => onScanPageChange(scanPage + 1)}
                  className="px-3 py-1.5 bg-obsidian-900 border border-slate-800 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-40"
                >
                  下一页
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Scope & Settings */}
      {activeTab === 'scope' && (
        <div className="argus-panel p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">白盒审查规则与路径范围</h3>
              <p className="text-xs text-slate-400 mt-0.5">控制送审至 OpenCodeReview 引擎的文件路径模式</p>
            </div>
            <button
              onClick={onOpenEditModal}
              className="px-3 py-1.5 bg-obsidian-900 hover:bg-slate-800 border border-slate-700 text-xs text-slate-200 rounded-xl transition-colors"
            >
              修改规则
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-obsidian-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-brand-400">
                包含路径 (Include Patterns)
              </span>
              {project.include.length > 0 ? (
                <ul className="space-y-1">
                  {project.include.map((pat, idx) => (
                    <li key={idx} className="text-xs font-mono text-slate-300 bg-obsidian-900 px-2.5 py-1 rounded border border-slate-800/80">
                      {pat}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-500 italic">全仓扫描（未指定特定目录）</p>
              )}
            </div>

            <div className="bg-obsidian-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-rose-400">
                排除路径 (Exclude Patterns)
              </span>
              {project.exclude.length > 0 ? (
                <ul className="space-y-1">
                  {project.exclude.map((pat, idx) => (
                    <li key={idx} className="text-xs font-mono text-slate-300 bg-obsidian-900 px-2.5 py-1 rounded border border-slate-800/80">
                      {pat}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-500 italic">无额外排除路径</p>
              )}
            </div>
          </div>

          <div className="bg-obsidian-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              LLM 业务上下文背景 (Architecture Background)
            </span>
            {project.background ? (
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                {project.background}
              </p>
            ) : (
              <p className="text-xs text-slate-500 italic">未配置业务背景知识</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

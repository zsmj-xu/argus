import React, { useState } from 'react';
import {
  ArrowLeft,
  RotateCw,
  Ban,
  GitCommit,
  GitBranch,
  Clock,
  Cpu,
  Layers,
  FileCode2,
  Terminal,
  FileText,
  Download,
} from 'lucide-react';
import { useScanWatcher } from '../../hooks/useScanWatcher';
import { cancelScan, retryScan } from '../../api/scans';
import { exportDiagnostics } from '../../api/diagnostics';
import { StatusBadge } from '../scan/ScanList';
import { StageStepper } from './StageStepper';
import { CoverageMeter } from './CoverageMeter';
import { ActivityAlert } from './ActivityAlert';
import { EventStream } from './EventStream';
import { DiagnosticsCard } from './DiagnosticsCard';
import { FindingWorkbench } from '../findings/FindingWorkbench';
import { ReportViewer } from '../report/ReportViewer';
import { formatDate, truncateSha } from '../../lib/utils';

interface ScanDetailViewProps {
  scanId: string;
  onBack: () => void;
}

type TabType = 'findings' | 'events' | 'report' | 'metadata';

export const ScanDetailView: React.FC<ScanDetailViewProps> = ({ scanId, onBack }) => {
  const {
    scan,
    events,
    isLoading,
    refresh,
    isPolling,
    eventHistoryTruncated,
    expiredEventCount,
  } = useScanWatcher(scanId);

  const [activeTab, setActiveTab] = useState<TabType>('findings');
  const [isCanceling, setIsCanceling] = useState(false);
  const [isRetrying, setIsRetrying] = useState(false);

  if (isLoading && !scan) {
    return (
      <div className="py-24 text-center space-y-3">
        <RotateCw className="w-8 h-8 text-emerald-500 animate-spin mx-auto" />
        <p className="text-xs text-zinc-400">正在获取扫描详情与事件流...</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="py-20 text-center space-y-4">
        <p className="text-sm text-zinc-400">未找到指定的扫描任务</p>
        <button
          onClick={onBack}
          className="px-4 py-2 bg-zinc-800 text-zinc-200 text-xs rounded-lg hover:bg-zinc-700"
        >
          返回任务列表
        </button>
      </div>
    );
  }

  const canCancel = scan.status === 'queued' || scan.status === 'running';
  const canRetry = ['failed', 'partial', 'canceled', 'skipped'].includes(scan.status);

  const handleCancel = async () => {
    setIsCanceling(true);
    try {
      await cancelScan(scanId);
      await refresh();
    } finally {
      setIsCanceling(false);
    }
  };

  const handleRetry = async () => {
    setIsRetrying(true);
    try {
      await retryScan(scanId);
      await refresh();
    } finally {
      setIsRetrying(false);
    }
  };

  const obs = scan.observation;
  const ocrSummary = scan.metadata?.ocr_summary || {};
  const ocrLlm = scan.metadata?.ocr_llm || {};

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Top Navigation & Action Bar */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-zinc-800/80">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 bg-zinc-900 border border-zinc-800 rounded-lg hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>返回列表</span>
          </button>

          <StatusBadge status={scan.status} phase={obs?.stage || scan.phase} />

          <span className="text-xs font-mono text-zinc-500">
            ID: <span className="text-zinc-400">{scan.id}</span>
          </span>
        </div>

        {/* Top Actions */}
        <div className="flex items-center gap-2">
          {canCancel && (
            <button
              onClick={handleCancel}
              disabled={isCanceling}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-950/40 border border-rose-800/50 hover:bg-rose-900/50 text-rose-300 text-xs rounded-lg transition-colors font-medium"
            >
              <Ban className="w-3.5 h-3.5" />
              <span>{isCanceling ? '取消中...' : '取消任务'}</span>
            </button>
          )}

          {canRetry && (
            <button
              onClick={handleRetry}
              disabled={isRetrying}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs rounded-lg transition-colors font-medium shadow-sm"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRetrying ? 'animate-spin' : ''}`} />
              <span>{isRetrying ? '重试中...' : '重试任务'}</span>
            </button>
          )}

          <button
            onClick={() => exportDiagnostics(scanId)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 text-xs rounded-lg border border-zinc-800 transition-colors"
            title="导出脱敏诊断包"
          >
            <Download className="w-3.5 h-3.5 text-zinc-400" />
            <span>导出诊断</span>
          </button>

          <button
            onClick={() => refresh()}
            className="p-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 text-xs rounded-lg border border-zinc-800 transition-colors"
            title="手动刷新"
          >
            <RotateCw className={`w-4 h-4 ${isPolling ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Target Repository Info Header */}
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="font-mono text-base font-semibold text-zinc-100">
            {scan.repository_url}
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            {scan.ref && (
              <span className="flex items-center gap-1 bg-zinc-950 px-2.5 py-1 rounded-md border border-zinc-800 text-zinc-300">
                <GitBranch className="w-3.5 h-3.5 text-zinc-500" />
                {scan.ref}
              </span>
            )}
            {scan.commit_sha && (
              <span className="flex items-center gap-1 bg-zinc-950 px-2.5 py-1 rounded-md border border-zinc-800 text-zinc-300">
                <GitCommit className="w-3.5 h-3.5 text-zinc-500" />
                {truncateSha(scan.commit_sha)}
              </span>
            )}
            <span className="flex items-center gap-1 text-zinc-400">
              <Clock className="w-3.5 h-3.5 text-zinc-500" />
              创建于 {formatDate(scan.created_at)}
            </span>
          </div>
        </div>

        {scan.background && (
          <p className="text-xs text-zinc-400 bg-zinc-950/60 p-3 rounded-lg border border-zinc-800/80 italic">
            审查背景：“{scan.background}”
          </p>
        )}
      </div>

      {/* Observability Tier 1: Stage Stepper */}
      <StageStepper
        currentStage={obs?.stage || scan.phase}
        status={scan.status}
        elapsedSeconds={obs?.elapsed_seconds}
        stageElapsedSeconds={obs?.stage_elapsed_seconds}
      />

      {/* Observability Tier 2: Activity Alert (120s / 300s & Deadline) */}
      <ActivityAlert
        activityState={obs?.activity_state}
        deadlineAt={obs?.deadline_at}
      />

      {/* Observability Tier 3: Coverage Meter */}
      <CoverageMeter
        coverage={obs?.coverage}
        capabilities={obs?.capabilities}
        warnings={obs?.warnings}
        isCompleted={scan.status === 'completed'}
      />

      {/* Observability Tier 4: Diagnostics Card (for failed or partial) */}
      <DiagnosticsCard
        scanId={scan.id}
        status={scan.status}
        errorSummary={obs?.error_summary}
        rawError={scan.error}
        onRetried={refresh}
      />

      {/* Main Tabs Navigation */}
      <div className="flex items-center gap-2 border-b border-zinc-800 pt-2">
        <button
          onClick={() => setActiveTab('findings')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'findings'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <FileCode2 className="w-4 h-4" />
          <span>静态发现</span>
          <span className="ml-1 px-1.5 py-0.5 text-[10px] rounded-full bg-zinc-800 font-mono">
            {scan.finding_count}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('events')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'events'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>增量事件流</span>
          <span className="ml-1 px-1.5 py-0.5 text-[10px] rounded-full bg-zinc-800 font-mono">
            {events.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('report')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'report'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>报告与导出</span>
        </button>

        <button
          onClick={() => setActiveTab('metadata')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'metadata'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>审计指标</span>
        </button>
      </div>

      {/* Tab Content Panels */}
      <div>
        {activeTab === 'findings' && <FindingWorkbench scanId={scan.id} />}

        {activeTab === 'events' && (
          <EventStream
            events={events}
            historyTruncated={eventHistoryTruncated}
            expiredEventCount={expiredEventCount}
            isPolling={isPolling}
          />
        )}

        {activeTab === 'report' && (
          <ReportViewer scanId={scan.id} reportReady={!!obs?.report_ready} />
        )}

        {activeTab === 'metadata' && (
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              <span>OCR 审查引擎与 Token 消耗指标</span>
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800">
                <span className="text-[11px] text-zinc-500 block">LLM 供应商 / 模型</span>
                <span className="text-sm font-semibold font-mono text-purple-300">
                  {ocrLlm.provider || ocrLlm.model
                    ? `${ocrLlm.provider || ''} / ${ocrLlm.model || ''}`
                    : '环境变量预配置'}
                </span>
              </div>

              <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800">
                <span className="text-[11px] text-zinc-500 block">总 Token 消耗</span>
                <span className="text-base font-bold font-mono text-zinc-200">
                  {ocrSummary.total_tokens !== undefined ? ocrSummary.total_tokens.toLocaleString() : '-'}
                </span>
              </div>

              <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800">
                <span className="text-[11px] text-zinc-500 block">输入 / 输出 Token</span>
                <span className="text-xs font-mono text-zinc-300">
                  {ocrSummary.input_tokens || 0} in / {ocrSummary.output_tokens || 0} out
                </span>
              </div>

              <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800">
                <span className="text-[11px] text-zinc-500 block">缓存命中 Tokens</span>
                <span className="text-sm font-bold font-mono text-emerald-400">
                  {ocrSummary.cache_read_tokens || 0}
                </span>
              </div>
            </div>

            <div className="pt-2">
              <span className="text-[11px] text-zinc-500 block mb-1">原生 OCR 会话与会话 ID</span>
              <span className="font-mono text-xs text-zinc-400 bg-zinc-950 px-2 py-1 rounded border border-zinc-800">
                {scan.session_id || '原生会话在扫描后已按安全策略清理'}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

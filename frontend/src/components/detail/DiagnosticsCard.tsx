import React, { useState } from 'react';
import {
  AlertCircle,
  Lightbulb,
  Download,
  RotateCw,
  HelpCircle,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { ScanErrorSummary, ScanStatus } from '../../types/api';
import { exportDiagnostics } from '../../api/diagnostics';
import { retryScan } from '../../api/scans';

interface DiagnosticsCardProps {
  scanId: string;
  status: ScanStatus;
  errorSummary?: ScanErrorSummary;
  rawError?: string | null;
  onRetried?: () => void;
}

export const DiagnosticsCard: React.FC<DiagnosticsCardProps> = ({
  scanId,
  status,
  errorSummary,
  rawError,
  onRetried,
}) => {
  const [isExporting, setIsExporting] = useState(false);
  const [isRetrying, setIsRetrying] = useState(false);

  const isFailed = status === 'failed';
  const isPartial = status === 'partial';

  if (!isFailed && !isPartial && !errorSummary?.code && !rawError) {
    return null;
  }

  const handleExport = async () => {
    setIsExporting(true);
    try {
      await exportDiagnostics(scanId);
    } finally {
      setIsExporting(false);
    }
  };

  const handleRetry = async () => {
    setIsRetrying(true);
    try {
      await retryScan(scanId);
      if (onRetried) onRetried();
    } finally {
      setIsRetrying(false);
    }
  };

  const canRetry = errorSummary?.retryable !== false;

  return (
    <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2">
          {isFailed ? (
            <AlertCircle className="w-4 h-4 text-rose-400" />
          ) : (
            <HelpCircle className="w-4 h-4 text-orange-400" />
          )}
          <span className="font-semibold text-xs text-zinc-200 uppercase tracking-wider">
            {isFailed ? '故障根因分析与诊断' : '部分覆盖诊断与提示'}
          </span>
        </div>

        <button
          onClick={handleExport}
          disabled={isExporting}
          className="flex items-center gap-1.5 px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs rounded-lg transition-colors border border-zinc-700 font-medium"
        >
          <Download className="w-3.5 h-3.5" />
          <span>{isExporting ? '导出中...' : '导出脱敏诊断包 (.json)'}</span>
        </button>
      </div>

      {/* Error detail grid */}
      <div className="space-y-3">
        <div className="flex items-start gap-4 flex-wrap text-xs">
          {errorSummary?.code && (
            <div>
              <span className="text-zinc-500 block text-[11px]">错误代码 (Code)</span>
              <span className="font-mono text-zinc-200 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800">
                {errorSummary.code}
              </span>
            </div>
          )}

          {errorSummary?.source && (
            <div>
              <span className="text-zinc-500 block text-[11px]">来源 (Source)</span>
              <span className="font-mono text-zinc-300 capitalize">{errorSummary.source}</span>
            </div>
          )}

          <div>
            <span className="text-zinc-500 block text-[11px]">重试可行性 (Retryable)</span>
            {errorSummary?.retryable === true ? (
              <span className="inline-flex items-center gap-1 text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" /> 可安全重试
              </span>
            ) : errorSummary?.retryable === false ? (
              <span className="inline-flex items-center gap-1 text-rose-400">
                <XCircle className="w-3.5 h-3.5" /> 不建议盲目重试 (请先排查)
              </span>
            ) : (
              <span className="text-zinc-400">视具体原因而定</span>
            )}
          </div>
        </div>

        {/* Message */}
        <div className="p-3 bg-zinc-950 rounded-lg border border-zinc-800/80 text-xs text-zinc-300 font-mono">
          {errorSummary?.message || rawError || '未记录详细错误信息'}
        </div>

        {/* Highlighted Actionable Suggestion */}
        {errorSummary?.suggestion && (
          <div className="p-3.5 bg-emerald-950/20 border border-emerald-800/40 rounded-xl text-xs text-emerald-300 space-y-1">
            <div className="flex items-center gap-1.5 font-semibold text-emerald-400">
              <Lightbulb className="w-4 h-4" />
              <span>排错与修复建议 (Suggestion)</span>
            </div>
            <p className="text-emerald-300/90 text-xs leading-relaxed pl-5.5">
              {errorSummary.suggestion}
            </p>
          </div>
        )}
      </div>

      {/* Action footer */}
      {canRetry && (
        <div className="pt-2 flex justify-end">
          <button
            onClick={handleRetry}
            disabled={isRetrying}
            className="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium shadow-sm transition-colors"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isRetrying ? 'animate-spin' : ''}`} />
            <span>重新发起扫描 (Retry)</span>
          </button>
        </div>
      )}
    </div>
  );
};

import React from 'react';
import { ScanCoverage, ScanCapabilities } from '../../types/api';
import { FileCheck, Files, AlertOctagon, Cpu, Radio } from 'lucide-react';

interface CoverageMeterProps {
  coverage: ScanCoverage | undefined;
  capabilities?: ScanCapabilities;
  warnings?: string[];
  isCompleted?: boolean;
}

export const CoverageMeter: React.FC<CoverageMeterProps> = ({
  coverage,
  capabilities,
  warnings,
  isCompleted,
}) => {
  const isUnknown = !coverage || coverage.total === null || coverage.percent === null;
  const percent = coverage?.percent ?? 0;

  return (
    <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2">
          <Files className="w-4 h-4 text-emerald-400" />
          <span className="font-semibold text-xs text-zinc-200 uppercase tracking-wider">
            真实源码覆盖率计量 (Truthful Coverage)
          </span>
        </div>

        {/* Observed Capabilities Badges */}
        <div className="flex items-center gap-2">
          {capabilities?.file_progress && (
            <span
              className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-sky-950/60 border border-sky-800/60 text-sky-300"
              title="已正面观测到逐文件审查事件"
            >
              <FileCheck className="w-3 h-3" />
              File Events
            </span>
          )}
          {capabilities?.llm_requests && (
            <span
              className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/60 border border-purple-800/60 text-purple-300"
              title="已正面观测到大模型生成请求事实"
            >
              <Cpu className="w-3 h-3" />
              LLM Calls
            </span>
          )}
          {capabilities?.event_protocol && (
            <span
              className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60 text-emerald-300"
              title="已激活独立 OCR NDJSON 事件协议通道"
            >
              <Radio className="w-3 h-3" />
              v1 Protocol
            </span>
          )}
        </div>
      </div>

      {/* Progress Bar Display */}
      {isUnknown ? (
        <div className="space-y-2 py-1">
          <div className="flex justify-between text-xs text-zinc-400">
            <span className="flex items-center gap-1.5 text-sky-400 animate-pulse">
              <span className="w-2 h-2 rounded-full bg-sky-400" />
              文件资产盘点中 (动态未知状态)...
            </span>
            <span className="font-mono text-zinc-500">待计算</span>
          </div>
          {/* Indeterminate Shimmer Progress Bar */}
          <div className="h-3 w-full bg-zinc-950 rounded-full overflow-hidden border border-zinc-800 relative">
            <div className="absolute inset-y-0 bg-gradient-to-r from-transparent via-sky-500/50 to-transparent w-1/3 animate-[shimmer_1.8s_infinite] -translate-x-full" />
          </div>
          <p className="text-[11px] text-zinc-400">
            严格遵守可观测性合同：在引擎完成文件扫描盘点前，不根据心跳或耗时伪造百分比。
          </p>
        </div>
      ) : (
        <div className="space-y-2 py-1">
          <div className="flex justify-between text-xs">
            <span className="text-zinc-300 font-medium">
              审查进度: {coverage.reviewed} / {coverage.total} 文件
            </span>
            <span className="font-mono font-bold text-emerald-400">{percent}%</span>
          </div>
          <div className="h-3 w-full bg-zinc-950 rounded-full overflow-hidden border border-zinc-800 p-0.5">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                isCompleted ? 'bg-emerald-500' : 'bg-gradient-to-r from-sky-500 to-emerald-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(2, percent))}%` }}
            />
          </div>
        </div>
      )}

      {/* Counters Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
        <div className="bg-zinc-950/80 border border-zinc-800/80 rounded-lg p-3">
          <span className="text-[11px] text-zinc-400 block">已审查 (Reviewed)</span>
          <span className="text-lg font-bold font-mono text-emerald-400">
            {coverage?.reviewed ?? 0}
          </span>
        </div>

        <div className="bg-zinc-950/80 border border-zinc-800/80 rounded-lg p-3">
          <span className="text-[11px] text-zinc-400 block">总文件 (Total)</span>
          <span className="text-lg font-bold font-mono text-zinc-200">
            {coverage?.total !== null && coverage?.total !== undefined ? coverage.total : '-'}
          </span>
        </div>

        <div className="bg-zinc-950/80 border border-zinc-800/80 rounded-lg p-3">
          <span className="text-[11px] text-zinc-400 block">失败文件 (Failed)</span>
          <span
            className={`text-lg font-bold font-mono ${
              (coverage?.failed ?? 0) > 0 ? 'text-rose-400' : 'text-zinc-500'
            }`}
          >
            {coverage?.failed ?? 0}
          </span>
        </div>

        <div className="bg-zinc-950/80 border border-zinc-800/80 rounded-lg p-3">
          <span className="text-[11px] text-zinc-400 block">跳过文件 (Skipped)</span>
          <span className="text-lg font-bold font-mono text-zinc-500">
            {coverage?.skipped ?? 0}
          </span>
        </div>
      </div>

      {/* Coverage Warnings */}
      {warnings && warnings.length > 0 && (
        <div className="p-3 bg-amber-950/30 border border-amber-800/40 rounded-lg text-xs text-amber-300 space-y-1">
          <div className="font-semibold flex items-center gap-1.5">
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>覆盖率警告提示 (Coverage Warnings)</span>
          </div>
          <ul className="list-disc list-inside space-y-0.5 text-amber-300/80 text-[11px]">
            {warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

import React from 'react';
import { Check, Loader2, AlertCircle } from 'lucide-react';
import { ScanStatus } from '../../types/api';
import { formatDuration } from '../../lib/utils';

interface StageStepperProps {
  currentStage: string;
  status: ScanStatus;
  elapsedSeconds?: number;
  stageElapsedSeconds?: number;
}

interface StepDef {
  key: string;
  label: string;
  desc: string;
}

const STAGES: StepDef[] = [
  { key: 'queued', label: '排队等待', desc: '等待 Worker 领取任务' },
  { key: 'git_fetching', label: 'Git 获取', desc: '隔离临时 Clone 与检出' },
  { key: 'source_checking', label: '范围检查', desc: '文件资产盘点与边界校验' },
  { key: 'ocr_starting', label: 'OCR 启动', desc: '初始化审查引擎进程' },
  { key: 'ocr_running', label: '全文件审查', desc: 'OpenCodeReview 深度语义分析' },
  { key: 'parsing', label: '结果归一', desc: '静态发现解析与过滤' },
  { key: 'persisting', label: '入库持久化', desc: '生成报告与持久化' },
];

export const StageStepper: React.FC<StageStepperProps> = ({
  currentStage,
  status,
  elapsedSeconds,
  stageElapsedSeconds,
}) => {
  const isTerminal = ['completed', 'partial', 'failed', 'canceled', 'skipped'].includes(status);
  const isFailed = status === 'failed';

  // Map stage to index
  const getStageIndex = (stage: string): number => {
    const idx = STAGES.findIndex((s) => s.key === stage);
    if (idx !== -1) return idx;
    if (stage === 'preparing') return 1;
    if (stage === 'scanning') return 4;
    return 0;
  };

  const currentIndex = isTerminal ? STAGES.length : getStageIndex(currentStage);

  return (
    <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between text-xs border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-zinc-200">生命周期阶段追踪</span>
          <span className="text-zinc-500 font-mono">({currentStage || status})</span>
        </div>
        <div className="flex items-center gap-3 text-zinc-400 font-mono">
          {stageElapsedSeconds !== undefined && stageElapsedSeconds > 0 && !isTerminal && (
            <span>当前阶段: {formatDuration(stageElapsedSeconds)}</span>
          )}
          {elapsedSeconds !== undefined && (
            <span className="text-zinc-300">总耗时: {formatDuration(elapsedSeconds)}</span>
          )}
        </div>
      </div>

      {/* Horizontal Step Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
        {STAGES.map((step, idx) => {
          const isDone = isTerminal ? !isFailed || idx < currentIndex : idx < currentIndex;
          const isCurrent = !isTerminal && idx === currentIndex;

          let stepStatusClass = 'border-zinc-800 bg-zinc-950/50 text-zinc-500';
          let icon = <span className="text-[11px] font-mono">{idx + 1}</span>;

          if (isDone) {
            stepStatusClass = 'border-emerald-500/40 bg-emerald-950/20 text-emerald-300';
            icon = <Check className="w-3.5 h-3.5 text-emerald-400" />;
          } else if (isCurrent) {
            stepStatusClass =
              'border-sky-500/50 bg-sky-950/30 text-sky-200 shadow-sm shadow-sky-950';
            icon = <Loader2 className="w-3.5 h-3.5 text-sky-400 animate-spin" />;
          } else if (isFailed && idx === currentIndex) {
            stepStatusClass = 'border-rose-500/50 bg-rose-950/30 text-rose-300';
            icon = <AlertCircle className="w-3.5 h-3.5 text-rose-400" />;
          }

          return (
            <div
              key={step.key}
              className={`flex flex-col p-2.5 rounded-lg border text-left transition-all ${stepStatusClass}`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="w-5 h-5 rounded-full flex items-center justify-center bg-zinc-900/80 border border-current">
                  {icon}
                </span>
                {isCurrent && (
                  <span className="text-[10px] font-mono text-sky-400 animate-pulse">RUNNING</span>
                )}
              </div>
              <div className="font-medium text-xs truncate mt-0.5">{step.label}</div>
              <div className="text-[10px] text-zinc-400 truncate mt-0.5" title={step.desc}>
                {step.desc}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

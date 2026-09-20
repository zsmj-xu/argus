import React, { useState, useEffect } from 'react';
import { AlertTriangle, Clock, ShieldAlert } from 'lucide-react';
import { formatDuration } from '../../lib/utils';

interface ActivityAlertProps {
  activityState: string | undefined;
  deadlineAt: string | null | undefined;
}

export const ActivityAlert: React.FC<ActivityAlertProps> = ({
  activityState,
  deadlineAt,
}) => {
  const [timeLeft, setTimeLeft] = useState<number | null>(null);

  useEffect(() => {
    if (!deadlineAt) {
      setTimeLeft(null);
      return;
    }

    const calcTime = () => {
      const now = Date.now();
      const target = new Date(deadlineAt).getTime();
      const diffSec = Math.max(0, Math.floor((target - now) / 1000));
      setTimeLeft(diffSec);
    };

    calcTime();
    const interval = setInterval(calcTime, 1000);
    return () => clearInterval(interval);
  }, [deadlineAt]);

  const isIdleWarning = activityState === 'idle_warning';
  const isStaleWarning = activityState === 'stale_warning';

  if (!isIdleWarning && !isStaleWarning && !deadlineAt) {
    return null;
  }

  return (
    <div className="space-y-3">
      {/* 120s Idle Warning */}
      {isIdleWarning && (
        <div className="p-3.5 bg-amber-950/40 border border-amber-800/60 rounded-xl text-xs text-amber-300 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold block">
              诊断预警：连续 120 秒未检测到输出事实 (idle_warning)
            </span>
            <p className="text-amber-300/80 text-[11px] leading-relaxed">
              底层 OCR 引擎当前未向管道写入新字节。根据可观测性合同，此状态仅作为诊断参考，不代表 Worker 异常或任务失败，系统不会发起自动取消。
            </p>
          </div>
        </div>
      )}

      {/* 300s Stale Warning */}
      {isStaleWarning && (
        <div className="p-3.5 bg-orange-950/40 border border-orange-800/60 rounded-xl text-xs text-orange-300 flex items-start gap-2.5">
          <ShieldAlert className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold block">
              停滞告警：连续 300 秒未检测到进度或输出 (stale_warning)
            </span>
            <p className="text-orange-300/80 text-[11px] leading-relaxed">
              任务可能处于复杂代码块推理或模型高负载排队中。Worker 租约保护机制正在后台维护健康锁，请耐心等待或查看增量事件。
            </p>
          </div>
        </div>
      )}

      {/* Deadline Countdown */}
      {deadlineAt && timeLeft !== null && (
        <div className="px-3.5 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-xs text-zinc-400 flex items-center justify-between">
          <span className="flex items-center gap-1.5 text-zinc-300">
            <Clock className="w-3.5 h-3.5 text-zinc-500" />
            进程硬超时截止时间 (30 分钟上限)
          </span>
          <span className="font-mono font-medium text-amber-400">
            {timeLeft > 0 ? `剩余 ${formatDuration(timeLeft)}` : '已达截止时限'}
          </span>
        </div>
      )}
    </div>
  );
};

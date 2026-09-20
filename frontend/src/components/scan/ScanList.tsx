import React from 'react';
import {
  Clock,
  GitCommit,
  AlertTriangle,
  RotateCw,
  Ban,
  FileCode2,
  ChevronRight,
  Shield,
} from 'lucide-react';
import { ScanResponse, ScanStatus } from '../../types/api';
import { formatDate, formatDuration, truncateSha } from '../../lib/utils';
import { cancelScan, retryScan } from '../../api/scans';

interface ScanListProps {
  scans: ScanResponse[];
  selectedScanId: string | null;
  onSelectScan: (id: string) => void;
  onRefresh: () => void;
  isLoading: boolean;
}

export const StatusBadge: React.FC<{ status: ScanStatus; phase?: string }> = ({
  status,
  phase,
}) => {
  switch (status) {
    case 'queued':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-300 border border-amber-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
          排队中
        </span>
      );
    case 'running':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-sky-500/10 text-sky-300 border border-sky-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-ping" />
          审查中 ({phase || '运行'})
        </span>
      );
    case 'completed':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          已完成
        </span>
      );
    case 'partial':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-orange-500/10 text-orange-300 border border-orange-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-orange-400" />
          部分覆盖
        </span>
      );
    case 'failed':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-300 border border-rose-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
          失败
        </span>
      );
    case 'canceled':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-zinc-800 text-zinc-400 border border-zinc-700">
          已取消
        </span>
      );
    case 'skipped':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-purple-500/10 text-purple-300 border border-purple-500/30">
          已跳过
        </span>
      );
    default:
      return <span>{status}</span>;
  }
};

export const ScanList: React.FC<ScanListProps> = ({
  scans,
  selectedScanId,
  onSelectScan,
  onRefresh,
  isLoading,
}) => {
  const [actionLoadingId, setActionLoadingId] = React.useState<string | null>(null);

  const handleCancel = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    setActionLoadingId(id);
    try {
      await cancelScan(id);
      onRefresh();
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleRetry = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    setActionLoadingId(id);
    try {
      await retryScan(id);
      onRefresh();
    } finally {
      setActionLoadingId(null);
    }
  };

  if (scans.length === 0 && !isLoading) {
    return (
      <div className="text-center py-16 px-4 border border-dashed border-zinc-800 rounded-xl bg-zinc-900/30">
        <Shield className="w-12 h-12 text-zinc-600 mx-auto mb-3" />
        <h3 className="text-base font-medium text-zinc-300">暂无白盒扫描任务</h3>
        <p className="text-xs text-zinc-400 mt-1 max-w-sm mx-auto">
          点击右上角“新建扫描”，提交 Git 仓库地址进行自动化白盒代码审查。
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {scans.map((scan) => {
        const isSelected = scan.id === selectedScanId;
        const canCancel = scan.status === 'queued' || scan.status === 'running';
        const canRetry = ['failed', 'partial', 'canceled', 'skipped'].includes(scan.status);
        const isActionLoading = actionLoadingId === scan.id;

        return (
          <div
            key={scan.id}
            onClick={() => onSelectScan(scan.id)}
            className={`group relative rounded-xl border p-4.5 cursor-pointer transition-all ${
              isSelected
                ? 'bg-zinc-900/90 border-emerald-500/60 shadow-lg shadow-emerald-950/20 ring-1 ring-emerald-500/20'
                : 'bg-zinc-900/40 border-zinc-800/80 hover:bg-zinc-900/80 hover:border-zinc-700'
            }`}
          >
            <div className="flex items-start justify-between gap-4">
              {/* Left Column: Status, Repo, Commit */}
              <div className="min-w-0 flex-1 space-y-1.5">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <StatusBadge status={scan.status} phase={scan.observation?.stage || scan.phase} />
                  <span className="text-xs font-mono text-zinc-500">ID: {scan.id.slice(0, 8)}</span>
                  {scan.commit_sha && (
                    <span className="inline-flex items-center gap-1 text-xs font-mono text-zinc-400 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800">
                      <GitCommit className="w-3 h-3 text-zinc-500" />
                      {truncateSha(scan.commit_sha)}
                    </span>
                  )}
                  {scan.ref && (
                    <span className="text-xs font-mono text-zinc-400 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800">
                      ref: {scan.ref}
                    </span>
                  )}
                </div>

                <div className="font-mono text-sm text-zinc-200 truncate group-hover:text-emerald-300 transition-colors">
                  {scan.repository_url}
                </div>

                {scan.background && (
                  <p className="text-xs text-zinc-400 line-clamp-1 italic">
                    “{scan.background}”
                  </p>
                )}

                {/* Metadata Row: Files, Findings, Time */}
                <div className="flex items-center gap-4 text-xs text-zinc-400 pt-1 flex-wrap">
                  <span className="inline-flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-zinc-500" />
                    {formatDate(scan.created_at)}
                  </span>

                  {scan.started_at && (
                    <span className="text-zinc-500">
                      耗时: {formatDuration(scan.observation?.elapsed_seconds)}
                    </span>
                  )}

                  <span className="inline-flex items-center gap-1 text-zinc-300">
                    <FileCode2 className="w-3.5 h-3.5 text-zinc-500" />
                    {scan.observation?.coverage?.total !== null && scan.observation?.coverage?.total !== undefined ? (
                      <span>{scan.observation.coverage.reviewed} / {scan.observation.coverage.total} 文件已审</span>
                    ) : (
                      <span>{scan.progress?.reviewed_files || 0} 文件</span>
                    )}
                  </span>

                  {scan.finding_count > 0 ? (
                    <span className="inline-flex items-center gap-1 text-amber-300 font-medium">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      {scan.finding_count} 处静态发现
                    </span>
                  ) : (
                    <span className="text-zinc-500">0 发现</span>
                  )}
                </div>
              </div>

              {/* Right Column: Actions & Chevron */}
              <div className="flex items-center gap-2 shrink-0">
                {canCancel && (
                  <button
                    onClick={(e) => handleCancel(e, scan.id)}
                    disabled={isActionLoading}
                    className="p-1.5 text-zinc-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                    title="取消任务"
                  >
                    <Ban className="w-4 h-4" />
                  </button>
                )}

                {canRetry && (
                  <button
                    onClick={(e) => handleRetry(e, scan.id)}
                    disabled={isActionLoading}
                    className="p-1.5 text-zinc-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded-lg transition-colors"
                    title="重试任务"
                  >
                    <RotateCw className={`w-4 h-4 ${isActionLoading ? 'animate-spin' : ''}`} />
                  </button>
                )}

                <div className="text-zinc-500 group-hover:text-zinc-300 transition-colors">
                  <ChevronRight className="w-5 h-5" />
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

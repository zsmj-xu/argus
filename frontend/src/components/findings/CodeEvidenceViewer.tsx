import React, { useState } from 'react';
import {
  FileCode,
  Check,
  Copy,
  Wrench,
  FileCheck,
  X,
  ShieldAlert,
  Tag,
  Hash,
} from 'lucide-react';
import { FindingResponse } from '../../types/api';

interface CodeEvidenceViewerProps {
  finding: FindingResponse;
  onClose?: () => void;
}

export const SEVERITY_CONFIG: Record<
  string,
  { label: string; badge: string; color: string }
> = {
  critical: {
    label: '严重 (Critical)',
    badge: '严重',
    color: 'text-rose-400 border-rose-800 bg-rose-950/40',
  },
  high: {
    label: '高危 (High)',
    badge: '高危',
    color: 'text-orange-400 border-orange-800 bg-orange-950/40',
  },
  medium: {
    label: '中危 (Medium)',
    badge: '中危',
    color: 'text-amber-400 border-amber-800 bg-amber-950/40',
  },
  low: {
    label: '低危 (Low)',
    badge: '低危',
    color: 'text-sky-400 border-sky-800 bg-sky-950/40',
  },
  unknown: {
    label: '未知/提示 (Unknown)',
    badge: '未知',
    color: 'text-zinc-400 border-zinc-700 bg-zinc-800',
  },
};

export function getCategoryLabel(category: string | undefined): {
  display: string;
  raw: string;
} {
  if (!category) return { display: '常规安全', raw: 'general' };
  const lower = category.toLowerCase();
  const map: Record<string, string> = {
    security: '安全缺陷',
    correctness: '逻辑正确性',
    maintainability: '代码可维护性',
    performance: '性能隐患',
    style: '代码规范',
    bug: '代码缺陷',
    vulnerability: '已知漏洞',
  };
  const translated = map[lower];
  return {
    display: translated ? `${translated} (${category})` : category,
    raw: category,
  };
}

export const CodeEvidenceViewer: React.FC<CodeEvidenceViewerProps> = ({
  finding,
  onClose,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopyRemediation = () => {
    if (!finding.remediation) return;
    navigator.clipboard.writeText(finding.remediation);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sevKey = (finding.severity || 'unknown').toLowerCase();
  const sevInfo = SEVERITY_CONFIG[sevKey] || SEVERITY_CONFIG.unknown;
  const categoryInfo = getCategoryLabel(finding.category);

  const locationStr = finding.file
    ? `${finding.file}${
        finding.start_line
          ? `:${finding.start_line}${
              finding.end_line && finding.end_line !== finding.start_line
                ? `-${finding.end_line}`
                : ''
            }`
          : ''
      }`
    : null;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 space-y-5 shadow-lg">
      {/* Title & Header */}
      <div className="space-y-3 border-b border-zinc-800 pb-4">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1.5 min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className={`text-[11px] font-bold uppercase px-2.5 py-0.5 rounded border font-mono ${sevInfo.color}`}
              >
                {sevInfo.label}
              </span>
              <span className="inline-flex items-center gap-1 font-mono text-xs text-zinc-400 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800">
                <Hash className="w-3 h-3 text-zinc-500" />
                规则 ID: {finding.rule_id}
              </span>
            </div>
            <h3 className="text-base font-semibold text-zinc-100 leading-snug break-words">
              {finding.title || '无标题告警'}
            </h3>
          </div>

          {onClose && (
            <button
              onClick={onClose}
              className="p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 rounded-lg transition-colors shrink-0"
              title="关闭详情 (Escape)"
              aria-label="关闭详情"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Location & Meta Tags */}
        <div className="flex items-center gap-2.5 text-xs font-mono flex-wrap">
          {locationStr ? (
            <div
              className="flex items-center gap-1.5 text-emerald-400 bg-emerald-950/30 border border-emerald-800/40 px-2.5 py-1 rounded-md"
              title="代码文件与行号位置"
            >
              <FileCode className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate max-w-lg">{locationStr}</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-zinc-500 bg-zinc-950 px-2.5 py-1 rounded-md border border-zinc-800">
              <FileCode className="w-3.5 h-3.5 shrink-0" />
              <span>未标记具体源码行号 (宏观架构或跨文件项)</span>
            </div>
          )}

          <span className="flex items-center gap-1 text-zinc-300 bg-zinc-950 px-2.5 py-1 rounded border border-zinc-800">
            <Tag className="w-3 h-3 text-zinc-500" />
            分类: {categoryInfo.display}
          </span>

          {finding.confidence && (
            <span className="text-zinc-400 bg-zinc-950 px-2.5 py-1 rounded border border-zinc-800">
              置信度: {finding.confidence}
            </span>
          )}
        </div>
      </div>

      {/* Description / Message */}
      <div className="space-y-1.5">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
          问题说明与安全影响 (Message)
        </h4>
        {finding.message && finding.message.trim() ? (
          <div className="text-sm text-zinc-200 leading-relaxed bg-zinc-950/60 p-3.5 rounded-lg border border-zinc-800/80 whitespace-pre-wrap">
            {finding.message}
          </div>
        ) : (
          <div className="p-3 bg-zinc-950/60 rounded-lg border border-zinc-800/80 text-xs text-zinc-500 italic">
            暂无具体问题说明
          </div>
        )}
      </div>

      {/* Code Evidence Block */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <FileCheck className="w-3.5 h-3.5 text-sky-400" />
            <span>静态源码证据 (Code Evidence)</span>
          </h4>
          {finding.start_line && (
            <span className="text-[11px] font-mono text-zinc-500">
              行号范围: {finding.start_line}
              {finding.end_line && finding.end_line !== finding.start_line
                ? ` - ${finding.end_line}`
                : ''}
            </span>
          )}
        </div>
        {finding.evidence && finding.evidence.trim() ? (
          <div className="relative rounded-lg overflow-hidden border border-zinc-800 bg-zinc-950">
            <pre className="p-4 text-xs font-mono text-zinc-300 overflow-x-auto leading-relaxed">
              <code>{finding.evidence}</code>
            </pre>
          </div>
        ) : (
          <div className="p-3.5 bg-zinc-950/60 rounded-lg border border-zinc-800/80 text-xs text-zinc-500 italic flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-zinc-600 shrink-0" />
            <span>此告警未附带具体源码证据片段（可能为全局规则或架构级发现）</span>
          </div>
        )}
      </div>

      {/* Remediation / Fix Recommendation */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
            <Wrench className="w-3.5 h-3.5" />
            <span>修复建议与对策 (Remediation)</span>
          </h4>
          {finding.remediation && finding.remediation.trim() && (
            <button
              onClick={handleCopyRemediation}
              className="flex items-center gap-1 text-[11px] text-zinc-400 hover:text-zinc-200 bg-zinc-800 px-2 py-0.5 rounded border border-zinc-700 transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span className="text-emerald-400">已复制</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>复制建议</span>
                </>
              )}
            </button>
          )}
        </div>
        {finding.remediation && finding.remediation.trim() ? (
          <div className="relative rounded-lg overflow-hidden border border-emerald-800/30 bg-emerald-950/10">
            <pre className="p-4 text-xs font-mono text-emerald-300/90 overflow-x-auto leading-relaxed whitespace-pre-wrap">
              <code>{finding.remediation}</code>
            </pre>
          </div>
        ) : (
          <div className="p-3.5 bg-zinc-950/60 rounded-lg border border-zinc-800/80 text-xs text-zinc-500 italic">
            未提供针对性的修复建议对策
          </div>
        )}
      </div>
    </div>
  );
};

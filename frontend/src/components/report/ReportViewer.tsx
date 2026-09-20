import React, { useState, useEffect } from 'react';
import {
  Download,
  Copy,
  Check,
  ShieldCheck,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ReportFormat } from '../../types/api';
import { getReportText, downloadReport } from '../../api/scans';

interface ReportViewerProps {
  scanId: string;
  reportReady: boolean;
}

export const ReportViewer: React.FC<ReportViewerProps> = ({ scanId, reportReady }) => {
  const [activeFormat, setActiveFormat] = useState<ReportFormat>('markdown');
  const [content, setContent] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  useEffect(() => {
    if (!reportReady || !scanId) return;

    let isMounted = true;
    setIsLoading(true);

    getReportText(scanId, activeFormat)
      .then((data) => {
        if (isMounted) {
          setContent(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
          setIsLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setContent(`加载报告失败: ${err.message || err}`);
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [scanId, reportReady, activeFormat]);

  const handleCopy = () => {
    if (!content) return;
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = async (format: ReportFormat) => {
    setIsDownloading(true);
    try {
      await downloadReport(scanId, format);
    } finally {
      setIsDownloading(false);
    }
  };

  if (!reportReady) {
    return (
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-12 text-center space-y-2">
        <AlertCircle className="w-10 h-10 text-zinc-600 mx-auto" />
        <h4 className="text-sm font-medium text-zinc-300">报告尚未就绪</h4>
        <p className="text-xs text-zinc-500 max-w-sm mx-auto">
          仅当扫描进入完成 (completed)、部分覆盖 (partial) 或跳过 (skipped) 终态时，服务才提供权威报告导出。
        </p>
      </div>
    );
  }

  return (
    <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
      {/* Header & Format Toggle */}
      <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3 flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span className="font-semibold text-xs text-zinc-200 uppercase tracking-wider">
            静态审查报告与导出 (Reports & Export)
          </span>
        </div>

        {/* Format Selector & Actions */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs">
            <button
              onClick={() => setActiveFormat('markdown')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                activeFormat === 'markdown'
                  ? 'bg-zinc-800 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Markdown
            </button>
            <button
              onClick={() => setActiveFormat('sarif')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                activeFormat === 'sarif'
                  ? 'bg-zinc-800 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              SARIF
            </button>
            <button
              onClick={() => setActiveFormat('json')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                activeFormat === 'json'
                  ? 'bg-zinc-800 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              JSON
            </button>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs rounded-lg transition-colors border border-zinc-700"
            title="复制文本"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">已复制</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>复制</span>
              </>
            )}
          </button>

          <button
            onClick={() => handleDownload(activeFormat)}
            disabled={isDownloading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg shadow-sm transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{isDownloading ? '下载中...' : `下载 .${activeFormat}`}</span>
          </button>
        </div>
      </div>

      {/* Content Preview */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-zinc-500 text-xs gap-2">
          <Loader2 className="w-4 h-4 animate-spin text-emerald-500" />
          <span>正在生成并加载报告...</span>
        </div>
      ) : activeFormat === 'markdown' ? (
        <div className="prose prose-invert prose-sm max-w-none bg-zinc-950 p-6 rounded-xl border border-zinc-800 overflow-x-auto leading-relaxed">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
        </div>
      ) : (
        <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800 overflow-x-auto max-h-[600px]">
          <pre className="text-xs font-mono text-zinc-300 leading-relaxed">
            <code>{content}</code>
          </pre>
        </div>
      )}
    </div>
  );
};

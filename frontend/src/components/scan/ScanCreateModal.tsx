import React, { useState } from 'react';
import { X, ShieldAlert, GitBranch, FolderGit2, AlertTriangle, Loader2 } from 'lucide-react';
import { createScan } from '../../api/scans';
import { validateGitUrl } from '../../lib/utils';
import { authStore } from '../../store/auth';

interface ScanCreateModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (scanId: string) => void;
  onRequireAuth: () => void;
}

export const ScanCreateModal: React.FC<ScanCreateModalProps> = ({
  isOpen,
  onClose,
  onCreated,
  onRequireAuth,
}) => {
  const [repoUrl, setRepoUrl] = useState('');
  const [ref, setRef] = useState('');
  const [include, setInclude] = useState('');
  const [exclude, setExclude] = useState('');
  const [background, setBackground] = useState('');
  const [disclosureConfirmed, setDisclosureConfirmed] = useState(false);

  const [urlError, setUrlError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleUrlChange = (val: string) => {
    setRepoUrl(val);
    const check = validateGitUrl(val);
    if (!check.isValid && check.error) {
      setUrlError(check.error);
    } else {
      setUrlError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authStore.getApiKey()) {
      onRequireAuth();
      return;
    }

    const check = validateGitUrl(repoUrl);
    if (!check.isValid) {
      setUrlError(check.error || '无效的 Git 仓库地址');
      return;
    }

    if (!disclosureConfirmed) {
      setSubmitError('提交扫描前必须确认源码披露授权');
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    const parseList = (str: string) =>
      str
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter(Boolean);

    try {
      const payload = {
        repository_url: repoUrl.trim(),
        ref: ref.trim() || null,
        include: parseList(include),
        exclude: parseList(exclude),
        background: background.trim() || null,
        source_disclosure_confirmed: true,
      };

      const result = await createScan(payload);
      setIsSubmitting(false);
      onClose();
      onCreated(result.id);
    } catch (err: any) {
      setIsSubmitting(false);
      setSubmitError(err.message || '提交扫描失败');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="w-full max-w-2xl bg-zinc-900 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden my-8 animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <div className="flex items-center gap-2.5 font-semibold text-zinc-100">
            <FolderGit2 className="w-5 h-5 text-emerald-400" />
            <span>新建白盒代码扫描</span>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {/* Repository URL */}
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1.5 uppercase tracking-wider">
              Git 仓库地址 (Repository URL) <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              value={repoUrl}
              onChange={(e) => handleUrlChange(e.target.value)}
              placeholder="https://github.com/example/repo.git 或 git@github.com:example/repo.git"
              className="w-full px-3.5 py-2.5 bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 font-mono text-sm"
            />
            {urlError && (
              <div className="flex items-start gap-1.5 text-xs text-rose-400 mt-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span>{urlError}</span>
              </div>
            )}
            <p className="text-[11px] text-zinc-400 mt-1">
              支持 HTTPS、SSH、Git 与 SCP 格式。URL 内严禁内嵌用户名密码或 Token；私有仓库凭据由部署宿主机的 Git 凭据助手或 SSH Agent 提供。
            </p>
          </div>

          {/* Ref */}
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1.5 uppercase tracking-wider flex items-center gap-1.5">
              <GitBranch className="w-3.5 h-3.5 text-zinc-400" />
              <span>Git Ref / 分支 / Tag / Commit SHA</span>
            </label>
            <input
              type="text"
              value={ref}
              onChange={(e) => setRef(e.target.value)}
              placeholder="main、v1.0.0 或具体的 40 位 Commit SHA (默认仓库缺省分支)"
              className="w-full px-3.5 py-2.5 bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 font-mono text-sm"
            />
          </div>

          {/* Path Filters: Include / Exclude */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                包含路径 (Include Patterns)
              </label>
              <input
                type="text"
                value={include}
                onChange={(e) => setInclude(e.target.value)}
                placeholder="例如: src, backend, api/ (以逗号分隔)"
                className="w-full px-3 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-200 placeholder-zinc-500 text-xs font-mono focus:outline-none focus:border-emerald-500"
              />
              <p className="text-[11px] text-zinc-400 mt-1">留空表示全仓库扫描</p>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                排除路径 (Exclude Patterns)
              </label>
              <input
                type="text"
                value={exclude}
                onChange={(e) => setExclude(e.target.value)}
                placeholder="例如: **/test/**, vendor, docs (以逗号分隔)"
                className="w-full px-3 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-200 placeholder-zinc-500 text-xs font-mono focus:outline-none focus:border-emerald-500"
              />
              <p className="text-[11px] text-zinc-400 mt-1">跳过不需要审计的生成代码或测试目录</p>
            </div>
          </div>

          {/* Background / Focus description */}
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1.5">
              审查重点 / 背景说明 (Background)
            </label>
            <textarea
              rows={3}
              value={background}
              onChange={(e) => setBackground(e.target.value)}
              placeholder="例如：重点审查用户认证、权限边界、敏感数据加密与 SQL 注入风险..."
              className="w-full px-3.5 py-2.5 bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 text-sm"
            />
          </div>

          {/* Mandatory Disclosure Checkbox */}
          <div className="bg-amber-950/30 border border-amber-800/40 rounded-xl p-4 space-y-2">
            <div className="flex items-start gap-2.5">
              <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-xs text-amber-200 font-medium leading-relaxed">
                  源码披露授权确认 (Source Disclosure Confirmation)
                </p>
                <p className="text-[11px] text-amber-300/80 leading-relaxed mt-0.5">
                  Argus 依靠配置的模型完成深度语义审查。提交扫描意味着您已获准将本次所选范围内的源代码发送给服务配置的大模型端点。
                </p>
              </div>
            </div>

            <label className="flex items-center gap-3 pt-2 cursor-pointer select-none">
              <input
                type="checkbox"
                required
                checked={disclosureConfirmed}
                onChange={(e) => {
                  setDisclosureConfirmed(e.target.checked);
                  if (e.target.checked) setSubmitError(null);
                }}
                className="w-4 h-4 rounded border-zinc-700 bg-zinc-950 text-emerald-500 focus:ring-emerald-500/50 cursor-pointer"
              />
              <span className="text-xs font-medium text-zinc-200">
                我确认本次选中的源码已获准发送给配置的 LLM <span className="text-rose-400">*</span>
              </span>
            </label>
          </div>

          {submitError && (
            <div className="p-3 bg-rose-950/50 border border-rose-800/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{submitError}</span>
            </div>
          )}

          {/* Submit Actions */}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={!disclosureConfirmed || isSubmitting || !!urlError}
              className="flex items-center gap-2 px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-zinc-800 disabled:text-zinc-500 disabled:cursor-not-allowed text-white font-medium text-sm rounded-lg shadow-sm shadow-emerald-950 transition-all"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>提交中...</span>
                </>
              ) : (
                <span>提交并启动审查</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

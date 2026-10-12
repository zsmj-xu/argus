import React, { useState, useEffect } from 'react';
import { X, GitBranch, FolderGit2, Info, AlertTriangle, ShieldCheck } from 'lucide-react';
import { Project, ProjectCreatePayload, ProjectUpdatePayload } from '../../types/api';

interface ProjectModalProps {
  isOpen: boolean;
  mode: 'create' | 'edit';
  project?: Project | null;
  busy?: boolean;
  onClose: () => void;
  onSubmit: (payload: ProjectCreatePayload | ProjectUpdatePayload) => Promise<void>;
}

export const ProjectModal: React.FC<ProjectModalProps> = ({
  isOpen,
  mode,
  project,
  busy = false,
  onClose,
  onSubmit,
}) => {
  const [name, setName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [branchChoice, setBranchChoice] = useState('main');
  const [customBranch, setCustomBranch] = useState('');
  const [background, setBackground] = useState('');
  const [includeText, setIncludeText] = useState('');
  const [excludeText, setExcludeText] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (mode === 'edit' && project) {
      setName(project.name);
      setRepoUrl(project.repository_url);
      setBranchChoice(['main', 'master'].includes(project.branch) ? project.branch : 'custom');
      setCustomBranch(['main', 'master'].includes(project.branch) ? '' : project.branch);
      setBackground(project.background || '');
      setIncludeText(project.include.join(', '));
      setExcludeText(project.exclude.join(', '));
    } else {
      setName('');
      setRepoUrl('');
      setBranchChoice('main');
      setCustomBranch('');
      setBackground('');
      setIncludeText('');
      setExcludeText('');
    }
    setError('');
  }, [mode, project, isOpen]);

  if (!isOpen) return null;

  // Auto-infer name from repository URL if name is currently empty or user hasn't typed a custom name
  const handleRepoUrlChange = (value: string) => {
    setRepoUrl(value);
    if (mode === 'create' && (!name || name === inferRepoName(repoUrl))) {
      const inferred = inferRepoName(value);
      if (inferred) setName(inferred);
    }
  };

  const inferRepoName = (url: string) => {
    try {
      const clean = url.trim().replace(/\.git$/, '');
      const parts = clean.split(/[/:]/).filter(Boolean);
      if (parts.length >= 2) {
        return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
      }
      return parts[parts.length - 1] || '';
    } catch {
      return '';
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const parseList = (str: string) =>
      str
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter(Boolean);

    const effectiveBranch = branchChoice === 'custom' ? customBranch.trim() : branchChoice;
    if (mode === 'create' && !effectiveBranch) {
      setError('请输入有效的扫描分支');
      return;
    }

    try {
      if (mode === 'create') {
        await onSubmit({
          name: name.trim(),
          repository_url: repoUrl.trim(),
          branch: effectiveBranch,
          background: background.trim() || null,
          include: parseList(includeText),
          exclude: parseList(excludeText),
        });
      } else {
        await onSubmit({
          name: name.trim(),
          background: background.trim() || null,
          include: parseList(includeText),
          exclude: parseList(excludeText),
        });
      }
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : '保存失败，请检查输入格式');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-2xl bg-obsidian-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-obsidian-950/60 shrink-0">
          <div className="flex items-center gap-2.5 text-brand-400 font-semibold text-sm">
            <div className="w-7 h-7 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center">
              <FolderGit2 className="w-4 h-4 text-brand-400" />
            </div>
            <span>{mode === 'create' ? '新建代码扫描项目' : '修改项目配置'}</span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors p-1 rounded-lg hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 overflow-y-auto flex-1">
          {error && (
            <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-xl text-xs text-rose-300 font-mono">
              {error}
            </div>
          )}

          {/* Repo URL & Branch (Create mode only) */}
          {mode === 'create' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                  Git 仓库地址 <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={repoUrl}
                  onChange={(e) => handleRepoUrlChange(e.target.value)}
                  placeholder="https://gitlab.company.example/security/backend.git"
                  className="w-full px-3.5 py-2.5 bg-obsidian-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 font-mono text-xs"
                />
                <p className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
                  <Info className="w-3 h-3 text-slate-500 shrink-0" />
                  <span>私有仓库凭据由部署宿主机的 Git Credential Helper 或 SSH 密钥安全提供，无需在 URL 中嵌入密码。</span>
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                  扫描分支 <span className="text-rose-400">*</span>
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {['main', 'master', 'custom'].map((b) => (
                    <button
                      key={b}
                      type="button"
                      onClick={() => setBranchChoice(b)}
                      className={`flex items-center justify-center gap-1.5 py-2 px-3 rounded-xl border text-xs font-mono transition-colors ${
                        branchChoice === b
                          ? 'bg-brand-500/10 border-brand-500/50 text-brand-300 font-medium'
                          : 'bg-obsidian-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <GitBranch className="w-3.5 h-3.5" />
                      <span>{b === 'custom' ? '自定义分支' : b}</span>
                    </button>
                  ))}
                </div>
                {branchChoice === 'custom' && (
                  <input
                    type="text"
                    required
                    value={customBranch}
                    onChange={(e) => setCustomBranch(e.target.value)}
                    placeholder="例如: release/v2.1 或 feature-auth"
                    className="mt-2 w-full px-3.5 py-2.5 bg-obsidian-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 font-mono text-xs"
                  />
                )}
              </div>
            </div>
          )}

          {/* Project Name */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              项目标识名称 <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              maxLength={256}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如: payment-gateway 或 internal-auth"
              className="w-full px-3.5 py-2.5 bg-obsidian-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 text-xs"
            />
          </div>

          {/* Business Background Knowledge for LLM */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5 flex items-center justify-between">
              <span>业务架构与审查背景 (Context)</span>
              <span className="text-[10px] text-slate-400 normal-case font-normal">提供给 LLM 辅助降低误报</span>
            </label>
            <textarea
              rows={3}
              value={background}
              onChange={(e) => setBackground(e.target.value)}
              placeholder="例如：这是基于 FastAPI + PostgreSQL 的支付前置系统，敏感参数已在上游 API 网关完成 HMAC 验签..."
              className="w-full px-3.5 py-2.5 bg-obsidian-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 text-xs leading-relaxed"
            />
          </div>

          {/* Scope Patterns */}
          <div className="space-y-3 pt-1">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              扫描文件范围过滤 (Path Filters)
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">包含路径 (Include)</label>
              <input
                type="text"
                value={includeText}
                onChange={(e) => setIncludeText(e.target.value)}
                placeholder="留空默认全仓扫描，多个路径用逗号分隔，如: src, app/api"
                className="w-full px-3.5 py-2 bg-obsidian-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 font-mono text-xs"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">排除路径 (Exclude)</label>
              <input
                type="text"
                value={excludeText}
                onChange={(e) => setExcludeText(e.target.value)}
                placeholder="例如: vendor, tests, **/generated/*"
                className="w-full px-3.5 py-2 bg-obsidian-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 font-mono text-xs"
              />
            </div>
          </div>

          {mode === 'edit' && (
            <div className="bg-amber-950/30 border border-amber-800/40 rounded-xl p-3 text-xs text-amber-300 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                注意：修改业务背景或文件过滤规则后，将重置基线提交记录，下次分析时系统将重新执行全仓扫描。
              </span>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              disabled={busy}
              className="px-4 py-2 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-xl transition-colors"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={busy}
              className="flex items-center gap-1.5 px-5 py-2 text-xs bg-brand-600 hover:bg-brand-500 active:bg-brand-700 text-white font-medium rounded-xl shadow-glow-sm transition-all disabled:opacity-50"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>{busy ? '正在保存...' : mode === 'create' ? '立即创建项目' : '保存修改'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { KeyRound, ShieldAlert, X, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { authStore } from '../../store/auth';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [keyInput, setKeyInput] = useState(authStore.getApiKey() || '');
  const [showKey, setShowKey] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = keyInput.trim();
    if (!trimmed) {
      setError('请输入有效的 Argus API Key');
      return;
    }
    authStore.setApiKey(trimmed);
    setError('');
    onClose();
    if (onSuccess) onSuccess();
  };

  const handleClear = () => {
    authStore.clearApiKey();
    setKeyInput('');
    setError('');
    onClose();
    if (onSuccess) onSuccess();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-obsidian-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-obsidian-950/60">
          <div className="flex items-center gap-2.5 text-brand-400 font-semibold text-sm">
            <div className="w-7 h-7 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center">
              <KeyRound className="w-4 h-4 text-brand-400" />
            </div>
            <span>Argus 访问凭据配置</span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors p-1 rounded-lg hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Security Compliance Notice */}
          <div className="bg-amber-950/30 border border-amber-800/40 rounded-xl p-3.5 text-xs text-amber-200/90 flex items-start gap-3">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-medium text-amber-300">仅内存隔离安全存储</p>
              <p className="text-[11px] text-amber-200/80 leading-relaxed">
                遵循企业内部白盒安全规范：API Key 仅在当前网页会话内存中维持，绝不写入 LocalStorage、Cookie、查询参数或任何存储介质。刷新或关闭页面即安全清空。
              </p>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
              Argus Bearer API Key
            </label>
            <div className="relative">
              <input
                type={showKey ? 'text' : 'password'}
                value={keyInput}
                onChange={(e) => {
                  setKeyInput(e.target.value);
                  setError('');
                }}
                placeholder="argus-sec-..."
                autoFocus
                className="w-full pl-3.5 pr-10 py-2.5 bg-obsidian-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/40 focus:border-brand-500 font-mono text-xs transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
                title={showKey ? '隐藏密钥' : '显示密钥'}
              >
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {error && <p className="text-xs text-rose-400 mt-1.5 font-mono">{error}</p>}
          </div>

          <div className="flex items-center justify-between pt-2">
            {authStore.getApiKey() ? (
              <button
                type="button"
                onClick={handleClear}
                className="px-3 py-1.5 text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-950/30 rounded-lg transition-colors font-mono"
              >
                清除当前凭据
              </button>
            ) : <span />}

            <div className="flex gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-xl transition-colors"
              >
                取消
              </button>
              <button
                type="submit"
                className="flex items-center gap-1.5 px-4 py-2 text-xs bg-brand-600 hover:bg-brand-500 active:bg-brand-700 text-white font-medium rounded-xl shadow-glow-sm transition-all"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>保存并连接</span>
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

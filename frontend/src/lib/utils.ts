import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(isoString: string | null | undefined): string {
  if (!isoString) return '-';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString('zh-CN', {
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return isoString;
  }
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || isNaN(seconds)) return '0s';
  const sec = Math.max(0, Math.floor(seconds));
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const remSec = sec % 60;
  if (min < 60) return `${min}m ${remSec}s`;
  const hr = Math.floor(min / 60);
  const remMin = min % 60;
  return `${hr}h ${remMin}m`;
}

export function truncateSha(sha: string | null | undefined): string {
  if (!sha) return '-';
  return sha.slice(0, 8);
}

/**
 * Validates Git URL against Argus security boundary:
 * 1. Must not embed userinfo (passwords or tokens)
 * 2. Must be a safe HTTPS, SSH, Git, or SCP URL
 */
export function validateGitUrl(url: string): { isValid: boolean; error?: string } {
  const trimmed = url.trim();
  if (!trimmed) {
    return { isValid: false, error: '请输入 Git 仓库地址' };
  }

  // Check for credentials in URL
  if (trimmed.includes('@') && (trimmed.startsWith('http://') || trimmed.startsWith('https://'))) {
    const authority = trimmed.split('://')[1]?.split('/')[0] || '';
    if (authority.includes('@')) {
      return {
        isValid: false,
        error: '安全拦截：禁止在 Git URL 中嵌入用户名、密码或 Token。私有仓库凭据由服务端 Git 凭据助手提供。',
      };
    }
  }

  return { isValid: true };
}

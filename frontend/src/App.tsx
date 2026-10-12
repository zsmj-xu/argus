import { useState, useEffect, useCallback } from 'react';
import {
  Header,
} from './components/layout/Header';
import { AuthModal } from './components/layout/AuthModal';
import { ProjectsDashboard } from './components/projects/ProjectsDashboard';
import { ProjectWorkspace } from './components/projects/ProjectWorkspace';
import { ProjectModal } from './components/projects/ProjectModal';
import { ScanDetailView } from './components/detail/ScanDetailView';
import { authStore } from './store/auth';
import {
  listProjects,
  getProject,
  createProject,
  updateProject,
  listProjectScans,
  triggerProjectScan,
  listProjectVulnerabilities,
  updateVulnerabilityStatus,
  downloadProjectReport,
} from './api/projects';
import { cancelScan, retryScan } from './api/scans';
import {
  Project,
  ScanResponse,
  Vulnerability,
  VulnerabilityStatus,
  ReportFormat,
  ProjectCreatePayload,
  ProjectUpdatePayload,
} from './types/api';
import { AlertCircle, Key, Shield } from 'lucide-react';

const FAILURE_LABELS: Record<string, string> = {
  git_baseline_missing: '上次分析的基线提交在远端已不存在，请执行“重新全仓分析”。',
  git_baseline_diverged: '分支提交历史已被强推或分叉改变，请执行“重新全仓分析”。',
  git_ref_missing: '扫描的目标分支不存在，请检查项目配置中的分支名称。',
  git_auth: 'Git 仓库拉取鉴权失败，请检查服务部署宿主机的只读凭据或 SSH 密钥。',
  git_limit: '仓库文件数或磁盘空间超出限制。',
  ocr_timeout: '白盒分析模型响应超时，可尝试从头重试原版本。',
  'this project already has an active scan': '本项目已有排队或运行中的分析任务。',
  'project baseline or configuration changed; start a new scan':
    '项目基线或范围配置已变更，请在项目主页启动新扫描。',
  'a project for this repository and branch already exists':
    '该仓库与分支已存在对应项目，不可重复创建。',
  'Failed to fetch': '暂时无法连接 Argus 后端服务，请检查网络或刷新页面。',
};

function formatErrorMessage(msg: string): string {
  if (FAILURE_LABELS[msg]) return FAILURE_LABELS[msg];
  for (const [key, val] of Object.entries(FAILURE_LABELS)) {
    if (msg.includes(key)) return val;
  }
  return msg;
}

function parseHashRoute() {
  const hash = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash;
  const params = new URLSearchParams(hash);
  return {
    projectId: params.get('project') || null,
    scanId: params.get('scan') || null,
    tab: (params.get('tab') as 'vulnerabilities' | 'scans' | 'scope') || 'vulnerabilities',
    isCreateModal: params.get('create') === '1',
  };
}

export function App() {
  const [route, setRoute] = useState(parseHashRoute);
  const [hasAuth, setHasAuth] = useState(!!authStore.getApiKey());
  const [authModalOpen, setAuthModalOpen] = useState(false);

  // Projects list state
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsTotal, setProjectsTotal] = useState(0);
  const [projectPage, setProjectPage] = useState(1);
  const pageSize = 12;

  // Selected project state
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [projectScans, setProjectScans] = useState<ScanResponse[]>([]);
  const [scansTotal, setScansTotal] = useState(0);
  const [scanPage, setScanPage] = useState(1);
  const [projectVulns, setProjectVulns] = useState<Vulnerability[]>([]);
  const [vulnsTotal, setVulnsTotal] = useState(0);
  const [vulnPage, setVulnPage] = useState(1);
  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'scans' | 'scope'>('vulnerabilities');

  // Filters for vulnerabilities
  const [vulnFilters, setVulnFilters] = useState<{
    status?: string;
    severity?: string;
    category?: string;
    search?: string;
  }>({});

  // Modals & UI states
  const [projectModalOpen, setProjectModalOpen] = useState(false);
  const [projectModalMode, setProjectModalMode] = useState<'create' | 'edit'>('create');
  const [busy, setBusy] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  // Handle URL hash changes
  useEffect(() => {
    const handleHashChange = () => {
      const parsed = parseHashRoute();
      setRoute(parsed);
      if (parsed.tab) setActiveTab(parsed.tab);
      if (parsed.isCreateModal) {
        setProjectModalMode('create');
        setProjectModalOpen(true);
      }
      setErrorMessage('');
    };

    window.addEventListener('hashchange', handleHashChange);
    const unsub = authStore.subscribe((key) => {
      setHasAuth(!!key);
      if (!key) {
        setProjects([]);
        setCurrentProject(null);
        setAuthModalOpen(true);
      }
    });

    return () => {
      window.removeEventListener('hashchange', handleHashChange);
      unsub();
    };
  }, []);

  // Navigation handlers
  const navigateToHome = () => {
    window.location.hash = '';
  };

  const navigateToProject = (projectId: string, tab: string = 'vulnerabilities') => {
    window.location.hash = `project=${encodeURIComponent(projectId)}&tab=${encodeURIComponent(tab)}`;
  };

  const navigateToScan = (projectId: string, scanId: string) => {
    window.location.hash = `project=${encodeURIComponent(projectId)}&scan=${encodeURIComponent(scanId)}`;
  };

  // Data Loading
  const loadData = useCallback(async () => {
    if (!hasAuth) return;

    // View 1: Projects Dashboard
    if (!route.projectId) {
      const res = await listProjects(pageSize, (projectPage - 1) * pageSize);
      setProjects(res.items);
      setProjectsTotal(res.total);
      return;
    }

    // View 2 or 3: Project Detail or Scan Detail
    const proj = await getProject(route.projectId);
    setCurrentProject(proj);

    // If viewing scan detail, ScanDetailView handles scan polling
    if (route.scanId) {
      return;
    }

    // Load Project's Scans and Vulnerabilities
    const [scansRes, vulnsRes] = await Promise.all([
      listProjectScans(route.projectId, 20, (scanPage - 1) * 20),
      listProjectVulnerabilities(route.projectId, {
        limit: 20,
        offset: (vulnPage - 1) * 20,
        status: vulnFilters.status,
        severity: vulnFilters.severity,
        category: vulnFilters.category,
        search: vulnFilters.search,
      }),
    ]);

    setProjectScans(scansRes.items);
    setScansTotal(scansRes.total);
    setProjectVulns(vulnsRes.items);
    setVulnsTotal(vulnsRes.total);
  }, [hasAuth, route.projectId, route.scanId, projectPage, scanPage, vulnPage, vulnFilters]);

  // Refresh with loading indicator
  const handleRefresh = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage('');
    try {
      await loadData();
    } catch (err: any) {
      setErrorMessage(err?.message || '读取数据失败');
    } finally {
      setIsLoading(false);
    }
  }, [loadData]);

  // Initial load & reaction to dependencies
  useEffect(() => {
    void handleRefresh();
  }, [handleRefresh]);

  // Auto-poll if a project has an active scan
  useEffect(() => {
    if (!hasAuth || !route.projectId || route.scanId) return;
    const interval = window.setInterval(() => {
      void loadData().catch(() => {});
    }, 3500);
    return () => window.clearInterval(interval);
  }, [hasAuth, route.projectId, route.scanId, loadData]);

  // Project Action Handlers
  const handleStartScan = async (mode: 'auto' | 'full') => {
    if (!currentProject) return;
    setBusy(true);
    setErrorMessage('');
    try {
      const scan = await triggerProjectScan(currentProject.id, mode, true);
      navigateToScan(currentProject.id, scan.id);
    } catch (err: any) {
      setErrorMessage(formatErrorMessage(err?.message || '启动扫描失败'));
    } finally {
      setBusy(false);
    }
  };

  const handleCancelScan = async (scanId: string) => {
    setBusy(true);
    try {
      await cancelScan(scanId);
      await loadData();
    } catch (err: any) {
      setErrorMessage(formatErrorMessage(err?.message || '取消扫描失败'));
    } finally {
      setBusy(false);
    }
  };

  const handleRetryScan = async (scanId: string) => {
    setBusy(true);
    try {
      await retryScan(scanId);
      await loadData();
    } catch (err: any) {
      setErrorMessage(formatErrorMessage(err?.message || '重试失败'));
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateVulnStatus = async (vulnId: string, status: VulnerabilityStatus) => {
    if (!currentProject) return;
    setBusy(true);
    try {
      // Optimistic update
      setProjectVulns((prev) =>
        prev.map((v) => (v.id === vulnId ? { ...v, status } : v))
      );
      await updateVulnerabilityStatus(currentProject.id, vulnId, status);
      await loadData();
    } catch (err: any) {
      setErrorMessage(err?.message || '更新状态失败');
      await loadData();
    } finally {
      setBusy(false);
    }
  };

  const handleDownloadReport = async (format: ReportFormat) => {
    if (!currentProject) return;
    setBusy(true);
    try {
      await downloadProjectReport(currentProject.id, format);
    } catch (err: any) {
      setErrorMessage(err?.message || '导出报告失败');
    } finally {
      setBusy(false);
    }
  };

  const handleSaveProject = async (
    payload: ProjectCreatePayload | ProjectUpdatePayload
  ) => {
    setBusy(true);
    try {
      if (projectModalMode === 'create') {
        const created = await createProject(payload as ProjectCreatePayload);
        setProjectModalOpen(false);
        navigateToProject(created.id);
      } else if (currentProject) {
        const updated = await updateProject(currentProject.id, payload as ProjectUpdatePayload);
        setCurrentProject(updated);
        setProjectModalOpen(false);
        await loadData();
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-obsidian-950 text-slate-100 flex flex-col font-sans">
      {/* Global Persistent Header */}
      <Header
        currentProjectId={route.projectId}
        currentProjectName={currentProject?.name}
        currentScanId={route.scanId}
        onNavigateHome={navigateToHome}
        onNavigateProject={(id) => navigateToProject(id)}
        onOpenNewProject={() => {
          if (!hasAuth) {
            setAuthModalOpen(true);
          } else {
            setProjectModalMode('create');
            setProjectModalOpen(true);
          }
        }}
        onOpenAuth={() => setAuthModalOpen(true)}
      />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 flex-1 space-y-6">
        {/* Error Notification Banner */}
        {errorMessage && (
          <div
            role="alert"
            className="argus-panel border-rose-800/80 bg-rose-950/40 p-4 text-xs text-rose-300 flex items-start justify-between gap-3 animate-in fade-in duration-150"
          >
            <div className="flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <span className="font-semibold block text-rose-200">操作提示</span>
                <span className="leading-relaxed">{formatErrorMessage(errorMessage)}</span>
              </div>
            </div>
            <button
              onClick={() => setErrorMessage('')}
              className="text-rose-400 hover:text-rose-200 text-xs font-mono"
            >
              关闭
            </button>
          </div>
        )}

        {/* Unauthenticated Onboarding Banner */}
        {!hasAuth ? (
          <div className="argus-panel p-12 sm:p-20 text-center max-w-2xl mx-auto space-y-6 shadow-glow-sm">
            <div className="w-16 h-16 rounded-2xl bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 mx-auto shadow-glow-sm">
              <Shield className="w-8 h-8" />
            </div>

            <div className="space-y-2">
              <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100">
                连接 Argus 白盒安全审查平台
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 max-w-md mx-auto leading-relaxed">
                Argus 是内部专用的代码白盒安全审查服务，基于 OpenCodeReview 引擎与 LLM 自动化审计。请输入 Bearer API Key 以开始管理代码资产与执行扫描。
              </p>
            </div>

            <button
              onClick={() => setAuthModalOpen(true)}
              className="inline-flex items-center gap-2 px-6 py-2.5 bg-brand-600 hover:bg-brand-500 active:bg-brand-700 text-white rounded-xl text-xs sm:text-sm font-medium shadow-glow-sm transition-all"
            >
              <Key className="w-4 h-4" />
              <span>配置 API Key 连接服务</span>
            </button>
          </div>
        ) : (
          <>
            {/* View 1: Scan Detail View */}
            {route.scanId && (
              <ScanDetailView
                scanId={route.scanId}
                onBack={() => {
                  if (route.projectId) navigateToProject(route.projectId, 'scans');
                  else navigateToHome();
                }}
              />
            )}

            {/* View 2: Project Workspace */}
            {route.projectId && !route.scanId && currentProject && (
              <ProjectWorkspace
                project={currentProject}
                scans={projectScans}
                scansTotal={scansTotal}
                scanPage={scanPage}
                vulnerabilities={projectVulns}
                vulnsTotal={vulnsTotal}
                vulnPage={vulnPage}
                isLoading={isLoading}
                busy={busy}
                activeTab={activeTab}
                onTabChange={(tab) => {
                  setActiveTab(tab);
                  navigateToProject(currentProject.id, tab);
                }}
                onScanPageChange={setScanPage}
                onVulnPageChange={setVulnPage}
                onFilterChange={(filters) => {
                  setVulnFilters((prev) => ({ ...prev, ...filters }));
                  setVulnPage(1);
                }}
                onStartScan={handleStartScan}
                onCancelScan={handleCancelScan}
                onRetryScan={handleRetryScan}
                onSelectScan={(id) => navigateToScan(currentProject.id, id)}
                onUpdateVulnStatus={handleUpdateVulnStatus}
                onOpenEditModal={() => {
                  setProjectModalMode('edit');
                  setProjectModalOpen(true);
                }}
                onDownloadReport={handleDownloadReport}
                onRefresh={handleRefresh}
              />
            )}

            {/* View 3: Projects Dashboard (Home) */}
            {!route.projectId && !route.scanId && (
              <ProjectsDashboard
                projects={projects}
                total={projectsTotal}
                page={projectPage}
                pageSize={pageSize}
                isLoading={isLoading}
                onPageChange={setProjectPage}
                onSelectProject={(id) => navigateToProject(id)}
                onOpenCreateModal={() => {
                  setProjectModalMode('create');
                  setProjectModalOpen(true);
                }}
                onRefresh={handleRefresh}
              />
            )}
          </>
        )}
      </main>

      {/* Global Modals */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onSuccess={() => void handleRefresh()}
      />

      <ProjectModal
        isOpen={projectModalOpen}
        mode={projectModalMode}
        project={projectModalMode === 'edit' ? currentProject : null}
        busy={busy}
        onClose={() => setProjectModalOpen(false)}
        onSubmit={handleSaveProject}
      />
    </div>
  );
}

const root = document.documentElement;
const sidebar = document.querySelector("#sidebar");
const sidebarScrim = document.querySelector("#sidebar-scrim");
const menuButton = document.querySelector("#menu-button");
const themeToggle = document.querySelector("#theme-toggle");
const scanModal = document.querySelector("#scan-modal");
const interventionModal = document.querySelector("#intervention-modal");
const findingDrawer = document.querySelector("#finding-drawer");
const artifactModal = document.querySelector("#artifact-modal");
const scanForm = document.querySelector("#scan-form");
const interventionForm = document.querySelector("#intervention-form");
const toast = document.querySelector("#toast");
const searchInput = document.querySelector("#finding-search");
const findingsBody = document.querySelector("#findings-body");
const approveButton = document.querySelector("#approve-review");
const exportButton = document.querySelector("#export-report");
let lastFocusedElement = null;
let toastTimer = null;
let refreshTimer = null;
let dashboardData = null;
let selectedWorkspace = null;
let currentFindings = [];
let allFindings = [];
let currentDrawerFinding = null;
let settingsData = null;
let currentView = "overview";
let findingsWorkspaceScope = "all";
let findingsLoadRequest = 0;
let artifactLogWorkspace = null;
let artifactRefreshTimer = null;

function setTheme(theme) {
  root.dataset.theme = theme;
  localStorage.setItem("argus-theme", theme);
  themeToggle.setAttribute("aria-label", theme === "dark" ? "切换浅色主题" : "切换深色主题");
}

setTheme(localStorage.getItem("argus-theme") || "dark");

themeToggle.addEventListener("click", () => {
  setTheme(root.dataset.theme === "dark" ? "light" : "dark");
});

function setSidebar(open) {
  sidebar.classList.toggle("open", open);
  sidebarScrim.hidden = !open;
  menuButton.setAttribute("aria-expanded", String(open));
  menuButton.setAttribute("aria-label", open ? "关闭主导航" : "打开主导航");
}

menuButton.addEventListener("click", () => setSidebar(!sidebar.classList.contains("open")));
sidebarScrim.addEventListener("click", () => setSidebar(false));

function getFocusable(container) {
  return [...container.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
  )].filter((element) => !element.hasAttribute("hidden"));
}

function openLayer(layer) {
  lastFocusedElement = document.activeElement;
  layer.hidden = false;
  document.body.style.overflow = "hidden";
  requestAnimationFrame(() => getFocusable(layer)[0]?.focus());
}

function closeLayer(layer) {
  layer.hidden = true;
  document.body.style.overflow = "";
  lastFocusedElement?.focus();
}

function trapFocus(event, layer) {
  if (event.key !== "Tab") return;
  const focusable = getFocusable(layer);
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function showToast(title = "操作已完成", detail = "状态已更新。", isError = false) {
  toast.querySelector("strong").textContent = title;
  toast.querySelector("small").textContent = detail;
  toast.querySelector(".toast-icon").style.color = isError ? "var(--critical)" : "";
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.hidden = true;
  }, 4800);
}

toast.querySelector("button").addEventListener("click", () => {
  toast.hidden = true;
  clearTimeout(toastTimer);
});

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const message = typeof body === "object" && body?.error ? body.error : `请求失败（${response.status}）`;
    throw new Error(message);
  }
  return body;
}

function statusLabel(status) {
  return {
    running: "扫描运行中",
    checkpoint: "等待审阅",
    resumable: "可恢复",
    complete: "扫描完成",
    failed: "运行失败",
    created: "工作区已创建",
  }[status] || "状态未知";
}

function reviewStatusLabel(status) {
  return {
    confirmed: "已确认",
    false_positive: "误报",
    unreviewed: "未审阅",
  }[status] || "未审阅";
}

function artifactLabel(artifacts) {
  const labels = [];
  if (artifacts?.enriched) labels.push("富化图");
  if (artifacts?.findings) labels.push("发现");
  if (artifacts?.report) labels.push("报告");
  return labels.length ? labels.join("、") : "仅检查点";
}

function setText(selector, value) {
  const element = document.querySelector(selector);
  if (element) element.textContent = value;
}

function populateWorkspaceSelect(workspaces, selectedName) {
  const select = document.querySelector("#workspace-select");
  select.replaceChildren();
  if (!workspaces.length) {
    const option = document.createElement("option");
    option.textContent = "尚无工作区";
    option.value = "";
    select.append(option);
    select.disabled = true;
    return;
  }
  select.disabled = false;
  workspaces.forEach((workspace) => {
    const option = document.createElement("option");
    option.value = workspace.workspace;
    option.textContent = workspace.workspace;
    option.selected = workspace.workspace === selectedName;
    select.append(option);
  });
}

function updatePipeline(workspace) {
  const stages = [...document.querySelectorAll(".pipeline li")];
  const artifacts = workspace?.artifacts || {};
  const complete = [
    Boolean(artifacts.state),
    Boolean(artifacts.enriched),
    Boolean(artifacts.findings),
    workspace?.status === "complete",
    Boolean(artifacts.report),
  ];
  let currentIndex = complete.findIndex((value) => !value);
  if (workspace?.status === "checkpoint") {
    currentIndex = 3;
  } else if (workspace?.status === "complete") {
    currentIndex = -1;
  }
  stages.forEach((stage, index) => {
    stage.classList.toggle("complete", complete[index]);
    stage.classList.toggle("current", index === currentIndex);
    const marker = stage.querySelector(".stage-marker");
    if (complete[index]) {
      marker.innerHTML = '<svg><use href="#i-check"></use></svg>';
    } else {
      marker.textContent = String(index + 1);
    }
    const detail = stage.querySelector("small");
    if (complete[index]) {
      detail.textContent = "已完成";
    } else if (index === currentIndex) {
      detail.textContent = workspace?.status === "checkpoint" ? "需要操作" : "当前阶段";
    } else {
      detail.textContent = "等待上游";
    }
  });
}

function renderWorkspace(workspace, workspaces) {
  selectedWorkspace = workspace;
  if (!workspace) {
    setText("#repo-label", "尚无工作区");
    setText("#active-run-title", "创建第一次扫描");
    setText("#active-run-description", "使用右上角“新建扫描”开始");
    setText("#active-run-status", "等待创建");
    setText("#metric-total", "0");
    setText("#metric-critical", "0");
    setText("#metric-high", "0");
    setText("#metric-workspaces", String(workspaces.length));
    setText("#scan-nav-count", String(workspaces.length));
    setText("#review-nav-count", "0");
    setText("#page-status-description", "还没有扫描工作区，创建第一次扫描即可开始。");
    setText("#page-heading-title", "创建第一次代码扫描");
    approveButton.disabled = true;
    exportButton.disabled = true;
    updatePipeline(null);
    return;
  }

  const status = workspace.status;
  const statusChip = document.querySelector("#active-run-status");
  statusChip.className = `status-chip ${status === "checkpoint" ? "warning" : status}`;
  statusChip.innerHTML = `<span class="status-dot"></span>${statusLabel(status)}`;
  setText("#repo-label", workspace.workspace);
  setText("#active-run-title", workspace.workspace);
  setText(
    "#active-run-description",
    `runs/${workspace.workspace} · ${workspace.finding_count} 条发现 · ${statusLabel(status)}`
  );
  setText("#metric-total", String(workspace.finding_count));
  setText("#metric-critical", String(workspace.severity_counts.critical || 0));
  setText("#metric-high", String(workspace.severity_counts.high || 0));
  setText("#metric-workspaces", String(workspaces.length));
  setText("#scan-nav-count", String(workspaces.length));
  const needsAction = status === "checkpoint" || status === "resumable";
  setText("#review-nav-count", needsAction ? "1" : "0");
  setText("#review-count", needsAction ? "1" : "0");
  setText(
    "#review-summary",
    status === "checkpoint"
      ? "1 个检查点需要确认"
      : status === "resumable"
        ? "1 个中断任务可以恢复"
        : "当前没有待办检查点"
  );
  setText(
    "#page-status-description",
    status === "checkpoint"
      ? `${workspace.workspace} 已暂停在人工检查点，等待你的确认。`
      : status === "resumable"
        ? `${workspace.workspace} 曾被中断，可以从最近状态恢复。`
        : status === "running"
          ? `${workspace.workspace} 正在后台运行，状态会自动更新。`
          : `${workspace.workspace} 已完成，可以查看发现并导出报告。`
  );
  setText(
    "#page-heading-title",
    status === "checkpoint"
      ? "有一个检查点等待审阅。"
      : status === "resumable"
        ? "有一个扫描可以恢复。"
        : status === "running"
          ? "扫描正在后台运行。"
          : "扫描结果已经就绪。"
  );
  setText(
    "#review-findings-summary",
    `${workspace.finding_count} 条发现 · ${workspace.severity_counts.critical || 0} 条严重风险`
  );
  setText(
    "#review-primary-title",
    !needsAction
      ? "当前没有待办操作"
      : status === "resumable"
        ? "恢复中断的扫描"
        : workspace.artifacts.findings
          ? "确认关键发现"
          : "检查语义富化结果"
  );
  document.querySelector("#review-primary-action").disabled = !needsAction;
  const artifactCount = Object.values(workspace.artifacts).filter(Boolean).length;
  setText("#review-artifacts-summary", `${artifactCount} / 4 个工作区产物可用`);
  approveButton.disabled = !needsAction;
  approveButton.innerHTML =
    status === "resumable"
      ? '<svg><use href="#i-arrow"></use></svg>恢复扫描'
      : workspace.artifacts.findings
        ? '<svg><use href="#i-check"></use></svg>批准并生成报告'
        : '<svg><use href="#i-check"></use></svg>批准并继续分析';
  exportButton.disabled = !workspace.artifacts.report;
  updatePipeline(workspace);
}

function severityLabel(severity) {
  return {
    critical: "严重",
    high: "高危",
    medium: "中危",
    low: "低危",
    info: "提示",
  }[severity] || severity || "未知";
}

function confidenceLabel(confidence) {
  return { high: "高", medium: "中", low: "低" }[confidence] || confidence || "未知";
}

function createCell() {
  return document.createElement("td");
}

function renderFindings(findings) {
  currentFindings = findings;
  findingsBody.replaceChildren();
  if (!findings.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = createCell();
    cell.colSpan = 6;
    cell.textContent = "当前工作区还没有漏洞发现。运行分析或选择其他工作区后会显示在这里。";
    row.append(cell);
    findingsBody.append(row);
    setText("#findings-count", "显示 0 条发现");
    return;
  }

  findings.slice(0, 50).forEach((finding, index) => {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.dataset.findingIndex = String(index);
    row.dataset.severity = finding.severity || "info";

    const severityCell = createCell();
    const severity = document.createElement("span");
    severity.className = `severity-chip ${finding.severity || "info"}`;
    severity.textContent = severityLabel(finding.severity);
    severityCell.append(severity);

    const titleCell = createCell();
    const title = document.createElement("strong");
    title.textContent = finding.title || "未命名发现";
    const summary = document.createElement("small");
    const reviewSuffix = finding.review_status ? ` · ${reviewStatusLabel(finding.review_status)}` : "";
    summary.textContent = `${finding.rationale || finding.evidence || "暂无风险说明"}${reviewSuffix}`;
    titleCell.append(title, summary);

    const classCell = createCell();
    const classChip = document.createElement("span");
    classChip.className = "class-chip";
    classChip.textContent = (finding.vuln_class || finding.analyzer || "UNKNOWN").toUpperCase();
    classCell.append(classChip);

    const locationCell = createCell();
    const location = finding.locations?.[0];
    const locationLabel = document.createElement("span");
    locationLabel.className = "file-link mono";
    locationLabel.textContent = location ? `${location.file}:${location.line}` : "未提供位置";
    locationCell.append(locationLabel);

    const confidenceCell = createCell();
    const confidence = document.createElement("span");
    confidence.className = "confidence";
    confidence.innerHTML = "<i></i><i></i><i></i>";
    confidence.append(document.createTextNode(confidenceLabel(finding.confidence)));
    confidenceCell.append(confidence);

    const actionCell = createCell();
    const action = document.createElement("button");
    action.className = "row-action";
    action.setAttribute("aria-label", `查看${finding.title || "漏洞"}详情`);
    action.innerHTML = '<svg><use href="#i-chevron"></use></svg>';
    actionCell.append(action);

    row.append(severityCell, titleCell, classCell, locationCell, confidenceCell, actionCell);
    findingsBody.append(row);
  });
  setText("#findings-count", `显示 ${Math.min(findings.length, 50)} / ${findings.length} 条发现`);
}

function renderRisk(findings, severityCounts) {
  const classCounts = new Map();
  findings.forEach((finding) => {
    const name = finding.vuln_class || finding.analyzer || "unknown";
    classCounts.set(name, (classCounts.get(name) || 0) + 1);
  });
  const sorted = [...classCounts.entries()].sort((left, right) => right[1] - left[1]).slice(0, 5);
  const total = findings.length;
  const leading = sorted[0] || ["暂无数据", 0];
  const percentage = total ? Math.round((leading[1] / total) * 100) : 0;
  setText("#metric-classes", String(classCounts.size));
  setText("#risk-concentration", `${percentage}%`);
  setText("#risk-concentration-label", total ? `来自 ${leading[0]}` : "暂无发现");

  const bars = document.querySelector("#risk-bars");
  bars.replaceChildren();
  (sorted.length ? sorted : [["暂无数据", 0]]).forEach(([name, count]) => {
    const row = document.createElement("div");
    row.className = "bar-row";
    const label = document.createElement("span");
    label.textContent = name;
    const track = document.createElement("div");
    track.className = "bar-track";
    const bar = document.createElement("span");
    bar.style.setProperty("--bar-width", `${total ? Math.max(5, Math.round((count / total) * 100)) : 0}%`);
    track.append(bar);
    const value = document.createElement("strong");
    value.textContent = String(count);
    row.append(label, track, value);
    bars.append(row);
  });
  document.querySelector("#risk-summary").setAttribute(
    "aria-label",
    total ? `${leading[0]} 占全部发现的 ${percentage}%` : "当前没有风险分布数据"
  );
  document.querySelector("#chart-legend").innerHTML = `
    <span><i class="severity-mark critical"></i>严重 ${severityCounts.critical || 0}</span>
    <span><i class="severity-mark high"></i>高危 ${severityCounts.high || 0}</span>
    <span><i class="severity-mark medium"></i>中危 ${severityCounts.medium || 0}</span>
  `;
}

function showFinding(finding) {
  if (!finding) return;
  currentDrawerFinding = finding;
  const location = finding.locations?.[0];
  const severity = document.querySelector("#drawer-severity");
  severity.className = `severity-chip ${finding.severity || "info"}`;
  severity.textContent = severityLabel(finding.severity);
  setText("#drawer-title", finding.title || "未命名发现");
  setText("#drawer-id", finding.id || "无稳定 ID");
  setText("#drawer-analyzer", finding.analyzer || "unknown");
  setText("#drawer-confidence", confidenceLabel(finding.confidence));
  setText("#drawer-class", finding.vuln_class || "unknown");
  setText("#drawer-rationale", finding.rationale || "暂无风险说明。");
  setText("#drawer-location", location ? `${location.file}:${location.line}` : "未提供代码位置");
  setText("#drawer-remediation", finding.remediation || "暂无修复建议。");

  const evidenceCode = document.querySelector("#drawer-evidence code");
  evidenceCode.textContent = finding.evidence || "暂无证据文本。";
  const dataFlow = document.querySelector("#drawer-data-flow");
  dataFlow.replaceChildren();
  const item = document.createElement("li");
  const label = document.createElement("span");
  label.textContent = "分析路径";
  const value = document.createElement("strong");
  value.textContent = finding.data_flow || "暂无数据流描述。";
  item.append(label, value);
  dataFlow.append(item);
  const falsePositiveButton = document.querySelector("#mark-false-positive");
  const confirmButton = document.querySelector("#confirm-finding");
  falsePositiveButton.textContent =
    finding.review_status === "false_positive" ? "取消误报标记" : "标记误报";
  confirmButton.innerHTML =
    finding.review_status === "confirmed"
      ? '<svg><use href="#i-close"></use></svg>取消确认'
      : '<svg><use href="#i-check"></use></svg>确认发现';
  openLayer(findingDrawer);
}

function miniButton(label, action, workspace, primary = false) {
  const button = document.createElement("button");
  button.className = `mini-button${primary ? " primary" : ""}`;
  button.textContent = label;
  button.dataset.action = action;
  if (workspace) button.dataset.workspace = workspace;
  return button;
}

function statusChip(status) {
  const chip = document.createElement("span");
  chip.className = `status-chip ${status === "checkpoint" ? "warning" : status}`;
  const dot = document.createElement("span");
  dot.className = "status-dot";
  chip.append(dot, document.createTextNode(statusLabel(status)));
  return chip;
}

function renderScans(workspaces) {
  const body = document.querySelector("#scans-body");
  body.replaceChildren();
  if (!workspaces.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = createCell();
    cell.colSpan = 6;
    cell.textContent = "还没有扫描任务。使用“新建扫描”创建第一个工作区。";
    row.append(cell);
    body.append(row);
    return;
  }
  workspaces.forEach((workspace) => {
    const row = document.createElement("tr");
    const workspaceCell = createCell();
    const name = document.createElement("strong");
    name.textContent = workspace.workspace;
    const detail = document.createElement("small");
    detail.textContent = workspace.job?.action
      ? `后台操作：${workspace.job.action}`
      : `runs/${workspace.workspace}`;
    workspaceCell.append(name, detail);

    const statusCell = createCell();
    statusCell.append(statusChip(workspace.status));

    const findingsCell = createCell();
    findingsCell.textContent = `${workspace.finding_count} 条`;

    const artifactsCell = createCell();
    artifactsCell.textContent = artifactLabel(workspace.artifacts);

    const updatedCell = createCell();
    updatedCell.textContent = new Date(workspace.updated_at * 1000).toLocaleString();

    const actionsCell = createCell();
    const actions = document.createElement("div");
    actions.className = "table-row-actions";
    actions.append(miniButton("选择", "select", workspace.workspace));
    actions.append(miniButton("日志", "log", workspace.workspace));
    if (workspace.artifacts.report) {
      actions.append(miniButton("报告", "report", workspace.workspace));
    }
    if (workspace.status === "checkpoint") {
      actions.append(miniButton("批准", "continue", workspace.workspace, true));
    } else if (workspace.status === "resumable") {
      actions.append(miniButton("恢复", "resume", workspace.workspace, true));
    }
    actionsCell.append(actions);
    row.append(workspaceCell, statusCell, findingsCell, artifactsCell, updatedCell, actionsCell);
    body.append(row);
  });
}

function renderReviewQueue(workspaces) {
  const queue = document.querySelector("#review-queue");
  queue.replaceChildren();
  const actionable = workspaces.filter((workspace) =>
    ["checkpoint", "resumable"].includes(workspace.status)
  );
  if (!actionable.length) {
    const empty = document.createElement("div");
    empty.className = "queue-card";
    const title = document.createElement("h2");
    title.textContent = "队列已清空";
    const copy = document.createElement("p");
    copy.textContent = "当前没有人工检查点或可恢复的中断任务。";
    empty.append(title, copy);
    queue.append(empty);
    return;
  }
  actionable.forEach((workspace) => {
    const card = document.createElement("article");
    card.className = "queue-card";
    const header = document.createElement("div");
    header.className = "queue-card-header";
    const titleWrap = document.createElement("div");
    const title = document.createElement("h2");
    title.textContent = workspace.workspace;
    const copy = document.createElement("p");
    copy.textContent =
      workspace.status === "checkpoint"
        ? "扫描已安全暂停，等待人工确认产物。"
        : "扫描曾被中断，可以从最近的持久化状态恢复。";
    titleWrap.append(title, copy);
    header.append(titleWrap, statusChip(workspace.status));

    const meta = document.createElement("div");
    meta.className = "queue-meta";
    meta.textContent = `${workspace.finding_count} 条发现 · ${artifactLabel(workspace.artifacts)} · ${new Date(
      workspace.updated_at * 1000
    ).toLocaleString()}`;

    const actions = document.createElement("div");
    actions.className = "queue-actions";
    actions.append(miniButton("查看日志", "log", workspace.workspace));
    actions.append(
      miniButton(
        workspace.status === "checkpoint" ? "批准并继续" : "恢复扫描",
        workspace.status === "checkpoint" ? "continue" : "resume",
        workspace.workspace,
        true
      )
    );
    card.append(header, meta, actions);
    queue.append(card);
  });
}

function renderReports(workspaces) {
  const list = document.querySelector("#reports-list");
  list.replaceChildren();
  const reports = workspaces.filter((workspace) => workspace.artifacts.report);
  if (!reports.length) {
    const empty = document.createElement("article");
    empty.className = "report-card";
    const title = document.createElement("h2");
    title.textContent = "还没有可用报告";
    const copy = document.createElement("p");
    copy.textContent = "扫描通过最后一个检查点后，Markdown 报告会出现在这里。";
    empty.append(title, copy);
    list.append(empty);
    return;
  }
  reports.forEach((workspace) => {
    const card = document.createElement("article");
    card.className = "report-card";
    const header = document.createElement("div");
    header.className = "report-card-header";
    const titleWrap = document.createElement("div");
    const title = document.createElement("h2");
    title.textContent = workspace.workspace;
    const copy = document.createElement("p");
    copy.textContent = `${workspace.finding_count} 条发现`;
    titleWrap.append(title, copy);
    const icon = document.createElement("span");
    icon.className = "report-icon";
    icon.innerHTML = '<svg><use href="#i-report"></use></svg>';
    header.append(titleWrap, icon);
    const meta = document.createElement("div");
    meta.className = "report-meta";
    meta.textContent = `${workspace.severity_counts.critical || 0} 严重 · ${
      workspace.severity_counts.high || 0
    } 高危 · ${new Date(workspace.updated_at * 1000).toLocaleString()}`;
    const actions = document.createElement("div");
    actions.className = "report-actions";
    actions.append(miniButton("预览", "preview-report", workspace.workspace));
    actions.append(miniButton("下载", "download-report", workspace.workspace, true));
    card.append(header, meta, actions);
    list.append(card);
  });
}

function reviewStatusChip(status) {
  const chip = document.createElement("span");
  chip.className = `review-status ${status || "unreviewed"}`;
  chip.textContent = reviewStatusLabel(status);
  return chip;
}

function renderAllFindings() {
  const body = document.querySelector("#all-findings-body");
  const query = document.querySelector("#all-findings-search").value.trim().toLowerCase();
  const severity = document.querySelector("#all-severity-filter").value;
  const workspace = document.querySelector("#all-workspace-filter").value;
  const filtered = allFindings.filter((finding) => {
    const haystack = `${finding.title || ""} ${finding.rationale || ""} ${
      finding.locations?.[0]?.file || ""
    } ${finding._workspace || ""}`.toLowerCase();
    return (
      (!query || haystack.includes(query)) &&
      (severity === "all" || finding.severity === severity) &&
      (workspace === "all" || finding._workspace === workspace)
    );
  });
  body.replaceChildren();
  if (!filtered.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = createCell();
    cell.colSpan = 6;
    cell.textContent = "没有符合当前筛选条件的漏洞发现。";
    row.append(cell);
    body.append(row);
  } else {
    filtered.slice(0, 200).forEach((finding) => {
      const row = document.createElement("tr");
      row.tabIndex = 0;
      row.dataset.findingId = finding.id || "";
      row.dataset.workspace = finding._workspace || "";
      const severityCell = createCell();
      const severityChip = document.createElement("span");
      severityChip.className = `severity-chip ${finding.severity || "info"}`;
      severityChip.textContent = severityLabel(finding.severity);
      severityCell.append(severityChip);
      const titleCell = createCell();
      const title = document.createElement("strong");
      title.textContent = finding.title || "未命名发现";
      const summary = document.createElement("small");
      summary.textContent = finding.vuln_class || finding.analyzer || "unknown";
      titleCell.append(title, summary);
      const workspaceCell = createCell();
      workspaceCell.textContent = finding._workspace || "未知";
      const locationCell = createCell();
      locationCell.className = "mono";
      const location = finding.locations?.[0];
      locationCell.textContent = location ? `${location.file}:${location.line}` : "未提供位置";
      const statusCell = createCell();
      statusCell.append(reviewStatusChip(finding.review_status));
      const actionCell = createCell();
      const action = miniButton("查看", "finding", finding._workspace);
      action.dataset.findingId = finding.id || "";
      actionCell.append(action);
      row.append(severityCell, titleCell, workspaceCell, locationCell, statusCell, actionCell);
      body.append(row);
    });
  }
  setText("#all-findings-count", `显示 ${Math.min(filtered.length, 200)} / ${allFindings.length} 条发现`);
}

function settingRow(label, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  description.textContent = value;
  row.append(term, description);
  return row;
}

function renderSettings(settings) {
  const llm = document.querySelector("#llm-settings");
  llm.replaceChildren(
    settingRow("API Key", settings.llm.api_key_configured ? "已配置" : "未配置"),
    settingRow("Base URL", settings.llm.base_url_configured ? settings.llm.endpoint || "已配置" : "未配置"),
    settingRow("模型", settings.llm.model || "未配置"),
    settingRow(
      "输出额度",
      `普通 ${Math.round(settings.llm.default_max_tokens / 1024)}K · 富化 ${Math.round(
        settings.llm.heavy_max_tokens / 1024
      )}K`
    ),
    settingRow("自动重试上限", `${Math.round(settings.llm.retry_ceiling / 1024)}K`)
  );
  const server = document.querySelector("#server-settings");
  server.replaceChildren(
    settingRow("访问范围", settings.server.local_only ? "仅本机" : "允许远程"),
    settingRow("项目目录", settings.server.project_root),
    settingRow("工作区目录", settings.server.runs_root)
  );
  const registry = document.querySelector("#analyzer-registry");
  registry.replaceChildren();
  settings.analyzers.forEach((analyzer) => {
    const token = document.createElement("div");
    token.className = "analyzer-token";
    const name = document.createElement("strong");
    name.textContent = analyzer.name;
    const phase = document.createElement("small");
    phase.textContent = analyzer.phase === "enrichment" ? "语义富化" : "漏洞分析";
    token.append(name, phase);
    registry.append(token);
  });
}

function openArtifact(title, eyebrow, content) {
  artifactLogWorkspace = null;
  clearTimeout(artifactRefreshTimer);
  document.querySelector("#artifact-progress").hidden = true;
  document.querySelector("#artifact-log-label").hidden = true;
  setText("#artifact-modal-title", title);
  setText("#artifact-modal-eyebrow", eyebrow);
  setText("#artifact-content", content || "暂无可用内容。");
  openLayer(artifactModal);
}

function progressDetail(event) {
  const details = event.details || {};
  const parts = [];
  if (details.batch_index && details.batch_count) {
    parts.push(`批次 ${details.batch_index}/${details.batch_count}`);
  }
  if (details.attempt) parts.push(`尝试 ${details.attempt}`);
  if (details.max_tokens) parts.push(`额度 ${Number(details.max_tokens).toLocaleString()} tokens`);
  if (details.completion_tokens) {
    parts.push(`输出 ${Number(details.completion_tokens).toLocaleString()} tokens`);
  }
  if (details.elapsed_seconds !== undefined) parts.push(`耗时 ${details.elapsed_seconds} 秒`);
  return parts.join(" · ");
}

function renderRunProgress(progress) {
  const panel = document.querySelector("#artifact-progress");
  const list = document.querySelector("#artifact-progress-list");
  const events = Array.isArray(progress?.events) ? progress.events : [];
  panel.hidden = false;
  document.querySelector("#artifact-log-label").hidden = false;
  setText(
    "#artifact-progress-current",
    events.length
      ? progress.legacy_audit && progress.status === "running"
        ? `${events[events.length - 1].message}；当前请求仍在运行，旧进程无法提供请求内心跳。`
        : events[events.length - 1].message
      : "任务已经启动，但当前版本尚未记录节点内部进度。"
  );
  list.replaceChildren();
  events
    .slice(-80)
    .reverse()
    .forEach((event) => {
      const item = document.createElement("li");
      item.className = event.level || "info";
      const timestamp = document.createElement("time");
      const parsed = new Date(event.timestamp);
      timestamp.textContent = Number.isNaN(parsed.getTime())
        ? "—"
        : parsed.toLocaleTimeString("zh-CN", { hour12: false });
      const dot = document.createElement("span");
      dot.className = "progress-event-dot";
      dot.setAttribute("aria-hidden", "true");
      const copy = document.createElement("div");
      copy.className = "progress-event-copy";
      const message = document.createElement("strong");
      message.textContent = event.message || event.event || "运行状态已更新";
      const detail = document.createElement("small");
      detail.textContent = progressDetail(event);
      if (!detail.textContent) detail.hidden = true;
      copy.append(message, detail);
      item.append(timestamp, dot, copy);
      list.append(item);
    });
}

async function refreshRunLog(workspace, { quiet = false } = {}) {
  try {
    const log = await api(`/api/workspaces/${encodeURIComponent(workspace)}/log`);
    let progress = { events: [] };
    try {
      progress = await api(`/api/workspaces/${encodeURIComponent(workspace)}/progress`);
    } catch {
      // Compatibility with a console process that has not yet been restarted.
    }
    if (artifactModal.hidden || artifactLogWorkspace !== workspace) return;
    if (document.querySelector("#artifact-content").textContent !== (log || "暂无运行日志。")) {
      setText("#artifact-content", log || "暂无运行日志。");
    }
    renderRunProgress(progress);
    const workspaceState = dashboardData?.workspaces?.find((item) => item.workspace === workspace);
    if (progress.status === "running" || workspaceState?.status === "running") {
      clearTimeout(artifactRefreshTimer);
      artifactRefreshTimer = setTimeout(() => refreshRunLog(workspace, { quiet: true }), 3000);
    }
  } catch (error) {
    if (!quiet) showToast("无法读取日志", error.message, true);
  }
}

async function openRunLog(workspace) {
  artifactLogWorkspace = workspace;
  clearTimeout(artifactRefreshTimer);
  setText("#artifact-modal-title", `${workspace} 运行日志`);
  setText("#artifact-modal-eyebrow", "实时运行进度");
  setText("#artifact-content", "正在读取原始进程日志…");
  document.querySelector("#artifact-progress").hidden = false;
  document.querySelector("#artifact-log-label").hidden = false;
  setText("#artifact-progress-current", "正在读取节点和模型调用进度…");
  document.querySelector("#artifact-progress-list").replaceChildren();
  openLayer(artifactModal);
  await refreshRunLog(workspace);
}

function analyzerDisplayName(name) {
  return {
    auth: "身份认证",
    authz: "访问控制",
    injection: "注入攻击",
    xss: "跨站脚本",
    ssrf: "SSRF",
    "business-logic": "业务逻辑",
    "business-flow": "业务流富化",
    invariant: "不变量富化",
    baseline: "基线分析",
    shannon: "Shannon 分析",
  }[name] || name;
}

function renderInterventionAnalyzers(runtime) {
  const container = document.querySelector("#intervention-analyzers");
  const selectedVuln = new Set(runtime.config.analyzers || []);
  const selectedEnrichment = new Set(runtime.config.enrichment_analyzers || []);
  container.replaceChildren();
  (dashboardData?.analyzers || []).forEach((analyzer) => {
    const enrichment = analyzer.phase === "enrichment";
    const label = document.createElement("label");
    label.className = "check-card";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = enrichment ? "enrichment_analyzers" : "analyzers";
    input.value = analyzer.name;
    input.checked = (enrichment ? selectedEnrichment : selectedVuln).has(analyzer.name);
    const copy = document.createElement("span");
    const title = document.createElement("strong");
    title.textContent = analyzerDisplayName(analyzer.name);
    const detail = document.createElement("small");
    detail.textContent = enrichment ? `语义富化 · ${analyzer.name}` : `漏洞分析 · ${analyzer.name}`;
    copy.append(title, detail);
    label.append(input, copy);
    container.append(label);
  });
}

async function openIntervention(workspace, action) {
  const submit = document.querySelector("#intervention-submit");
  submit.disabled = false;
  interventionForm.reset();
  interventionForm.elements.workspace.value = workspace;
  interventionForm.elements.action.value = action;
  setText("#intervention-workspace", workspace);
  setText("#intervention-stage", "正在读取 checkpoint…");
  setText("#intervention-progress", "—");
  setText("#intervention-log", "正在读取日志…");
  document.querySelector("#intervention-analyzers").replaceChildren();
  setText(
    "#intervention-modal-title",
    action === "resume" ? "修正配置并恢复扫描" : "检查配置并继续运行"
  );
  setText(
    "#intervention-alert-title",
    action === "resume" ? "节点上次运行失败，请先修正配置" : "检查点已暂停，可以调整后继续"
  );
  setText(
    "#intervention-alert-detail",
    action === "resume"
      ? "恢复会复用最近的 checkpoint；如果不调整失败原因，节点可能再次报错。"
      : "修改会写回 checkpoint，并对尚未执行的节点生效。"
  );
  submit.innerHTML =
    action === "resume"
      ? '<svg><use href="#i-arrow"></use></svg>应用调整并恢复'
      : '<svg><use href="#i-arrow"></use></svg>保存配置并继续';
  openLayer(interventionModal);

  try {
    const runtime = await api(`/api/workspaces/${encodeURIComponent(workspace)}/runtime`);
    if (interventionModal.hidden || interventionForm.elements.workspace.value !== workspace) return;
    const config = runtime.config;
    interventionForm.elements.focus.value = config.focus || "";
    interventionForm.elements.output_token_limit.value = config.output_token_limit || "auto";
    interventionForm.elements.business_flow_batch_size.value = config.business_flow_batch_size || 8;
    interventionForm.elements.strict_outputs.checked = Boolean(config.strict_outputs);
    setText(
      "#intervention-stage",
      runtime.stage || (runtime.next_nodes || []).join(" → ") || "最近失败节点"
    );
    setText(
      "#intervention-progress",
      runtime.completed_nodes?.length ? `${runtime.completed_nodes.length} 个节点` : "尚无完成节点"
    );
    setText("#intervention-log", runtime.log_tail || "当前没有 Web Console 运行日志。");
    const meaningfulLog = (runtime.log_tail || "")
      .split("\n")
      .reverse()
      .find((line) => line.trim() && !line.includes("[argus-web] process exited"));
    if (action === "resume" && meaningfulLog) {
      setText("#intervention-alert-detail", meaningfulLog.trim().slice(0, 260));
    }
    renderInterventionAnalyzers(runtime);
  } catch (error) {
    closeLayer(interventionModal);
    showToast("无法读取恢复配置", error.message, true);
  }
}

function renderDashboard(data) {
  dashboardData = data;
  const workspace = data.selected_workspace;
  const findings = Array.isArray(data.findings) ? data.findings : [];
  populateWorkspaceSelect(data.workspaces || [], workspace?.workspace);
  renderWorkspace(workspace, data.workspaces || []);
  renderFindings(findings);
  renderRisk(findings, workspace?.severity_counts || {});
  renderScans(data.workspaces || []);
  renderReviewQueue(data.workspaces || []);
  renderReports(data.workspaces || []);
  document.querySelector("#engine-status .status-dot").classList.add("success");
  setText("#engine-state", "在线");

  const available = new Set((data.analyzers || []).map((analyzer) => analyzer.name));
  scanForm.querySelectorAll('input[name="analyzers"], input[name="enrichment_analyzers"]').forEach((input) => {
    const enabled = available.has(input.value);
    input.disabled = !enabled;
    if (!enabled) input.checked = false;
    input.closest(".check-card").title = enabled ? "" : "当前安装中未发现此分析器";
  });
  if (!scanForm.elements.repo.value && data.project_root) {
    scanForm.elements.repo.value = `${data.project_root}/evaluation/targets/flowmart`;
  }
}

async function selectWorkspace(workspaceName, navigate = false) {
  const workspace = dashboardData?.workspaces?.find((item) => item.workspace === workspaceName);
  if (!workspace) return;
  try {
    const payload = await api(`/api/workspaces/${encodeURIComponent(workspaceName)}/findings`);
    selectedWorkspace = workspace;
    dashboardData.selected_workspace = workspace;
    dashboardData.findings = payload.findings;
    populateWorkspaceSelect(dashboardData.workspaces, workspaceName);
    renderWorkspace(workspace, dashboardData.workspaces);
    renderFindings(payload.findings);
    renderRisk(payload.findings, workspace.severity_counts || {});
    findingsWorkspaceScope = workspaceName;
    if (navigate) {
      showView("overview");
    } else if (currentView === "findings") {
      await loadAllFindings(workspaceName);
    }
  } catch (error) {
    showToast("无法切换工作区", error.message, true);
  }
}

async function loadAllFindings(preferredWorkspace = findingsWorkspaceScope) {
  const requestId = ++findingsLoadRequest;
  try {
    const payload = await api("/api/findings");
    if (requestId !== findingsLoadRequest) return;
    allFindings = payload.findings || [];
    const workspaceFilter = document.querySelector("#all-workspace-filter");
    const current = preferredWorkspace || "all";
    workspaceFilter.replaceChildren();
    const allOption = document.createElement("option");
    allOption.value = "all";
    allOption.textContent = "全部工作区";
    workspaceFilter.append(allOption);
    [
      ...new Set([
        ...(dashboardData?.workspaces || []).map((workspace) => workspace.workspace),
        ...allFindings.map((finding) => finding._workspace).filter(Boolean),
      ]),
    ]
      .sort()
      .forEach((workspace) => {
        const option = document.createElement("option");
        option.value = workspace;
        option.textContent = workspace;
        workspaceFilter.append(option);
      });
    workspaceFilter.value = [...workspaceFilter.options].some((option) => option.value === current)
      ? current
      : "all";
    findingsWorkspaceScope = workspaceFilter.value;
    renderAllFindings();
  } catch (error) {
    if (requestId !== findingsLoadRequest) return;
    showToast("无法读取漏洞中心", error.message, true);
  }
}

async function loadSettings() {
  if (settingsData) {
    renderSettings(settingsData);
    return;
  }
  try {
    settingsData = await api("/api/settings");
    renderSettings(settingsData);
  } catch (error) {
    showToast("无法读取设置", error.message, true);
  }
}

function showView(view, updateHash = true) {
  const target = document.querySelector(`.app-view[data-view="${view}"]`);
  if (!target) return;
  currentView = view;
  document.querySelectorAll(".app-view").forEach((section) => {
    const active = section === target;
    section.hidden = !active;
    section.classList.toggle("active", active);
  });
  document.querySelectorAll(".nav-item[data-view-target]").forEach((item) => {
    const active = item.dataset.viewTarget === view;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  if (updateHash) history.replaceState(null, "", `#${view}`);
  if (window.innerWidth <= 840) setSidebar(false);
  if (view === "findings") loadAllFindings();
  if (view === "settings") loadSettings();
  const heading = target.querySelector("h1");
  if (heading) {
    heading.tabIndex = -1;
    heading.focus({ preventScroll: true });
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function refreshDashboard({ quiet = false } = {}) {
  clearTimeout(refreshTimer);
  try {
    const data = await api("/api/dashboard");
    const preferredWorkspace = selectedWorkspace?.workspace;
    if (preferredWorkspace && preferredWorkspace !== data.selected_workspace?.workspace) {
      const preserved = data.workspaces.find((workspace) => workspace.workspace === preferredWorkspace);
      if (preserved) {
        const payload = await api(`/api/workspaces/${encodeURIComponent(preferredWorkspace)}/findings`);
        data.selected_workspace = preserved;
        data.findings = payload.findings;
      }
    }
    renderDashboard(data);
    if (currentView === "findings") loadAllFindings();
    const running = (data.workspaces || []).some((workspace) => workspace.status === "running");
    refreshTimer = setTimeout(() => refreshDashboard({ quiet: true }), running ? 3000 : 15000);
  } catch (error) {
    document.querySelector("#engine-status .status-dot").classList.remove("success");
    setText("#engine-state", "离线");
    if (!quiet) {
      showToast("无法连接本地 API", `${error.message}。请使用 “uv run argus web” 启动控制台。`, true);
    }
    refreshTimer = setTimeout(() => refreshDashboard({ quiet: true }), 10000);
  }
}

async function advanceWorkspace(workspace, action, payload, button) {
  const previous = button?.innerHTML;
  if (button) {
    button.disabled = true;
    button.textContent = action === "resume" ? "正在恢复…" : "正在继续…";
  }
  try {
    await api(`/api/workspaces/${encodeURIComponent(workspace)}/${action}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showToast(action === "resume" ? "扫描已恢复" : "检查点已批准", "后台任务已启动，状态会自动刷新。");
    await refreshDashboard({ quiet: true });
    return true;
  } catch (error) {
    showToast("无法推进扫描", error.message, true);
    if (button) {
      button.disabled = false;
      button.innerHTML = previous;
    }
    return false;
  }
}

async function handleWorkspaceAction(button) {
  const { action, workspace } = button.dataset;
  if (!action) return;
  if (action === "select") {
    await selectWorkspace(workspace, true);
    return;
  }
  if (action === "continue" || action === "resume") {
    await openIntervention(workspace, action);
    return;
  }
  if (action === "log") {
    await openRunLog(workspace);
    return;
  }
  if (action === "report" || action === "preview-report") {
    try {
      const report = await api(`/api/workspaces/${encodeURIComponent(workspace)}/report`);
      openArtifact(`${workspace} 安全报告`, "Markdown Report", report);
    } catch (error) {
      showToast("无法读取报告", error.message, true);
    }
    return;
  }
  if (action === "download-report") {
    window.location.assign(`/api/workspaces/${encodeURIComponent(workspace)}/report?download=1`);
    return;
  }
  if (action === "finding") {
    const finding = allFindings.find(
      (item) => item.id === button.dataset.findingId && item._workspace === workspace
    );
    showFinding(finding);
  }
}

async function reviewCurrentFinding(nextStatus) {
  if (!currentDrawerFinding) return;
  const workspace = currentDrawerFinding._workspace || selectedWorkspace?.workspace;
  if (!workspace) {
    showToast("无法保存审阅", "当前发现没有关联工作区。", true);
    return;
  }
  const button =
    nextStatus === "false_positive"
      ? document.querySelector("#mark-false-positive")
      : document.querySelector("#confirm-finding");
  button.disabled = true;
  try {
    const status = currentDrawerFinding.review_status === nextStatus ? "unreviewed" : nextStatus;
    await api(`/api/workspaces/${encodeURIComponent(workspace)}/findings/review`, {
      method: "POST",
      body: JSON.stringify({ finding_id: currentDrawerFinding.id, status }),
    });
    closeLayer(findingDrawer);
    showToast(
      status === "confirmed" ? "发现已确认" : status === "false_positive" ? "已标记误报" : "已清除审阅标记",
      "审阅状态已保存到工作区 findings.json。"
    );
    await refreshDashboard({ quiet: true });
    if (currentView === "findings") await loadAllFindings();
  } catch (error) {
    showToast("无法保存审阅", error.message, true);
  } finally {
    button.disabled = false;
  }
}

function filterOverviewFindings() {
  const query = searchInput.value.trim().toLowerCase();
  const severity = document.querySelector("#overview-severity-filter").value;
  document.querySelectorAll("#findings-body [data-finding-index]").forEach((row) => {
    row.hidden =
      !row.textContent.toLowerCase().includes(query) ||
      (severity !== "all" && row.dataset.severity !== severity);
  });
}

document.querySelectorAll("[data-open-scan]").forEach((button) => {
  button.addEventListener("click", () => {
    const workspaceInput = scanForm.elements.workspace;
    if (!workspaceInput.value) {
      const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 12);
      workspaceInput.value = `scan-${stamp}`;
    }
    openLayer(scanModal);
  });
});

document.querySelectorAll("[data-close-modal]").forEach((button) => {
  button.addEventListener("click", () => closeLayer(scanModal));
});

document.querySelectorAll("[data-close-intervention]").forEach((button) => {
  button.addEventListener("click", () => closeLayer(interventionModal));
});

document.querySelectorAll("[data-close-drawer]").forEach((button) => {
  button.addEventListener("click", () => closeLayer(findingDrawer));
});

document.querySelectorAll("[data-close-artifact]").forEach((button) => {
  button.addEventListener("click", () => {
    clearTimeout(artifactRefreshTimer);
    artifactLogWorkspace = null;
    closeLayer(artifactModal);
  });
});

scanModal.addEventListener("click", (event) => {
  if (event.target === scanModal) closeLayer(scanModal);
});

interventionModal.addEventListener("click", (event) => {
  if (event.target === interventionModal) closeLayer(interventionModal);
});

findingDrawer.addEventListener("click", (event) => {
  if (event.target === findingDrawer) closeLayer(findingDrawer);
});

artifactModal.addEventListener("click", (event) => {
  if (event.target === artifactModal) {
    clearTimeout(artifactRefreshTimer);
    artifactLogWorkspace = null;
    closeLayer(artifactModal);
  }
});

scanModal.addEventListener("keydown", (event) => trapFocus(event, scanModal));
interventionModal.addEventListener("keydown", (event) => trapFocus(event, interventionModal));
findingDrawer.addEventListener("keydown", (event) => trapFocus(event, findingDrawer));
artifactModal.addEventListener("keydown", (event) => trapFocus(event, artifactModal));

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (!artifactModal.hidden) {
    clearTimeout(artifactRefreshTimer);
    artifactLogWorkspace = null;
    closeLayer(artifactModal);
  }
  else if (!findingDrawer.hidden) closeLayer(findingDrawer);
  else if (!interventionModal.hidden) closeLayer(interventionModal);
  else if (!scanModal.hidden) closeLayer(scanModal);
  else if (sidebar.classList.contains("open")) setSidebar(false);
});

findingsBody.addEventListener("click", (event) => {
  const row = event.target.closest("[data-finding-index]");
  if (row) showFinding(currentFindings[Number(row.dataset.findingIndex)]);
});

findingsBody.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("[data-finding-index]");
  if (!row) return;
  event.preventDefault();
  showFinding(currentFindings[Number(row.dataset.findingIndex)]);
});

document.querySelector("[data-open-finding]").addEventListener("click", () => {
  if (currentFindings.length) showFinding(currentFindings[0]);
  else showView("reviews");
});

document.querySelector("#review-artifacts-action").addEventListener("click", () => {
  showView("scans");
});

approveButton.addEventListener("click", async () => {
  if (!selectedWorkspace) return;
  const action = selectedWorkspace.status === "resumable" ? "resume" : "continue";
  await openIntervention(selectedWorkspace.workspace, action);
});

document.querySelector("#review-now").addEventListener("click", () => {
  showView("reviews");
});

document.querySelector("#view-task-button").addEventListener("click", () => showView("scans"));
document.querySelector("#refresh-scans").addEventListener("click", () => refreshDashboard());

document.querySelector("#workspace-select").addEventListener("change", (event) => {
  selectWorkspace(event.currentTarget.value);
});

exportButton.addEventListener("click", () => {
  if (!selectedWorkspace?.artifacts.report) return;
  window.location.assign(`/api/workspaces/${encodeURIComponent(selectedWorkspace.workspace)}/report?download=1`);
});

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = scanForm.querySelector('[type="submit"]');
  const data = new FormData(scanForm);
  const payload = {
    repo: data.get("repo"),
    workspace: data.get("workspace"),
    source_mode: data.get("source_mode"),
    analyzers: data.getAll("analyzers"),
    enrichment_analyzers: data.getAll("enrichment_analyzers"),
    output_token_limit: data.get("output_token_limit"),
    business_flow_batch_size: Number(data.get("business_flow_batch_size")),
    checkpoints: data.has("checkpoints"),
    disclosure_acknowledged: data.has("disclosure_acknowledged"),
  };
  submit.disabled = true;
  submit.textContent = "正在创建工作区…";
  try {
    await api("/api/scans", { method: "POST", body: JSON.stringify(payload) });
    closeLayer(scanModal);
    scanForm.elements.disclosure_acknowledged.checked = false;
    showToast("扫描任务已创建", `${payload.workspace} 已进入代码图构建阶段。`);
    await refreshDashboard({ quiet: true });
  } catch (error) {
    showToast("无法创建扫描", error.message, true);
  } finally {
    submit.disabled = false;
    submit.innerHTML = '<svg><use href="#i-scan"></use></svg>开始扫描';
  }
});

interventionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(interventionForm);
  const workspace = String(data.get("workspace"));
  const action = String(data.get("action"));
  const submit = document.querySelector("#intervention-submit");
  const payload = {
    focus: data.get("focus"),
    analyzers: data.getAll("analyzers"),
    enrichment_analyzers: data.getAll("enrichment_analyzers"),
    output_token_limit: data.get("output_token_limit"),
    business_flow_batch_size: Number(data.get("business_flow_batch_size")),
    strict_outputs: data.has("strict_outputs"),
  };
  const advanced = await advanceWorkspace(workspace, action, payload, submit);
  if (advanced) {
    closeLayer(interventionModal);
  }
});

searchInput.addEventListener("input", () => {
  filterOverviewFindings();
});

document.querySelector("#overview-severity-filter").addEventListener("change", filterOverviewFindings);

document.querySelectorAll("[data-view-target]").forEach((item) => {
  item.addEventListener("click", (event) => {
    event.preventDefault();
    showView(item.dataset.viewTarget);
  });
});

["#scans-body", "#review-queue", "#reports-list", "#all-findings-body"].forEach((selector) => {
  document.querySelector(selector).addEventListener("click", (event) => {
    const button = event.target.closest("[data-action]");
    if (button) handleWorkspaceAction(button);
  });
});

document.querySelector("#all-findings-body").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("[data-finding-id]");
  if (!row) return;
  event.preventDefault();
  const finding = allFindings.find(
    (item) => item.id === row.dataset.findingId && item._workspace === row.dataset.workspace
  );
  showFinding(finding);
});

["#all-findings-search", "#all-severity-filter"].forEach((selector) => {
  document
    .querySelector(selector)
    .addEventListener(selector.includes("search") ? "input" : "change", renderAllFindings);
});

document.querySelector("#all-workspace-filter").addEventListener("change", (event) => {
  findingsWorkspaceScope = event.currentTarget.value;
  renderAllFindings();
});

document.querySelector("#copy-location").addEventListener("click", async () => {
  const location = document.querySelector("#drawer-location").textContent;
  try {
    await navigator.clipboard.writeText(location);
    showToast("代码位置已复制", location);
  } catch {
    showToast("无法复制", "浏览器未授予剪贴板权限。", true);
  }
});

document.querySelector("#mark-false-positive").addEventListener("click", () => {
  reviewCurrentFinding("false_positive");
});

document.querySelector("#confirm-finding").addEventListener("click", () => {
  reviewCurrentFinding("confirmed");
});

const initialView = ["overview", "scans", "reviews", "findings", "reports", "settings"].includes(
  location.hash.slice(1)
)
  ? location.hash.slice(1)
  : "overview";
showView(initialView, false);
refreshDashboard();

/**
 * Docker 集群管理页面
 * 管理 OpenClaw Docker 容器集群：节点管理、容器 CRUD、日志查看
 */
import { api } from '../lib/tauri-api.js'
import { toast } from '../components/toast.js'
import { showConfirm } from '../components/modal.js'

function esc(str) {
  if (!str) return ''
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function fmtBytes(bytes) {
  if (!bytes) return '-'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB'
  return (bytes / 1073741824).toFixed(1) + ' GB'
}

// OpenClaw 容器识别
const OPENCLAW_PATTERNS = ['openclaw', 'qingchencloud']
function isOpenClawContainer(c) {
  const img = (c.image || '').toLowerCase()
  return OPENCLAW_PATTERNS.some(p => img.includes(p))
}

// 用户手动纳入管理的容器 ID 持久化
const ADOPTED_KEY = 'clawpanel_adopted_containers'
function getAdoptedIds() {
  try { return new Set(JSON.parse(localStorage.getItem(ADOPTED_KEY) || '[]')) }
  catch { return new Set() }
}
function saveAdoptedIds(ids) {
  localStorage.setItem(ADOPTED_KEY, JSON.stringify([...ids]))
}
function isManagedContainer(c) {
  return isOpenClawContainer(c) || getAdoptedIds().has(c.id)
}

let _refreshTimer = null

export async function render() {
  const page = document.createElement('div')
  page.className = 'page'

  page.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Docker 集群管理</h1>
      <p class="page-desc">管理 OpenClaw Docker 容器集群，快速部署和扩展</p>
    </div>
    <div id="docker-stats" class="stat-cards"><div class="stat-card loading-placeholder" style="height:80px"></div></div>
    <div id="docker-nodes" style="margin-top:var(--space-lg)"><div class="stat-card loading-placeholder" style="height:120px"></div></div>
    <div id="docker-containers" style="margin-top:var(--space-lg)"><div class="stat-card loading-placeholder" style="height:200px"></div></div>
  `

  bindEvents(page)
  await loadClusterOverview(page)

  _refreshTimer = setInterval(() => loadClusterOverview(page), 30000)
  return page
}

export function cleanup() {
  if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null }
}

async function loadClusterOverview(page) {
  try {
    const nodes = await api.dockerClusterOverview()
    renderStats(page, nodes)
    renderNodes(page, nodes)
    renderContainers(page, nodes)
  } catch (e) {
    const statsEl = page.querySelector('#docker-stats')
    statsEl.innerHTML = `
      <div class="docker-empty">
        <div class="docker-empty-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48"><rect x="1" y="11" width="4" height="3" rx=".5"/><rect x="6" y="11" width="4" height="3" rx=".5"/><rect x="11" y="11" width="4" height="3" rx=".5"/><rect x="6" y="7" width="4" height="3" rx=".5"/><rect x="11" y="7" width="4" height="3" rx=".5"/><rect x="16" y="11" width="4" height="3" rx=".5"/><rect x="11" y="3" width="4" height="3" rx=".5"/><path d="M2 17c1 3 4 5 10 5s9-2 10-5"/></svg>
        </div>
        <div class="docker-empty-title">Docker 未连接</div>
        <div class="docker-empty-desc">${esc(e.message)}</div>
        <div class="docker-empty-hint">
          <p>确保 Docker 已安装并运行：</p>
          <code>docker info</code>
          <p style="margin-top:8px">如果在 Docker 容器内运行，请挂载 Docker Socket：</p>
          <code>-v /var/run/docker.sock:/var/run/docker.sock</code>
        </div>
      </div>
    `
    page.querySelector('#docker-nodes').innerHTML = ''
    page.querySelector('#docker-containers').innerHTML = ''
  }
}

function renderStats(page, nodes) {
  const el = page.querySelector('#docker-stats')
  const totalNodes = nodes.length
  const onlineNodes = nodes.filter(n => n.online).length
  // 统计托管容器（OpenClaw + 手动纳入）
  let managedTotal = 0, managedRunning = 0, managedStopped = 0
  for (const n of nodes) {
    if (!n.online || !n.containers) continue
    for (const c of n.containers) {
      if (isManagedContainer(c)) {
        managedTotal++
        if (c.state === 'running') managedRunning++
        else managedStopped++
      }
    }
  }
  el.innerHTML = `
    <div class="stat-card">
      <div class="stat-card-value">${onlineNodes}<span class="stat-card-unit">/ ${totalNodes}</span></div>
      <div class="stat-card-label">节点在线</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-value">${managedTotal}</div>
      <div class="stat-card-label">托管容器</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-value" style="color:var(--success, #22c55e)">${managedRunning}</div>
      <div class="stat-card-label">运行中</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-value" style="color:var(--text-tertiary)">${managedStopped}</div>
      <div class="stat-card-label">已停止</div>
    </div>
  `
}

function renderNodes(page, nodes) {
  const el = page.querySelector('#docker-nodes')
  let html = `
    <div class="docker-section-header">
      <div class="docker-section-title">节点管理</div>
      <div class="docker-section-actions">
        <button class="btn btn-primary btn-sm" data-action="add-node">+ 添加节点</button>
      </div>
    </div>
    <div class="docker-node-grid">
  `
  for (const node of nodes) {
    const statusClass = node.online ? 'online' : 'offline'
    const statusText = node.online ? '在线' : '离线'
    const mem = node.memory ? fmtBytes(node.memory) : '-'
    html += `
      <div class="docker-node-card ${statusClass}">
        <div class="docker-node-header">
          <div class="docker-node-status ${statusClass}"></div>
          <div class="docker-node-name">${esc(node.name)}</div>
          <div class="docker-node-badge">${statusText}</div>
          ${node.id !== 'local' ? `<button class="docker-node-remove" data-action="remove-node" data-node-id="${esc(node.id)}" title="移除节点">&times;</button>` : ''}
        </div>
        <div class="docker-node-info">
          <span>${esc(node.endpoint)}</span>
          ${node.online ? `<span>Docker ${esc(node.dockerVersion)}</span><span>${node.cpus || '-'} CPU · ${mem} RAM</span>` : `<span class="docker-node-error">${esc(node.error || '连接失败')}</span>`}
        </div>
        ${node.online ? `
          <div class="docker-node-footer">
            <span>${node.runningContainers || 0} 运行 / ${node.totalContainers || 0} 总计</span>
            <button class="btn btn-sm" data-action="deploy" data-node-id="${esc(node.id)}">部署容器</button>
          </div>
        ` : ''}
      </div>
    `
  }
  html += '</div>'
  el.innerHTML = html
}

function _renderContainerRow(c, showAdopt) {
  const isRunning = c.state === 'running'
  const stateClass = isRunning ? 'running' : 'stopped'
  const isAdopted = !isOpenClawContainer(c) && getAdoptedIds().has(c.id)
  return `<tr>
    <td><span class="docker-ct-name">${esc(c.name)}</span><span class="docker-ct-id">${esc(c.id)}</span></td>
    <td class="docker-ct-image">${esc(c.image)}</td>
    <td><span class="docker-ct-state ${stateClass}">${esc(c.status || c.state)}</span></td>
    <td class="docker-ct-ports">${esc(c.ports) || '-'}</td>
    <td class="docker-ct-actions">
      ${showAdopt ? `
        <button class="btn btn-sm" data-action="adopt" data-ct="${esc(c.id)}" data-node="${esc(c.nodeId)}" data-name="${esc(c.name)}">纳入管理</button>
      ` : `
        ${isRunning
          ? `<button class="btn-icon" data-action="stop" data-ct="${esc(c.id)}" data-node="${esc(c.nodeId)}" title="停止">⏹</button>
             <button class="btn-icon" data-action="restart" data-ct="${esc(c.id)}" data-node="${esc(c.nodeId)}" title="重启">🔄</button>`
          : `<button class="btn-icon" data-action="start" data-ct="${esc(c.id)}" data-node="${esc(c.nodeId)}" title="启动">▶</button>`
        }
        <button class="btn-icon" data-action="logs" data-ct="${esc(c.id)}" data-node="${esc(c.nodeId)}" title="日志">📋</button>
        ${isAdopted ? `<button class="btn-icon" data-action="unadopt" data-ct="${esc(c.id)}" title="取消管理">✕</button>` : ''}
        <button class="btn-icon danger" data-action="remove" data-ct="${esc(c.id)}" data-node="${esc(c.nodeId)}" data-name="${esc(c.name)}" title="删除">🗑</button>
      `}
    </td>
  </tr>`
}

function renderContainers(page, nodes) {
  const el = page.querySelector('#docker-containers')
  const allContainers = []
  for (const node of nodes) {
    if (!node.online || !node.containers) continue
    for (const c of node.containers) {
      allContainers.push({ ...c, nodeId: node.id, nodeName: node.name })
    }
  }

  const managed = allContainers.filter(c => isManagedContainer(c))
  const other = allContainers.filter(c => !isManagedContainer(c))

  let html = `
    <div class="docker-section-header">
      <div class="docker-section-title">OpenClaw 容器</div>
      <div class="docker-section-actions">
        <button class="btn btn-sm" data-action="refresh">刷新</button>
      </div>
    </div>
  `

  if (managed.length === 0) {
    html += `<div class="docker-empty-inline">暂无 OpenClaw 容器，点击节点上的「部署容器」创建，或从下方已有容器中纳入管理</div>`
  } else {
    html += `<div class="docker-table-wrap"><table class="docker-table">
      <thead><tr>
        <th>名称</th><th>镜像</th><th>状态</th><th>端口</th><th>操作</th>
      </tr></thead><tbody>`
    for (const c of managed) html += _renderContainerRow(c, false)
    html += '</tbody></table></div>'
  }

  // 其他容器（可折叠）
  if (other.length > 0) {
    html += `
      <details class="docker-other-section" style="margin-top:var(--space-lg)">
        <summary class="docker-other-toggle">
          <span>其他 Docker 容器</span>
          <span class="docker-other-count">${other.length}</span>
        </summary>
        <div class="docker-table-wrap" style="margin-top:var(--space-sm)"><table class="docker-table">
          <thead><tr>
            <th>名称</th><th>镜像</th><th>状态</th><th>端口</th><th>操作</th>
          </tr></thead><tbody>
          ${other.map(c => _renderContainerRow(c, true)).join('')}
        </tbody></table></div>
      </details>
    `
  }

  el.innerHTML = html
}

function bindEvents(page) {
  page.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]')
    if (!btn) return
    const action = btn.dataset.action

    if (action === 'refresh') {
      toast('刷新中...')
      await loadClusterOverview(page)
      return
    }

    if (action === 'add-node') {
      showAddNodeDialog(page)
      return
    }

    if (action === 'remove-node') {
      const nodeId = btn.dataset.nodeId
      const ok = await showConfirm('确定移除此节点？', '移除后该节点上的容器将不再在此面板中管理。')
      if (!ok) return
      try {
        await api.dockerRemoveNode(nodeId)
        toast('节点已移除')
        await loadClusterOverview(page)
      } catch (e) { toast(e.message, 'error') }
      return
    }

    if (action === 'deploy') {
      showDeployDialog(page, btn.dataset.nodeId)
      return
    }

    if (action === 'adopt') {
      const ids = getAdoptedIds()
      ids.add(btn.dataset.ct)
      saveAdoptedIds(ids)
      toast(`已将 ${btn.dataset.name || btn.dataset.ct} 纳入管理`)
      await loadClusterOverview(page)
      return
    }

    if (action === 'unadopt') {
      const ids = getAdoptedIds()
      ids.delete(btn.dataset.ct)
      saveAdoptedIds(ids)
      toast('已取消管理')
      await loadClusterOverview(page)
      return
    }

    const containerId = btn.dataset.ct
    const nodeId = btn.dataset.node

    if (action === 'start') {
      try {
        btn.disabled = true
        await api.dockerStartContainer(nodeId, containerId)
        toast('容器已启动')
        await loadClusterOverview(page)
      } catch (e) { toast(e.message, 'error') }
      return
    }

    if (action === 'stop') {
      try {
        btn.disabled = true
        await api.dockerStopContainer(nodeId, containerId)
        toast('容器已停止')
        await loadClusterOverview(page)
      } catch (e) { toast(e.message, 'error') }
      return
    }

    if (action === 'restart') {
      try {
        btn.disabled = true
        await api.dockerRestartContainer(nodeId, containerId)
        toast('容器已重启')
        await loadClusterOverview(page)
      } catch (e) { toast(e.message, 'error') }
      return
    }

    if (action === 'remove') {
      const name = btn.dataset.name || containerId
      const ok = await showConfirm(`删除容器 ${name}？`, '容器数据卷将保留，但容器本身将被删除。')
      if (!ok) return
      try {
        await api.dockerRemoveContainer(nodeId, containerId, true)
        toast('容器已删除')
        await loadClusterOverview(page)
      } catch (e) { toast(e.message, 'error') }
      return
    }

    if (action === 'logs') {
      showLogsDialog(page, nodeId, containerId)
      return
    }
  })
}

function showAddNodeDialog(page) {
  const isWin = navigator.platform?.toLowerCase().includes('win')
  const presets = [
    { label: '本机 (TCP)', endpoint: 'tcp://127.0.0.1:2375', desc: '本机 Docker TCP 端口' },
    { label: '本机 (Socket)', endpoint: isWin ? '//./pipe/docker_engine' : 'unix:///var/run/docker.sock', desc: isWin ? 'Windows Named Pipe' : 'Unix Socket' },
  ]

  const overlay = document.createElement('div')
  overlay.className = 'docker-dialog-overlay'
  overlay.innerHTML = `
    <div class="docker-dialog">
      <div class="docker-dialog-title">添加 Docker 节点</div>
      <div class="form-group">
        <label class="form-label">节点名称</label>
        <input class="form-input" id="dn-name" placeholder="如：生产服务器" />
      </div>
      <div class="form-group">
        <label class="form-label">Docker 端点</label>
        <div class="dn-presets">
          ${presets.map((p, i) => `<button class="dn-preset-btn" data-idx="${i}" title="${esc(p.desc)}">${esc(p.label)}</button>`).join('')}
          <button class="dn-preset-btn" data-idx="custom">自定义</button>
        </div>
        <div id="dn-endpoint-row" style="display:flex;gap:8px;align-items:center;margin-top:8px">
          <input class="form-input" id="dn-endpoint" placeholder="tcp://192.168.1.100:2375" style="flex:1" />
          <button class="btn btn-sm" id="dn-test" type="button" style="white-space:nowrap">测试连接</button>
        </div>
        <div id="dn-test-result" style="font-size:12px;margin-top:6px;min-height:18px"></div>
      </div>
      <div class="docker-dialog-hint">
        <strong>远程 Docker：</strong>需在目标机器开启 TCP 端口<br>
        <code>dockerd -H tcp://0.0.0.0:2375</code>
      </div>
      <div class="docker-dialog-actions">
        <button class="btn" data-dismiss>取消</button>
        <button class="btn btn-primary" id="dn-submit">添加</button>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
  overlay.querySelector('[data-dismiss]').onclick = () => overlay.remove()
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove() })

  const epInput = overlay.querySelector('#dn-endpoint')
  const resultEl = overlay.querySelector('#dn-test-result')

  // 预设按钮点击
  for (const btn of overlay.querySelectorAll('.dn-preset-btn')) {
    btn.onclick = () => {
      overlay.querySelectorAll('.dn-preset-btn').forEach(b => b.classList.remove('active'))
      btn.classList.add('active')
      const idx = btn.dataset.idx
      if (idx === 'custom') {
        epInput.value = ''
        epInput.focus()
      } else {
        epInput.value = presets[parseInt(idx)].endpoint
      }
      resultEl.textContent = ''
    }
  }

  // 测试连接
  overlay.querySelector('#dn-test').onclick = async () => {
    const ep = epInput.value.trim()
    if (!ep) { resultEl.innerHTML = '<span style="color:var(--error,#ef4444)">请先输入端点</span>'; return }
    resultEl.innerHTML = '<span style="color:var(--text-tertiary)">连接中...</span>'
    try {
      const info = await api.dockerTestEndpoint(ep)
      resultEl.innerHTML = `<span style="color:var(--success,#22c55e)">✓ 连接成功 — Docker ${esc(info.ServerVersion || '?')}，${info.Containers || 0} 个容器</span>`
    } catch (e) {
      resultEl.innerHTML = `<span style="color:var(--error,#ef4444)">✕ 连接失败：${esc(e.message)}</span>`
    }
  }

  overlay.querySelector('#dn-submit').onclick = async () => {
    const name = overlay.querySelector('#dn-name').value.trim()
    const endpoint = epInput.value.trim()
    if (!name || !endpoint) { toast('请填写完整', 'error'); return }
    const btn = overlay.querySelector('#dn-submit')
    btn.disabled = true
    btn.textContent = '连接中...'
    try {
      await api.dockerAddNode(name, endpoint)
      toast('节点添加成功')
      overlay.remove()
      await loadClusterOverview(page)
    } catch (e) {
      toast(e.message, 'error')
      btn.disabled = false
      btn.textContent = '添加'
    }
  }
}

async function showDeployDialog(page, nodeId) {
  // 自动检测已用端口，分配下一组可用端口
  let usedPorts = new Set()
  try {
    const containers = await api.dockerListContainers(nodeId, true)
    for (const c of containers) {
      if (c.ports) {
        for (const p of c.ports.split(', ')) {
          const m = p.match(/^(\d+)/)
          if (m) usedPorts.add(parseInt(m[1]))
        }
      }
    }
  } catch {}
  let autoPanel = 1421
  while (usedPorts.has(autoPanel)) autoPanel++
  let autoGw = 18790
  while (usedPorts.has(autoGw)) autoGw++

  const defaultName = `openclaw-${Date.now().toString(36).slice(-4)}`
  const defaultImage = 'ghcr.io/qingchencloud/openclaw:latest'

  const overlay = document.createElement('div')
  overlay.className = 'docker-dialog-overlay'
  overlay.innerHTML = `
    <div class="docker-dialog">
      <div class="docker-dialog-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>部署 OpenClaw 容器</span>
        <div class="deploy-mode-toggle">
          <button class="deploy-mode-btn active" data-mode="basic">基础</button>
          <button class="deploy-mode-btn" data-mode="advanced">高级</button>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">容器名称</label>
        <input class="form-input" id="dd-name" placeholder="给你的 OpenClaw 起个名字" value="${defaultName}" />
      </div>

      <div id="deploy-basic-info" class="deploy-auto-summary">
        <div class="deploy-auto-title">自动配置</div>
        <div class="deploy-auto-item"><span>镜像</span><span>一体版 (latest)</span></div>
        <div class="deploy-auto-item"><span>面板端口</span><span>${autoPanel}</span></div>
        <div class="deploy-auto-item"><span>Gateway 端口</span><span>${autoGw}</span></div>
        <div class="deploy-auto-item"><span>数据卷</span><span>自动创建</span></div>
        <div class="deploy-auto-item"><span>重启策略</span><span>unless-stopped</span></div>
      </div>

      <div id="deploy-advanced-fields" style="display:none">
        <div class="form-group">
          <label class="form-label">镜像</label>
          <select class="form-input" id="dd-image">
            <option value="ghcr.io/qingchencloud/openclaw:latest">一体版 (latest)</option>
            <option value="ghcr.io/qingchencloud/openclaw:latest-gateway">纯 Gateway (gateway)</option>
            <option value="ccr.ccs.tencentyun.com/qingchencloud/openclaw:latest">一体版 - 国内源 (腾讯云)</option>
          </select>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-sm)">
          <div class="form-group">
            <label class="form-label">面板端口</label>
            <input class="form-input" id="dd-panel-port" type="number" value="${autoPanel}" />
          </div>
          <div class="form-group">
            <label class="form-label">Gateway 端口</label>
            <input class="form-input" id="dd-gw-port" type="number" value="${autoGw}" />
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">环境变量 <span style="color:var(--text-tertiary)">(可选)</span></label>
          <textarea class="form-input" id="dd-env-key" rows="2" placeholder="OPENAI_API_KEY=sk-xxx" style="resize:vertical;font-family:var(--font-mono);font-size:12px"></textarea>
          <div class="form-hint">格式：KEY=VALUE，每行一个</div>
        </div>
      </div>

      <div class="docker-dialog-actions">
        <button class="btn" data-dismiss>取消</button>
        <button class="btn btn-primary" id="dd-submit">一键部署</button>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
  overlay.querySelector('[data-dismiss]').onclick = () => overlay.remove()
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove() })

  // 基础/高级模式切换
  let isAdvanced = false
  for (const btn of overlay.querySelectorAll('.deploy-mode-btn')) {
    btn.onclick = () => {
      isAdvanced = btn.dataset.mode === 'advanced'
      overlay.querySelectorAll('.deploy-mode-btn').forEach(b => b.classList.remove('active'))
      btn.classList.add('active')
      overlay.querySelector('#deploy-basic-info').style.display = isAdvanced ? 'none' : ''
      overlay.querySelector('#deploy-advanced-fields').style.display = isAdvanced ? '' : 'none'
      overlay.querySelector('#dd-submit').textContent = isAdvanced ? '部署' : '一键部署'
    }
  }

  overlay.querySelector('#dd-submit').onclick = async () => {
    const name = overlay.querySelector('#dd-name').value.trim()
    if (!name) { toast('请输入容器名称', 'error'); return }
    let image, tag, panelPort, gatewayPort, envVars = {}
    if (isAdvanced) {
      const imgFull = overlay.querySelector('#dd-image').value
      const parts = imgFull.split(':')
      tag = parts.pop()
      image = parts.join(':')
      panelPort = parseInt(overlay.querySelector('#dd-panel-port').value) || autoPanel
      gatewayPort = parseInt(overlay.querySelector('#dd-gw-port').value) || autoGw
      const envText = overlay.querySelector('#dd-env-key').value.trim()
      if (envText) {
        for (const line of envText.split('\n')) {
          const idx = line.indexOf('=')
          if (idx > 0) envVars[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
        }
      }
    } else {
      const parts = defaultImage.split(':')
      tag = parts.pop()
      image = parts.join(':')
      panelPort = autoPanel
      gatewayPort = autoGw
    }
    const btn = overlay.querySelector('#dd-submit')
    btn.disabled = true
    btn.textContent = '部署中...'
    try {
      const result = await api.dockerCreateContainer({ nodeId, name, image, tag, panelPort, gatewayPort, envVars })
      toast(`容器 ${result.name} 已部署并启动`)
      overlay.remove()
      await loadClusterOverview(page)
    } catch (e) {
      toast(e.message, 'error')
      btn.disabled = false
      btn.textContent = isAdvanced ? '部署' : '一键部署'
    }
  }
}

async function showLogsDialog(page, nodeId, containerId) {
  const overlay = document.createElement('div')
  overlay.className = 'docker-dialog-overlay'
  overlay.innerHTML = `
    <div class="docker-dialog docker-dialog-wide">
      <div class="docker-dialog-title">容器日志 <span style="color:var(--text-tertiary);font-size:12px">${esc(containerId)}</span></div>
      <pre class="docker-logs-content">加载中...</pre>
      <div class="docker-dialog-actions">
        <button class="btn" id="dl-refresh">刷新</button>
        <button class="btn" data-dismiss>关闭</button>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
  overlay.querySelector('[data-dismiss]').onclick = () => overlay.remove()
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove() })

  async function loadLogs() {
    const pre = overlay.querySelector('.docker-logs-content')
    try {
      const logs = await api.dockerContainerLogs(nodeId, containerId, 200)
      pre.textContent = logs || '（暂无日志）'
      pre.scrollTop = pre.scrollHeight
    } catch (e) {
      pre.textContent = '获取日志失败: ' + e.message
    }
  }
  await loadLogs()
  overlay.querySelector('#dl-refresh').onclick = loadLogs
}

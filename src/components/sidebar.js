/**
 * 侧边导航栏
 */
import { navigate, getCurrentRoute } from '../router.js'
import { toggleTheme, getTheme } from '../lib/theme.js'
import { isOpenclawReady, getActiveInstance, switchInstance, onInstanceChange } from '../lib/app-state.js'
import { api } from '../lib/tauri-api.js'
import { version as APP_VERSION } from '../../package.json'

const NAV_ITEMS_FULL = [
  {
    section: '概览',
    items: [
      { route: '/dashboard', label: '仪表盘', icon: 'dashboard' },
      { route: '/assistant', label: 'AI 助手', icon: 'assistant' },
      { route: '/chat', label: '实时聊天', icon: 'chat' },
      { route: '/services', label: '服务管理', icon: 'services' },
      { route: '/logs', label: '日志查看', icon: 'logs' },
    ]
  },
  {
    section: '配置',
    items: [
      { route: '/models', label: '模型配置', icon: 'models' },
      { route: '/agents', label: 'Agent 管理', icon: 'agents' },
      { route: '/gateway', label: 'Gateway', icon: 'gateway' },
      { route: '/security', label: '安全设置', icon: 'security' },
    ]
  },
  {
    section: '数据',
    items: [
      { route: '/memory', label: '记忆文件', icon: 'memory' },
    ]
  },
  {
    section: '扩展',
    items: [
      { route: '/extensions', label: '扩展工具', icon: 'extensions' },
      { route: '/skills', label: 'Skills', icon: 'skills' },
    ]
  },
  {
    section: 'Docker',
    items: [
      { route: '/docker', label: 'Docker 集群', icon: 'docker' },
    ]
  },
  {
    section: '',
    items: [
      { route: '/chat-debug', label: '系统诊断', icon: 'debug' },
      { route: '/about', label: '关于', icon: 'about' },
    ]
  }
]

const NAV_ITEMS_SETUP = [
  {
    section: '',
    items: [
      { route: '/setup', label: '初始设置', icon: 'setup' },
      { route: '/assistant', label: 'AI 助手', icon: 'assistant' },
    ]
  },
  {
    section: '扩展',
    items: [
      { route: '/extensions', label: '扩展工具', icon: 'extensions' },
      { route: '/skills', label: 'Skills', icon: 'skills' },
    ]
  },
  {
    section: '',
    items: [
      { route: '/chat-debug', label: '系统诊断', icon: 'debug' },
      { route: '/about', label: '关于', icon: 'about' },
    ]
  }
]

const ICONS = {
  setup: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/></svg>',
  dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
  chat: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>',
  services: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>',
  logs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
  models: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/><path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12"/></svg>',
  agents: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>',
  gateway: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
  memory: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 3h6a4 4 0 014 4v14a3 3 0 00-3-3H2z"/><path d="M22 3h-6a4 4 0 00-4 4v14a3 3 0 013-3h7z"/></svg>',
  extensions: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>',
  about: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  assistant: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/><path d="M18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456z"/></svg>',
  security: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
  skills: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>',
  docker: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="11" width="4" height="3" rx=".5"/><rect x="6" y="11" width="4" height="3" rx=".5"/><rect x="11" y="11" width="4" height="3" rx=".5"/><rect x="6" y="7" width="4" height="3" rx=".5"/><rect x="11" y="7" width="4" height="3" rx=".5"/><rect x="16" y="11" width="4" height="3" rx=".5"/><rect x="11" y="3" width="4" height="3" rx=".5"/><path d="M2 17c1 3 4 5 10 5s9-2 10-5"/></svg>',
  debug: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/><circle cx="12" cy="12" r="3"/></svg>',
}

let _delegated = false
let _hasMultipleInstances = false

// 异步检测是否有多实例（首次渲染后触发，有多实例时重渲染）
function _checkMultiInstances(el) {
  api.instanceList().then(data => {
    const has = data.instances && data.instances.length > 1
    if (has !== _hasMultipleInstances) {
      _hasMultipleInstances = has
      renderSidebar(el)
    }
  }).catch(() => {})
}

export function renderSidebar(el) {
  const current = getCurrentRoute()

  const inst = getActiveInstance()
  const isLocal = inst.type === 'local'
  const showSwitcher = !isLocal || _hasMultipleInstances

  let html = `
    <div class="sidebar-header">
      <div class="sidebar-logo">
        <img src="/images/logo.png" alt="ClawPanel">
      </div>
      <span class="sidebar-title">ClawPanel</span>
    </div>
    ${showSwitcher ? `<div class="instance-switcher" id="instance-switcher">
      <button class="instance-current" id="btn-instance-toggle">
        <span class="instance-dot ${isLocal ? 'local' : 'remote'}"></span>
        <span class="instance-label">${_escSidebar(inst.name)}</span>
        <svg class="instance-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M6 9l6 6 6-6"/></svg>
      </button>
      <div class="instance-dropdown" id="instance-dropdown"></div>
    </div>` : ''}
    <nav class="sidebar-nav">
  `

  const navItems = isOpenclawReady() ? NAV_ITEMS_FULL : NAV_ITEMS_SETUP

  for (const section of navItems) {
    html += `<div class="nav-section">
      <div class="nav-section-title">${section.section}</div>`

    for (const item of section.items) {
      const active = current === item.route ? ' active' : ''
      html += `<div class="nav-item${active}" data-route="${item.route}">
        ${ICONS[item.icon] || ''}
        <span>${item.label}</span>
      </div>`
    }
    html += '</div>'
  }

  html += '</nav>'

  // 主题切换按钮
  const isDark = getTheme() === 'dark'
  const sunIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
  const moonIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>'

  html += `
    <div class="sidebar-footer">
      <div class="nav-item" id="btn-theme-toggle">
        ${isDark ? sunIcon : moonIcon}
        <span>${isDark ? '日间模式' : '夜间模式'}</span>
      </div>
      <div class="sidebar-meta">
        <a href="https://claw.qt.cool" target="_blank" rel="noopener" class="sidebar-link">claw.qt.cool</a>
        <span class="sidebar-version">v${APP_VERSION}</span>
      </div>
    </div>
  `

  el.innerHTML = html

  // 首次渲染时异步检测多实例
  if (!_delegated) _checkMultiInstances(el)

  // 事件委托：只绑定一次，避免重复绑定
  if (!_delegated) {
    _delegated = true
    el.addEventListener('click', (e) => {
      // 导航点击
      const navItem = e.target.closest('.nav-item[data-route]')
      if (navItem) {
        navigate(navItem.dataset.route)
        return
      }
      // 主题切换
      const themeBtn = e.target.closest('#btn-theme-toggle')
      if (themeBtn) {
        toggleTheme()
        renderSidebar(el)
        return
      }
      // 实例切换器
      const toggleBtn = e.target.closest('#btn-instance-toggle')
      if (toggleBtn) {
        _toggleInstanceDropdown(el)
        return
      }
      // 选择实例
      const opt = e.target.closest('.instance-option[data-id]')
      if (opt) {
        const id = opt.dataset.id
        _closeInstanceDropdown()
        if (id !== getActiveInstance().id) {
          opt.style.opacity = '0.5'
          switchInstance(id).then(() => {
            renderSidebar(el)
            navigate(getCurrentRoute())
          })
        }
        return
      }
      // 添加实例
      const addBtn = e.target.closest('#btn-instance-add')
      if (addBtn) {
        _closeInstanceDropdown()
        _showAddInstanceDialog(el)
        return
      }
      // 点击其他区域关闭下拉
      if (!e.target.closest('.instance-switcher')) {
        _closeInstanceDropdown()
      }
    })

    // 监听实例变化，刷新多实例标记后重新渲染
    onInstanceChange(() => { _checkMultiInstances(el); renderSidebar(el) })
  }
}

function _escSidebar(s) { return String(s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;') }

function _closeInstanceDropdown() {
  const dd = document.getElementById('instance-dropdown')
  if (dd) dd.classList.remove('open')
}

async function _toggleInstanceDropdown(sidebarEl) {
  const dd = document.getElementById('instance-dropdown')
  if (!dd) return
  if (dd.classList.contains('open')) { dd.classList.remove('open'); return }

  dd.innerHTML = '<div style="padding:8px;color:var(--text-tertiary);font-size:12px">loading...</div>'
  dd.classList.add('open')

  try {
    const [data, health] = await Promise.all([api.instanceList(), api.instanceHealthAll()])
    const healthMap = Object.fromEntries((health || []).map(h => [h.id, h]))
    const activeId = getActiveInstance().id
    let html = ''
    for (const inst of data.instances) {
      const h = healthMap[inst.id] || {}
      const active = inst.id === activeId ? ' active' : ''
      const dot = h.online !== false ? 'online' : 'offline'
      const badge = inst.type === 'docker' ? '<span class="instance-badge">Docker</span>' : inst.type === 'remote' ? '<span class="instance-badge">Remote</span>' : ''
      html += `<div class="instance-option${active}" data-id="${inst.id}">
        <span class="instance-dot ${dot}"></span>
        <span class="instance-opt-name">${_escSidebar(inst.name)}</span>
        ${badge}
      </div>`
    }
    html += '<div class="instance-divider"></div>'
    html += '<div class="instance-option instance-add" id="btn-instance-add">+ Add Instance</div>'
    dd.innerHTML = html
  } catch (e) {
    dd.innerHTML = `<div style="padding:8px;color:var(--error);font-size:12px">${_escSidebar(e.message)}</div>`
  }
}

async function _showAddInstanceDialog(sidebarEl) {
  const overlay = document.createElement('div')
  overlay.className = 'docker-dialog-overlay'
  overlay.innerHTML = `
    <div class="docker-dialog">
      <div class="docker-dialog-title">Add Instance</div>
      <div class="form-group" style="margin-bottom:var(--space-md)">
        <label class="form-label">Name</label>
        <input class="form-input" id="inst-name" placeholder="My Server" />
      </div>
      <div class="form-group" style="margin-bottom:var(--space-md)">
        <label class="form-label">Panel Endpoint</label>
        <input class="form-input" id="inst-endpoint" placeholder="http://192.168.1.100:1420" />
      </div>
      <div class="form-group" style="margin-bottom:var(--space-md)">
        <label class="form-label">Gateway Port (optional)</label>
        <input class="form-input" id="inst-gw-port" type="number" value="18789" />
      </div>
      <div class="docker-dialog-hint">
        The remote server must be running ClawPanel (serve.js).<br/>
        Example: <code>http://192.168.1.100:1420</code>
      </div>
      <div id="inst-add-error" style="color:var(--error);font-size:12px;margin-top:var(--space-sm)"></div>
      <div class="docker-dialog-actions">
        <button class="btn btn-secondary btn-sm" id="inst-cancel">Cancel</button>
        <button class="btn btn-primary btn-sm" id="inst-confirm">Add</button>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
  overlay.querySelector('#inst-cancel').onclick = () => overlay.remove()
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove() })
  overlay.querySelector('#inst-confirm').onclick = async () => {
    const name = overlay.querySelector('#inst-name').value.trim()
    const endpoint = overlay.querySelector('#inst-endpoint').value.trim()
    const gwPort = parseInt(overlay.querySelector('#inst-gw-port').value) || 18789
    const errEl = overlay.querySelector('#inst-add-error')
    if (!name || !endpoint) { errEl.textContent = 'Name and endpoint are required'; return }
    const btn = overlay.querySelector('#inst-confirm')
    btn.disabled = true; btn.textContent = 'Adding...'
    try {
      await api.instanceAdd({ name, type: 'remote', endpoint, gatewayPort: gwPort })
      overlay.remove()
      renderSidebar(sidebarEl)
    } catch (e) {
      errEl.textContent = e.message || String(e)
      btn.disabled = false; btn.textContent = 'Add'
    }
  }
}

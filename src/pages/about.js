/**
 * 关于页面
 * 版本信息、项目链接、相关项目、系统环境
 */
import { api } from '../lib/tauri-api.js'
import { toast } from '../components/toast.js'
import { showUpgradeModal, showConfirm } from '../components/modal.js'
import { setUpgrading } from '../lib/app-state.js'
import { icon, statusIcon } from '../lib/icons.js'

export async function render() {
  const page = document.createElement('div')
  page.className = 'page'

  page.innerHTML = `
    <div class="page-header" style="display:flex;align-items:center;gap:16px">
      <img src="/images/logo-brand.png" alt="ClawPanel" style="height:48px;width:auto">
      <div>
        <h1 class="page-title" style="margin:0">ClawPanel</h1>
        <p class="page-desc" style="margin:0">OpenClaw 可视化管理面板 · <a href="https://claw.qt.cool" target="_blank" rel="noopener" style="color:var(--primary)">claw.qt.cool</a></p>
      </div>
    </div>
    <div class="stat-cards" id="version-cards">
      <div class="stat-card loading-placeholder"></div>
      <div class="stat-card loading-placeholder"></div>
      <div class="stat-card loading-placeholder"></div>
    </div>
    <div class="config-section">
      <div class="config-section-title">社群交流</div>
      <div id="community-section"></div>
    </div>
    <div class="config-section">
      <div class="config-section-title">相关项目</div>
      <div id="projects-list"></div>
    </div>
    <div class="config-section">
      <div class="config-section-title">参与贡献</div>
      <div id="contribute-section"></div>
    </div>
    <div class="config-section">
      <div class="config-section-title">快捷链接</div>
      <div id="links-list"></div>
    </div>
    <div class="config-section" style="color:var(--text-tertiary);font-size:var(--font-size-xs)">
      <p>ClawPanel 基于 Tauri v2 构建，前端 Vanilla JS + Vite，后端 Rust。</p>
      <p style="margin-top:8px">MIT License &copy; 2026 qingchencloud</p>
    </div>
  `

  loadData(page)
  renderCommunity(page)
  renderProjects(page)
  renderContribute(page)
  renderLinks(page)
  return page
}

async function loadData(page) {
  const cards = page.querySelector('#version-cards')
  try {
    const [version, install] = await Promise.all([
      api.getVersionInfo(),
      api.checkInstallation(),
    ])

    // 尝试从 Tauri API 获取 ClawPanel 自身版本号，失败则 fallback
    let panelVersion = typeof __APP_VERSION__ !== 'undefined' ? __APP_VERSION__ : '0.1.0'
    try {
      const { getVersion } = await import('@tauri-apps/api/app')
      panelVersion = await getVersion()
    } catch {
      // 非 Tauri 环境或 API 不可用，使用构建时注入的版本号
    }

    // 异步检查前端热更新
    let panelUpdateHtml = '<span style="color:var(--text-tertiary)">检查更新中...</span>'
    checkHotUpdate(cards, panelVersion)

    const isInstalled = !!version.current
    const sourceLabel = version.source === 'official' ? '官方版' : '汉化版'
    const btnSm = 'padding:2px 8px;font-size:var(--font-size-xs)'

    cards.innerHTML = `
      <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">ClawPanel</span></div>
        <div class="stat-card-value">${panelVersion}</div>
        <div class="stat-card-meta" id="panel-update-meta" style="display:flex;align-items:center;gap:8px">${panelUpdateHtml}</div>
      </div>
      <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">OpenClaw · ${sourceLabel}</span></div>
        <div class="stat-card-value">${version.current || '未安装'}</div>
        <div class="stat-card-meta" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          ${isInstalled ? (version.update_available
            ? `<span style="color:var(--accent)">新版本: ${version.latest}</span>
               <button class="btn btn-primary btn-sm" id="btn-upgrade-latest" style="${btnSm}">升级到最新</button>`
            : '<span style="color:var(--success)">已是最新</span>') : ''}
          <button class="btn btn-${isInstalled ? 'secondary' : 'primary'} btn-sm" id="btn-version-mgmt" style="${btnSm}">
            ${isInstalled ? '切换版本' : '安装 OpenClaw'}
          </button>
          ${isInstalled ? `<button class="btn btn-secondary btn-sm" id="btn-uninstall" style="${btnSm};color:var(--error)">卸载</button>` : ''}
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">安装路径</span></div>
        <div class="stat-card-value" style="font-size:var(--font-size-sm);word-break:break-all">${install.path || '未知'}</div>
        <div class="stat-card-meta">${install.installed ? '配置文件存在' : '未找到配置文件'}</div>
      </div>
    `

    // 升级到最新
    const upgLatestBtn = cards.querySelector('#btn-upgrade-latest')
    if (upgLatestBtn) {
      upgLatestBtn.onclick = () => doInstall(page, '升级 OpenClaw', version.source, null)
    }

    // 版本管理 / 安装
    const versionMgmtBtn = cards.querySelector('#btn-version-mgmt')
    if (versionMgmtBtn) {
      versionMgmtBtn.onclick = () => showVersionPicker(page, version)
    }

    // 卸载
    const uninstallBtn = cards.querySelector('#btn-uninstall')
    if (uninstallBtn) {
      uninstallBtn.onclick = async () => {
        const confirmed = await showConfirm('确定要卸载 OpenClaw 吗？\n\n这将停止 Gateway 服务并卸载 npm 全局包。\n配置文件（~/.openclaw/）默认保留，可稍后手动删除。')
        if (!confirmed) return
        const modal = showUpgradeModal('卸载 OpenClaw')
        modal.onClose(() => loadData(page))
        modal.appendLog('开始卸载 OpenClaw...')
        let unlistenLog, unlistenProgress
        try {
          if (window.__TAURI_INTERNALS__) {
            try {
              const { listen } = await import('@tauri-apps/api/event')
              unlistenLog = await listen('upgrade-log', (e) => modal.appendLog(e.payload))
              unlistenProgress = await listen('upgrade-progress', (e) => modal.setProgress(e.payload))
            } catch {}
          }
          const msg = await api.uninstallOpenclaw(false)
          modal.setDone(typeof msg === 'string' ? msg : '卸载完成')
        } catch (e) {
          modal.setError('卸载失败: ' + (e?.message || e))
        } finally {
          unlistenLog?.()
          unlistenProgress?.()
        }
      }
    }
  } catch {
    cards.innerHTML = '<div class="stat-card"><div class="stat-card-label">加载失败</div></div>'
  }
}

/**
 * 版本选择器弹窗 — 选择版本（汉化版/原版）+ 版本号
 */
async function showVersionPicker(page, currentVersion) {
  const isInstalled = !!currentVersion.current
  const overlay = document.createElement('div')
  overlay.className = 'modal-overlay'
  overlay.innerHTML = `
    <div class="modal" style="max-width:460px">
      <div class="modal-title">${isInstalled ? '切换版本' : '安装 OpenClaw'}</div>
      <div style="display:flex;flex-direction:column;gap:16px;margin:16px 0">
        <div>
          <label style="font-size:var(--font-size-sm);color:var(--text-secondary);display:block;margin-bottom:8px">版本</label>
          <div style="display:flex;gap:8px">
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:6px 12px;border-radius:8px;border:1px solid var(--border);font-size:var(--font-size-sm);flex:1;justify-content:center;transition:all .15s" id="lbl-chinese">
              <input type="radio" name="oc-source" value="chinese" ${currentVersion.source !== 'official' ? 'checked' : ''} style="accent-color:var(--primary)">
              汉化版
            </label>
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:6px 12px;border-radius:8px;border:1px solid var(--border);font-size:var(--font-size-sm);flex:1;justify-content:center;transition:all .15s" id="lbl-official">
              <input type="radio" name="oc-source" value="official" ${currentVersion.source === 'official' ? 'checked' : ''} style="accent-color:var(--primary)">
              原版
            </label>
          </div>
        </div>
        <div>
          <label style="font-size:var(--font-size-sm);color:var(--text-secondary);display:block;margin-bottom:8px">选择版本号</label>
          <select id="oc-version-select" class="input" style="width:100%;padding:8px 12px;font-size:var(--font-size-sm)">
            <option value="">加载中...</option>
          </select>
        </div>
        <div id="oc-action-hint" style="font-size:var(--font-size-xs);color:var(--text-tertiary);min-height:18px"></div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" data-action="cancel">取消</button>
        <button class="btn btn-primary btn-sm" data-action="confirm" disabled id="oc-confirm-btn">${isInstalled ? '切换' : '安装'}</button>
      </div>
    </div>
  `
  document.body.appendChild(overlay)

  const select = overlay.querySelector('#oc-version-select')
  const confirmBtn = overlay.querySelector('#oc-confirm-btn')
  const hintEl = overlay.querySelector('#oc-action-hint')
  const radios = overlay.querySelectorAll('input[name="oc-source"]')
  const lblChinese = overlay.querySelector('#lbl-chinese')
  const lblOfficial = overlay.querySelector('#lbl-official')

  const close = () => overlay.remove()
  overlay.querySelector('[data-action="cancel"]').onclick = close
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close() })
  overlay.addEventListener('keydown', (e) => { if (e.key === 'Escape') close() })

  let versionsCache = {}
  let currentSelect = currentVersion.source === 'official' ? 'official' : 'chinese'

  function updateRadioStyle() {
    const sel = currentSelect
    lblChinese.style.borderColor = sel !== 'official' ? 'var(--primary)' : 'var(--border)'
    lblChinese.style.background = sel !== 'official' ? 'var(--primary-bg, rgba(99,102,241,0.06))' : ''
    lblOfficial.style.borderColor = sel === 'official' ? 'var(--primary)' : 'var(--border)'
    lblOfficial.style.background = sel === 'official' ? 'var(--primary-bg, rgba(99,102,241,0.06))' : ''
  }

  function updateHint() {
    const targetSource = currentSelect
    const targetVer = select.value
    if (!targetVer || targetVer === '') { hintEl.textContent = ''; confirmBtn.disabled = true; return }

    const sameSource = targetSource === (currentVersion.source === 'official' ? 'official' : 'chinese')

    if (!isInstalled) {
      confirmBtn.textContent = '安装'
      hintEl.textContent = `将安装 ${targetSource === 'official' ? '原版' : '汉化版'} ${targetVer}`
      confirmBtn.disabled = false
      return
    }

    if (!sameSource) {
      confirmBtn.textContent = '切换'
      hintEl.innerHTML = `当前: <strong>${currentVersion.source === 'official' ? '原版' : '汉化版'} ${currentVersion.current}</strong> → <strong>${targetSource === 'official' ? '原版' : '汉化版'} ${targetVer}</strong>`
      confirmBtn.disabled = false
      return
    }

    // 同源，比较版本
    const parseVer = v => v.split(/[^0-9]/).filter(Boolean).map(Number)
    const cur = parseVer(currentVersion.current)
    const tgt = parseVer(targetVer)
    let cmp = 0
    for (let i = 0; i < Math.max(cur.length, tgt.length); i++) {
      if ((tgt[i] || 0) > (cur[i] || 0)) { cmp = 1; break }
      if ((tgt[i] || 0) < (cur[i] || 0)) { cmp = -1; break }
    }

    if (cmp === 0) {
      confirmBtn.textContent = '重新安装'
      hintEl.textContent = `当前已是 ${targetVer}`
      confirmBtn.disabled = false
    } else if (cmp > 0) {
      confirmBtn.textContent = '升级'
      hintEl.innerHTML = `<span style="color:var(--accent)">${currentVersion.current} → ${targetVer}</span>`
      confirmBtn.disabled = false
    } else {
      confirmBtn.textContent = '降级'
      hintEl.innerHTML = `<span style="color:var(--warning,#f59e0b)">${currentVersion.current} → ${targetVer}</span>`
      confirmBtn.disabled = false
    }
  }

  async function loadVersions(source) {
    select.innerHTML = '<option value="">加载中...</option>'
    confirmBtn.disabled = true
    hintEl.textContent = ''
    try {
      if (!versionsCache[source]) {
        versionsCache[source] = await api.listOpenclawVersions(source)
      }
      const versions = versionsCache[source]
      if (!versions.length) {
        select.innerHTML = '<option value="">未找到可用版本</option>'
        return
      }
      select.innerHTML = versions.map(v => {
        const isCurrent = isInstalled && v === currentVersion.current && source === (currentVersion.source === 'official' ? 'official' : 'chinese')
        return `<option value="${v}">${v}${isCurrent ? ' (当前)' : ''}</option>`
      }).join('')
      updateHint()
    } catch (e) {
      select.innerHTML = `<option value="">加载失败: ${e.message || e}</option>`
    }
  }

  radios.forEach(radio => {
    radio.addEventListener('change', () => {
      currentSelect = radio.value
      updateRadioStyle()
      loadVersions(currentSelect)
    })
  })

  select.addEventListener('change', updateHint)

  confirmBtn.onclick = () => {
    const source = currentSelect
    const ver = select.value
    const action = confirmBtn.textContent
    close()
    doInstall(page, `${action} OpenClaw`, source, ver)
  }

  updateRadioStyle()
  loadVersions(currentSelect)
}

/**
 * 执行安装/升级/降级/切换操作（带进度弹窗）
 */
async function doInstall(page, title, source, version) {
  const modal = showUpgradeModal(title)
  modal.onClose(() => loadData(page))
  let unlistenLog, unlistenProgress
  setUpgrading(true)
  try {
    if (window.__TAURI_INTERNALS__) {
      try {
        const { listen } = await import('@tauri-apps/api/event')
        unlistenLog = await listen('upgrade-log', (e) => modal.appendLog(e.payload))
        unlistenProgress = await listen('upgrade-progress', (e) => modal.setProgress(e.payload))
      } catch {}
    } else {
      modal.appendLog('Web 模式：安装过程日志不可用，请等待完成...')
    }
    const msg = await api.upgradeOpenclaw(source, version)
    modal.setDone(typeof msg === 'string' ? msg : (msg?.message || '操作完成'))
  } catch (e) {
    const errStr = String(e)
    modal.appendLog(errStr)
    const { diagnoseInstallError } = await import('../lib/error-diagnosis.js')
    const fullLog = modal.getLogText() + '\n' + errStr
    const diagnosis = diagnoseInstallError(fullLog)
    modal.setError(diagnosis.title)
    if (diagnosis.hint) modal.appendLog('')
    if (diagnosis.hint) modal.appendHtmlLog(`${statusIcon('info', 14)} ${diagnosis.hint}`)
    if (diagnosis.command) modal.appendHtmlLog(`${icon('clipboard', 14)} ${diagnosis.command}`)
    if (window.__openAIDrawerWithError) {
      window.__openAIDrawerWithError({
        title: diagnosis.title,
        error: fullLog,
        scene: title,
        hint: diagnosis.hint,
      })
    }
  } finally {
    setUpgrading(false)
    unlistenLog?.()
    unlistenProgress?.()
  }
}

async function checkHotUpdate(cards, panelVersion) {
  const el = () => cards.querySelector('#panel-update-meta')
  try {
    const info = await api.checkFrontendUpdate()
    const meta = el()
    if (!meta) return

    if (info.updateReady) {
      // 已下载更新，等待重载
      const ver = info.manifest?.version || info.latestVersion || ''
      meta.innerHTML = `
        <span style="color:var(--accent)">v${ver} 已就绪</span>
        <button class="btn btn-primary btn-sm" id="btn-hot-reload" style="padding:2px 8px;font-size:var(--font-size-xs)">重载应用</button>
        <button class="btn btn-secondary btn-sm" id="btn-hot-rollback" style="padding:2px 8px;font-size:var(--font-size-xs)">回退</button>
      `
      meta.querySelector('#btn-hot-reload')?.addEventListener('click', () => {
        window.location.reload()
      })
      meta.querySelector('#btn-hot-rollback')?.addEventListener('click', async () => {
        try {
          await api.rollbackFrontendUpdate()
          toast('已回退到内嵌版本，重载中...', 'success')
          setTimeout(() => window.location.reload(), 800)
        } catch (e) {
          toast('回退失败: ' + (e.message || e), 'error')
        }
      })
    } else if (info.hasUpdate) {
      // 有新版本可下载
      const ver = info.latestVersion
      const manifest = info.manifest || {}
      const changelog = manifest.changelog || ''
      meta.innerHTML = `
        <span style="color:var(--accent)">新版本: v${ver}</span>
        ${changelog ? `<span style="color:var(--text-tertiary);font-size:var(--font-size-xs)">${changelog}</span>` : ''}
        <button class="btn btn-primary btn-sm" id="btn-hot-download" style="padding:2px 8px;font-size:var(--font-size-xs)">热更新</button>
        <a class="btn btn-secondary btn-sm" href="https://github.com/qingchencloud/clawpanel/releases" target="_blank" rel="noopener" style="padding:2px 8px;font-size:var(--font-size-xs)">完整安装包</a>
      `
      meta.querySelector('#btn-hot-download')?.addEventListener('click', async () => {
        const btn = meta.querySelector('#btn-hot-download')
        if (btn) { btn.disabled = true; btn.textContent = '下载中...' }
        try {
          await api.downloadFrontendUpdate(manifest.url, manifest.hash || '')
          toast('更新下载完成，点击「重载应用」生效', 'success')
          checkHotUpdate(cards, panelVersion)
        } catch (e) {
          toast('下载失败: ' + (e.message || e), 'error')
          if (btn) { btn.disabled = false; btn.textContent = '重试' }
        }
      })
    } else if (!info.compatible) {
      meta.innerHTML = '<span style="color:var(--text-tertiary)">需要更新完整安装包</span> <a class="btn btn-secondary btn-sm" href="https://github.com/qingchencloud/clawpanel/releases" target="_blank" rel="noopener" style="padding:2px 8px;font-size:var(--font-size-xs)">下载</a>'
    } else {
      meta.innerHTML = '<span style="color:var(--success)">已是最新</span>'
    }
  } catch (err) {
    const meta = el()
    if (!meta) return
    const msg = String(err?.message || err || '')
    if (msg.includes('403') || msg.includes('404') || msg.includes('rate limit')) {
      meta.innerHTML = '<span style="color:var(--text-tertiary)">暂无法检查更新</span>'
    } else {
      meta.innerHTML = '<span style="color:var(--text-tertiary)">检查更新失败</span>'
    }
  }
}

function compareVersions(a, b) {
  const pa = a.split('.').map(Number)
  const pb = b.split('.').map(Number)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0
    const nb = pb[i] || 0
    if (na > nb) return 1
    if (na < nb) return -1
  }
  return 0
}

function renderCommunity(page) {
  const el = page.querySelector('#community-section')
  el.innerHTML = `
    <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start">
      <div style="text-align:center">
        <img src="/images/OpenClaw-QQ.png" alt="QQ 交流群" style="width:140px;height:140px;border-radius:var(--radius-md);border:1px solid var(--border-primary)">
        <div style="font-size:var(--font-size-sm);margin-top:8px;color:var(--text-secondary)">QQ 交流群</div>
      </div>
      <div style="text-align:center">
        <img src="/images/OpenClawWx.png" alt="微信交流群" style="width:140px;height:140px;border-radius:var(--radius-md);border:1px solid var(--border-primary)">
        <div style="font-size:var(--font-size-sm);margin-top:8px;color:var(--text-secondary)">微信交流群</div>
      </div>
      <div style="text-align:center">
        <img src="https://qt.cool/c/OpenClawDY/qr.png" alt="抖音交流群" style="width:140px;height:140px;border-radius:var(--radius-md);border:1px solid var(--border-primary);object-fit:contain;background:#fff">
        <div style="font-size:var(--font-size-sm);margin-top:8px;color:var(--text-secondary)">抖音交流群</div>
      </div>
      <div style="flex:1;min-width:200px;display:flex;flex-direction:column;gap:8px;padding-top:4px">
        <div style="font-size:var(--font-size-sm);color:var(--text-secondary)">扫码或点击链接加入交流群，反馈问题、获取帮助</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">
          <a class="btn btn-primary btn-sm" href="https://qt.cool/c/OpenClaw" target="_blank" rel="noopener">加入 QQ 群</a>
          <a class="btn btn-primary btn-sm" href="https://qt.cool/c/OpenClawWx" target="_blank" rel="noopener">加入微信群</a>
          <a class="btn btn-primary btn-sm" href="https://qt.cool/c/OpenClawDY" target="_blank" rel="noopener">加入抖音群</a>
          <a class="btn btn-secondary btn-sm" href="https://yb.tencent.com/gp/i/LsvIw7mdR7Lb" target="_blank" rel="noopener">元宝派社群</a>
        </div>
        <div style="font-size:var(--font-size-xs);color:var(--text-tertiary);margin-top:8px">
          2000 人大群，满员自动切换 · 碰到问题可直接在群内反馈
        </div>
      </div>
    </div>
  `
}

const PROJECTS = [
  {
    name: 'OpenClaw',
    desc: 'AI Agent 框架，支持多模型协作、工具调用、记忆管理',
    url: 'https://github.com/openclaw/openclaw',
  },
  {
    name: 'OpenClaw-zh',
    desc: 'AI Agent 框架，支持多模型协作、工具调用、记忆管理-中文优化版',
    url: 'https://github.com/1186258278/OpenClawChineseTranslation',
  },
  {
    name: 'ClawApp',
    desc: '跨平台移动聊天客户端，H5 + 代理服务器架构，支持离线和流式传输',
    url: 'https://github.com/qingchencloud/clawapp',
  },
  {
    name: 'cftunnel',
    desc: '全协议内网穿透工具，Cloud 模式免费 HTTP/WS + Relay 模式自建中继',
    url: 'https://github.com/qingchencloud/cftunnel',
  },
  {
    name: 'ClawPanel',
    desc: 'OpenClaw 可视化管理面板，Tauri v2 桌面应用',
    url: 'https://github.com/qingchencloud/clawpanel',
  },
]

function renderProjects(page) {
  const el = page.querySelector('#projects-list')
  el.innerHTML = PROJECTS.map(p => `
    <div class="service-card">
      <div class="service-info">
        <div>
          <div class="service-name">${p.name}</div>
          <div class="service-desc">${p.desc}</div>
        </div>
      </div>
      <div class="service-actions">
        <a class="btn btn-secondary btn-sm" href="${p.url}" target="_blank" rel="noopener">GitHub</a>
      </div>
    </div>
  `).join('')
}

const LINKS = [
  { label: 'Claw 项目官网', url: 'https://claw.qt.cool', primary: true },
  { label: 'cftunnel 官网', url: 'https://cftunnel.qt.cool' },
  { label: 'cftunnel 桌面客户端', url: 'https://github.com/qingchencloud/cftunnel-app/releases' },
  { label: 'OpenClaw 中文翻译', url: 'https://github.com/1186258278/OpenClawChineseTranslation' },
  { label: 'ClawApp 文档', url: 'https://github.com/qingchencloud/clawapp#readme' },
]

function renderContribute(page) {
  const el = page.querySelector('#contribute-section')
  el.innerHTML = `
    <div style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:12px">
      ClawPanel 是开源项目，欢迎参与贡献！遇到问题请提 Issue，功能建议和代码改进欢迎提 PR。
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:8px">
      <a class="btn btn-primary btn-sm" href="https://github.com/qingchencloud/clawpanel/issues/new" target="_blank" rel="noopener">提交 Issue</a>
      <a class="btn btn-secondary btn-sm" href="https://github.com/qingchencloud/clawpanel/pulls" target="_blank" rel="noopener">提交 PR</a>
      <a class="btn btn-secondary btn-sm" href="https://github.com/qingchencloud/clawpanel/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener">贡献指南</a>
      <a class="btn btn-secondary btn-sm" href="https://github.com/qingchencloud/clawpanel/issues" target="_blank" rel="noopener">查看 Issues</a>
    </div>
  `
}

function renderLinks(page) {
  const el = page.querySelector('#links-list')
  el.innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:var(--space-sm)">
    ${LINKS.map(l => `<a class="btn ${l.primary ? 'btn-primary' : 'btn-secondary'} btn-sm" href="${l.url}" target="_blank" rel="noopener">${l.label}</a>`).join('')}
  </div>`
}

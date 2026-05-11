const defaultBackendUrl = 'http://localhost:8000'

async function getSettings() {
  const stored = await chrome.storage.local.get(['backendUrl', 'authToken', 'lastScan'])
  return {
    backendUrl: stored.backendUrl || defaultBackendUrl,
    authToken: stored.authToken || '',
    lastScan: stored.lastScan || null,
  }
}

async function setSettings(partial) {
  await chrome.storage.local.set(partial)
}

async function fetchPageContext(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'GET_PAGE_CONTEXT' })
    if (response?.ok) {
      return response.context
    }
  } catch {
    return { text: '', html: '', title: '', url: '' }
  }
  return { text: '', html: '', title: '', url: '' }
}

async function scanActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab?.url) {
    throw new Error('No active tab found')
  }

  const settings = await getSettings()
  if (!settings.authToken) {
    throw new Error('Missing JWT token. Paste your dashboard token in the extension settings.')
  }

  const pageContext = await fetchPageContext(tab.id)
  const response = await fetch(`${settings.backendUrl}/api/v1/scan/page`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${settings.authToken}`,
    },
    body: JSON.stringify({
      url: tab.url,
      text: pageContext.text || tab.title || '',
      page_html: pageContext.html || '',
    }),
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(`Scan failed with status ${response.status}: ${message}`)
  }

  const result = await response.json()
  await setSettings({ lastScan: { result, pageContext } })
  return result
}

async function explainDeep() {
  const settings = await getSettings()
  if (!settings.authToken) {
    throw new Error('Missing JWT token.')
  }
  if (!settings.lastScan?.result) {
    throw new Error('Run a scan first.')
  }

  const { result, pageContext } = settings.lastScan
  const response = await fetch(`${settings.backendUrl}/api/v1/explain-deep`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${settings.authToken}`,
    },
    body: JSON.stringify({
      url: pageContext?.url || '',
      page_text: pageContext?.text || '',
      risk_score: Math.min(10, Math.max(0, Math.round((result?.risk_score || 0) / 10))),
    }),
  })

  if (response.status === 501) {
    const body = await response.json().catch(() => ({}))
    return { ok: false, error: body.detail || 'OpenRouter is not configured.' }
  }
  if (!response.ok) {
    throw new Error(`Deep analysis failed with status ${response.status}`)
  }
  return { ok: true, result: await response.json() }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'SAVE_SETTINGS') {
    setSettings(message.settings)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'GET_SETTINGS') {
    getSettings()
      .then((settings) => sendResponse({ ok: true, settings }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'GET_LAST_SCAN') {
    getSettings()
      .then((settings) => sendResponse({ ok: true, lastScan: settings.lastScan }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'SCAN_ACTIVE_TAB') {
    scanActiveTab()
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'DEEP_ANALYSIS') {
    explainDeep()
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  return undefined
})

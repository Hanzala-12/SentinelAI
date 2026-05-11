const backendUrlInput = document.getElementById('backendUrl')
const authTokenInput = document.getElementById('authToken')
const saveSettingsButton = document.getElementById('saveSettings')
const openDashboardButton = document.getElementById('openDashboard')
const scanButton = document.getElementById('scanButton')
const deepButton = document.getElementById('deepButton')
const riskScore = document.getElementById('riskScore')
const classification = document.getElementById('classification')
const status = document.getElementById('status')
const explanation = document.getElementById('explanation')
const issues = document.getElementById('issues')

function renderIssues(list) {
  issues.innerHTML = ''
  if (!list || !list.length) {
    const item = document.createElement('li')
    item.textContent = 'No high-confidence issues were detected.'
    issues.appendChild(item)
    return
  }

  for (const issue of list) {
    const item = document.createElement('li')
    item.textContent = `${issue.title}: ${issue.description}`
    issues.appendChild(item)
  }
}

function syncSettingsIntoInputs() {
  chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (response) => {
    if (!response?.ok) {
      return
    }
    backendUrlInput.value = response.settings.backendUrl || 'http://localhost:8000'
    authTokenInput.value = response.settings.authToken || ''
    if (response.settings.lastScan?.result) {
      applyResult(response.settings.lastScan.result)
    }
  })
}

function applyResult(result) {
  riskScore.textContent = `${result.risk_score ?? '--'}`
  classification.textContent = result.classification || 'Unknown'
  explanation.textContent = result.explanation?.explanation || 'No explanation available.'
  renderIssues(result.detected_issues || [])
}

saveSettingsButton.addEventListener('click', () => {
  chrome.runtime.sendMessage(
    {
      type: 'SAVE_SETTINGS',
      settings: {
        backendUrl: backendUrlInput.value.trim() || 'http://localhost:8000',
        authToken: authTokenInput.value.trim(),
      },
    },
    (response) => {
      status.textContent = response?.ok ? 'Settings saved.' : response?.error ?? 'Failed to save settings.'
    },
  )
})

openDashboardButton.addEventListener('click', () => {
  chrome.tabs.create({ url: 'http://localhost:5173' })
})

scanButton.addEventListener('click', () => {
  status.textContent = 'Scanning active tab...'
  chrome.runtime.sendMessage({ type: 'SCAN_ACTIVE_TAB' }, (response) => {
    if (!response?.ok) {
      status.textContent = response?.error ?? 'Scan failed.'
      return
    }
    status.textContent = 'Scan complete.'
    applyResult(response.result)
  })
})

deepButton.addEventListener('click', () => {
  status.textContent = 'Running deep analysis...'
  chrome.runtime.sendMessage({ type: 'DEEP_ANALYSIS' }, (response) => {
    if (!response?.ok) {
      status.textContent = response?.error ?? 'Deep analysis unavailable.'
      return
    }
    if (response.result?.used_llm) {
      explanation.textContent = response.result.explanation
      status.textContent = 'Deep analysis complete.'
    } else {
      explanation.textContent = response.error || 'Deep analysis unavailable.'
      status.textContent = response.error || 'Deep analysis unavailable.'
    }
  })
})

syncSettingsIntoInputs()

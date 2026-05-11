import axios from 'axios'
import { useEffect, useMemo, useState } from 'react'
import { api, clearAuthToken, getAuthToken, setAuthToken } from './lib/api'

type HealthState = {
  status: string
  service: string
  version: string
}

type AuthResponse = {
  access_token: string
  token_type: string
}

type EvidenceItem = {
  code: string
  title: string
  description: string
  severity: string
  source: string
  category: string
  score_impact: number
  confidence: number
  value?: unknown
}

type ThreatReport = {
  threat_level: string
  executive_summary: string
  reasoning_chain: string[]
  recommended_actions: string[]
  component_scores: Record<string, number>
  weighted_contributions: Record<string, number>
  indicators: Record<string, string[]>
  signal_counts: Record<string, number>
  evidence: EvidenceItem[]
  fetch_error?: string | null
}

type TechnicalFindings = {
  normalized_url: string | null
  redirect_chain: string[]
  fetched_html: boolean
  url_signals: EvidenceItem[]
  dom_signals: EvidenceItem[]
  content_signals: EvidenceItem[]
  reputation_signals: EvidenceItem[]
  model_signals: EvidenceItem[]
  metadata: Record<string, unknown>
}

type ScanResponse = {
  risk_score: number
  classification: string
  confidence: number
  explanation: {
    explanation: string
    detected_patterns: string[]
    confidence: number
  }
  detected_issues: Array<{
    code: string
    title: string
    description: string
    severity: string
  }>
  source_breakdown: Record<string, number>
  threat_report?: ThreatReport
  technical_findings?: TechnicalFindings
}

type HistoryItem = {
  id: number
  url: string | null
  scan_type: string
  risk_score: number
  classification: string
  confidence: number
  explanation: string
  created_at: string | null
}

type DashboardStats = {
  classification_breakdown: Array<{
    classification: string
    count: number
    avg_risk_score: number
  }>
  recent_scans: HistoryItem[]
  total_scans: number
  feature_flags?: {
    llm_enabled: boolean
    threat_intel_enabled: boolean
    vt_enabled: boolean
    urlscan_enabled: boolean
    abuseipdb_enabled: boolean
  }
}

type PageKey = 'Home' | 'Threat Report' | 'History' | 'Technical Analysis'

const pages: PageKey[] = ['Home', 'Threat Report', 'History', 'Technical Analysis']

function formatTime(value: string | null): string {
  if (!value) return 'Unknown'
  return new Date(value).toLocaleString()
}

function severityTone(severity: string): string {
  const normalized = severity.toLowerCase()
  if (normalized === 'critical' || normalized === 'high') return 'border-red-300 bg-red-50 text-red-700'
  if (normalized === 'medium') return 'border-amber-300 bg-amber-50 text-amber-700'
  if (normalized === 'low') return 'border-emerald-300 bg-emerald-50 text-emerald-700'
  return 'border-slate-300 bg-slate-100 text-slate-700'
}

function classificationTone(classification: string): string {
  if (classification === 'Critical' || classification === 'Dangerous') return 'border-red-300 bg-red-50 text-red-700'
  if (classification === 'Suspicious') return 'border-amber-300 bg-amber-50 text-amber-700'
  return 'border-emerald-300 bg-emerald-50 text-emerald-700'
}

export default function App() {
  const [health, setHealth] = useState<HealthState | null>(null)
  const [healthLoading, setHealthLoading] = useState(true)
  const [token, setTokenState] = useState<string | null>(getAuthToken())
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')
  const [authEmail, setAuthEmail] = useState('')
  const [authPassword, setAuthPassword] = useState('')
  const [authBusy, setAuthBusy] = useState(false)
  const [authError, setAuthError] = useState<string | null>(null)

  const [activePage, setActivePage] = useState<PageKey>('Home')
  const [dashboardStats, setDashboardStats] = useState<DashboardStats | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [historyQuery, setHistoryQuery] = useState('')
  const [historyFilter, setHistoryFilter] = useState<'all' | 'Safe' | 'Suspicious' | 'Dangerous' | 'Critical'>('all')

  const [scanUrl, setScanUrl] = useState('https://example.com')
  const [scanText, setScanText] = useState('')
  const [scanHtml, setScanHtml] = useState('')
  const [scanBusy, setScanBusy] = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)
  const [latestScan, setLatestScan] = useState<ScanResponse | null>(null)
  const [latestAnalyzedUrl, setLatestAnalyzedUrl] = useState<string | null>(null)
  const [latestTextPayload, setLatestTextPayload] = useState('')
  const [deepAnalysis, setDeepAnalysis] = useState('')
  const [deepBusy, setDeepBusy] = useState(false)

  useEffect(() => {
    let active = true
    api
      .get<HealthState>('/api/v1/health')
      .then((response) => {
        if (active) setHealth(response.data)
      })
      .catch(() => {
        if (active) setHealth(null)
      })
      .finally(() => {
        if (active) setHealthLoading(false)
      })
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (!token) {
      setDashboardStats(null)
      setHistory([])
      return
    }
    void refreshWorkspace()
  }, [token])

  const refreshWorkspace = async () => {
    try {
      const [statsRes, historyRes] = await Promise.all([
        api.get<DashboardStats>('/api/v1/dashboard/stats'),
        api.get<{ items: HistoryItem[]; total: number }>('/api/v1/history?limit=100&offset=0'),
      ])
      setDashboardStats(statsRes.data)
      setHistory(historyRes.data.items)
    } catch {
      setDashboardStats(null)
      setHistory([])
    }
  }

  const handleAuth = async () => {
    setAuthBusy(true)
    setAuthError(null)
    try {
      const endpoint = authMode === 'login' ? '/api/v1/auth/login' : '/api/v1/auth/register'
      const response = await api.post<AuthResponse>(endpoint, {
        email: authEmail.trim(),
        password: authPassword,
      })
      setAuthToken(response.data.access_token)
      setTokenState(response.data.access_token)
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = typeof error.response?.data?.detail === 'string' ? error.response.data.detail : null
        if (error.response?.status === 409) {
          setAuthError(detail ?? 'Account already exists. Try login.')
        } else if (error.response?.status === 401) {
          setAuthError(detail ?? 'Invalid credentials.')
        } else {
          setAuthError(detail ?? 'Authentication failed.')
        }
      } else {
        setAuthError('Authentication failed.')
      }
    } finally {
      setAuthBusy(false)
    }
  }

  const logout = () => {
    clearAuthToken()
    setTokenState(null)
    setLatestScan(null)
    setDeepAnalysis('')
  }

  const runScan = async () => {
    setScanBusy(true)
    setScanError(null)
    setDeepAnalysis('')
    try {
      const normalizedUrl = scanUrl.match(/^https?:\/\//i) ? scanUrl.trim() : `https://${scanUrl.trim()}`
      const textPayload = scanText.trim()
      const htmlPayload = scanHtml.trim()
      const endpoint = textPayload ? '/api/v1/scan/page' : '/api/v1/scan/url'
      const body = textPayload
        ? {
            url: normalizedUrl,
            text: textPayload,
            page_html: htmlPayload || undefined,
          }
        : {
            url: normalizedUrl,
            page_text: undefined,
            page_html: htmlPayload || undefined,
          }

      const response = await api.post<ScanResponse>(endpoint, body)
      setLatestScan(response.data)
      setLatestAnalyzedUrl(normalizedUrl)
      setLatestTextPayload(textPayload)
      setActivePage('Threat Report')
      await refreshWorkspace()
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = typeof error.response?.data?.detail === 'string' ? error.response.data.detail : null
        setScanError(detail ?? 'Scan failed. Verify the URL and retry.')
      } else {
        setScanError('Scan failed.')
      }
    } finally {
      setScanBusy(false)
    }
  }

  const runDeepAnalysis = async () => {
    if (!latestScan || !latestAnalyzedUrl) return
    setDeepBusy(true)
    try {
      const response = await api.post<{ explanation: string; model: string; used_llm: boolean }>('/api/v1/explain-deep', {
        url: latestAnalyzedUrl,
        page_text: latestTextPayload || '',
        risk_score: Math.min(10, Math.max(0, Math.round(latestScan.risk_score / 10))),
      })
      setDeepAnalysis(response.data.explanation)
    } catch {
      setDeepAnalysis('Deep AI narrative is unavailable because OpenRouter is not configured or returned an error.')
    } finally {
      setDeepBusy(false)
    }
  }

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesFilter = historyFilter === 'all' || item.classification === historyFilter
      const query = historyQuery.trim().toLowerCase()
      const matchesQuery = !query || (item.url ?? '').toLowerCase().includes(query) || item.explanation.toLowerCase().includes(query)
      return matchesFilter && matchesQuery
    })
  }, [history, historyFilter, historyQuery])

  const classificationMap = useMemo(() => {
    return new Map((dashboardStats?.classification_breakdown ?? []).map((row) => [row.classification, row.count]))
  }, [dashboardStats])

  if (!token) {
    return (
      <main className="min-h-screen px-5 py-10">
        <div className="mx-auto grid max-w-6xl gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <section className="soft-panel rounded-3xl p-8 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-[0.25em] text-slate-500">SentinelAI</p>
            <h1 className="mt-4 text-4xl font-semibold tracking-tight text-slate-900">Intelligent Threat Reasoning and Phishing Analysis</h1>
            <p className="mt-5 max-w-2xl text-sm leading-7 text-slate-600">
              Investigate suspicious URLs and webpage content using structured signal extraction, threat reasoning, and explainable evidence-driven reports.
            </p>
            <div className="mt-8 grid gap-4 md:grid-cols-2">
              <article className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Core Engine</p>
                <p className="mt-2 text-sm font-medium text-slate-800">URL, DOM, content, and reputation signals are correlated into a transparent risk model.</p>
              </article>
              <article className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Explainability</p>
                <p className="mt-2 text-sm font-medium text-slate-800">Every score is linked to concrete indicators and analyst-relevant remediation actions.</p>
              </article>
            </div>
          </section>

          <section className="soft-panel rounded-3xl p-8 shadow-sm">
            <div className="grid grid-cols-2 gap-2 rounded-2xl bg-slate-100 p-1">
              <button
                onClick={() => setAuthMode('login')}
                className={`rounded-xl px-3 py-2 text-sm font-medium ${authMode === 'login' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'}`}
              >
                Login
              </button>
              <button
                onClick={() => setAuthMode('register')}
                className={`rounded-xl px-3 py-2 text-sm font-medium ${authMode === 'register' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'}`}
              >
                Register
              </button>
            </div>

            <label className="mt-6 block text-sm text-slate-700">
              Email
              <input
                type="email"
                value={authEmail}
                onChange={(event) => setAuthEmail(event.target.value)}
                className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none focus:border-sky-500"
              />
            </label>
            <label className="mt-4 block text-sm text-slate-700">
              Password
              <input
                type="password"
                value={authPassword}
                onChange={(event) => setAuthPassword(event.target.value)}
                className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none focus:border-sky-500"
              />
            </label>

            {authError && <p className="mt-3 text-sm text-red-700">{authError}</p>}

            <button
              onClick={handleAuth}
              disabled={authBusy}
              className="mt-6 w-full rounded-xl bg-sky-700 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60"
            >
              {authBusy ? 'Authenticating...' : authMode === 'login' ? 'Sign in' : 'Create account'}
            </button>
          </section>
        </div>
      </main>
    )
  }

  return (
    <main className="min-h-screen px-5 py-6">
      <div className="mx-auto flex max-w-7xl flex-col gap-5">
        <header className="soft-panel rounded-3xl p-5 shadow-sm">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">SentinelAI</p>
              <h1 className="mt-2 text-2xl font-semibold text-slate-900">Threat Reasoning Console</h1>
              <p className="mt-2 text-sm text-slate-600">Evidence-focused phishing analysis with transparent scoring and investigation outputs.</p>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Runtime</p>
                <p className="mt-1 text-sm font-semibold text-slate-900">{healthLoading ? 'Checking' : health ? 'Online' : 'Offline'}</p>
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Total Scans</p>
                <p className="mt-1 text-sm font-semibold text-slate-900">{dashboardStats?.total_scans ?? 0}</p>
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">High Risk</p>
                <p className="mt-1 text-sm font-semibold text-slate-900">
                  {(classificationMap.get('Dangerous') ?? 0) + (classificationMap.get('Critical') ?? 0)}
                </p>
              </div>
            </div>
          </div>
        </header>

        <nav className="soft-panel flex flex-wrap items-center gap-2 rounded-2xl p-2 shadow-sm">
          {pages.map((page) => (
            <button
              key={page}
              onClick={() => setActivePage(page)}
              className={`rounded-xl px-4 py-2 text-sm font-medium ${activePage === page ? 'bg-slate-900 text-white' : 'text-slate-700 hover:bg-slate-100'}`}
            >
              {page}
            </button>
          ))}
          <button
            onClick={logout}
            className="ml-auto rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
          >
            Log out
          </button>
        </nav>

        {activePage === 'Home' && (
          <section className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
            <div className="soft-panel rounded-3xl p-6 shadow-sm">
              <h2 className="text-lg font-semibold text-slate-900">Run Threat Analysis</h2>
              <p className="mt-1 text-sm text-slate-600">Submit a URL with optional page content/HTML to extract phishing indicators and generate an explainable report.</p>

              <label className="mt-5 block text-sm font-medium text-slate-700">
                Target URL
                <input
                  value={scanUrl}
                  onChange={(event) => setScanUrl(event.target.value)}
                  className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none focus:border-sky-500"
                />
              </label>

              <label className="mt-4 block text-sm font-medium text-slate-700">
                Optional page text
                <textarea
                  rows={6}
                  value={scanText}
                  onChange={(event) => setScanText(event.target.value)}
                  className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none focus:border-sky-500"
                  placeholder="Paste suspicious message/content to improve scam language detection."
                />
              </label>

              <label className="mt-4 block text-sm font-medium text-slate-700">
                Optional page HTML
                <textarea
                  rows={5}
                  value={scanHtml}
                  onChange={(event) => setScanHtml(event.target.value)}
                  className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-800 outline-none focus:border-sky-500"
                  placeholder="<html>...</html>"
                />
              </label>

              <div className="mt-5 flex flex-wrap gap-3">
                <button
                  onClick={runScan}
                  disabled={scanBusy}
                  className="rounded-xl bg-sky-700 px-4 py-2 text-sm font-semibold text-white disabled:opacity-60"
                >
                  {scanBusy ? 'Analyzing...' : 'Analyze Threat'}
                </button>
                <button
                  onClick={() => {
                    setScanText('')
                    setScanHtml('')
                  }}
                  className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
                >
                  Clear Inputs
                </button>
              </div>
              {scanError && <p className="mt-4 text-sm text-red-700">{scanError}</p>}
            </div>

            <div className="soft-panel rounded-3xl p-6 shadow-sm">
              <h2 className="text-lg font-semibold text-slate-900">Latest Result</h2>
              {!latestScan ? (
                <p className="mt-3 text-sm text-slate-600">Run a scan to populate threat report and technical indicators.</p>
              ) : (
                <div className="mt-4 space-y-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${classificationTone(latestScan.classification)}`}>
                      {latestScan.classification}
                    </span>
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-3 py-1 text-xs text-slate-700">
                      Risk {latestScan.risk_score}/100
                    </span>
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-3 py-1 text-xs text-slate-700">
                      Confidence {Math.round(latestScan.confidence * 100)}%
                    </span>
                  </div>
                  <p className="text-sm leading-6 text-slate-700">{latestScan.explanation.explanation}</p>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Detected Patterns</p>
                    <p className="mt-2 break-all font-mono text-xs text-slate-700">
                      {latestScan.explanation.detected_patterns.length ? latestScan.explanation.detected_patterns.join(', ') : 'No strong pattern IDs'}
                    </p>
                  </div>
                  <button
                    onClick={() => setActivePage('Threat Report')}
                    className="rounded-xl border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
                  >
                    Open Detailed Threat Report
                  </button>
                </div>
              )}
            </div>
          </section>
        )}

        {activePage === 'Threat Report' && (
          <section className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
            <div className="soft-panel rounded-3xl p-6 shadow-sm">
              <h2 className="text-lg font-semibold text-slate-900">Threat Report</h2>
              {!latestScan?.threat_report ? (
                <p className="mt-3 text-sm text-slate-600">No threat report is available yet. Run a scan from Home first.</p>
              ) : (
                <div className="mt-4 space-y-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${classificationTone(latestScan.threat_report.threat_level)}`}>
                      {latestScan.threat_report.threat_level}
                    </span>
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-3 py-1 text-xs text-slate-700">
                      Score {latestScan.risk_score}/100
                    </span>
                  </div>
                  <p className="text-sm leading-6 text-slate-700">{latestScan.threat_report.executive_summary}</p>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Reasoning Chain</p>
                    <ul className="mt-2 space-y-2 text-sm text-slate-700">
                      {latestScan.threat_report.reasoning_chain.map((reason, index) => (
                        <li key={`${reason}-${index}`}>{reason}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Recommended Actions</p>
                    <ul className="mt-2 space-y-2 text-sm text-slate-700">
                      {latestScan.threat_report.recommended_actions.map((action, index) => (
                        <li key={`${action}-${index}`}>{action}</li>
                      ))}
                    </ul>
                  </div>

                  {latestScan.threat_report.fetch_error && (
                    <p className="rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
                      DOM fetch note: {latestScan.threat_report.fetch_error}
                    </p>
                  )}
                </div>
              )}
            </div>

            <div className="soft-panel rounded-3xl p-6 shadow-sm">
              <h2 className="text-lg font-semibold text-slate-900">Evidence & AI Enrichment</h2>
              {!latestScan?.threat_report ? (
                <p className="mt-3 text-sm text-slate-600">Evidence appears after the first scan.</p>
              ) : (
                <div className="mt-4 space-y-3">
                  {latestScan.threat_report.evidence.slice(0, 8).map((item) => (
                    <article key={item.code} className="rounded-xl border border-slate-200 bg-white p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${severityTone(item.severity)}`}>{item.severity}</span>
                        <span className="font-mono text-[11px] text-slate-500">{item.code}</span>
                      </div>
                      <p className="mt-2 text-sm font-medium text-slate-800">{item.title}</p>
                      <p className="mt-1 text-xs leading-5 text-slate-600">{item.description}</p>
                    </article>
                  ))}
                  <button
                    onClick={runDeepAnalysis}
                    disabled={deepBusy}
                    className="w-full rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-60"
                  >
                    {deepBusy ? 'Generating AI narrative...' : 'Generate AI Narrative'}
                  </button>
                  {deepAnalysis && (
                    <div className="rounded-xl border border-sky-200 bg-sky-50 p-3">
                      <p className="text-xs uppercase tracking-[0.2em] text-sky-700">AI Summary</p>
                      <p className="mt-2 text-sm leading-6 text-slate-700">{deepAnalysis}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>
        )}

        {activePage === 'History' && (
          <section className="soft-panel rounded-3xl p-6 shadow-sm">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-slate-900">Scan History</h2>
                <p className="text-sm text-slate-600">Review previous investigations and filter by risk classification.</p>
              </div>
              <button
                onClick={() => void refreshWorkspace()}
                className="rounded-xl border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
              >
                Refresh
              </button>
            </div>

            <div className="mt-4 flex flex-wrap gap-3">
              <input
                value={historyQuery}
                onChange={(event) => setHistoryQuery(event.target.value)}
                className="min-w-[260px] flex-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-sky-500"
                placeholder="Search URL or explanation"
              />
              <select
                value={historyFilter}
                onChange={(event) => setHistoryFilter(event.target.value as typeof historyFilter)}
                className="rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-sky-500"
              >
                <option value="all">All levels</option>
                <option value="Safe">Safe</option>
                <option value="Suspicious">Suspicious</option>
                <option value="Dangerous">Dangerous</option>
                <option value="Critical">Critical</option>
              </select>
            </div>

            <div className="mt-4 overflow-x-auto rounded-2xl border border-slate-200">
              <table className="min-w-full bg-white text-sm">
                <thead className="bg-slate-100 text-slate-700">
                  <tr>
                    <th className="px-3 py-2 text-left">Time</th>
                    <th className="px-3 py-2 text-left">Target</th>
                    <th className="px-3 py-2 text-left">Type</th>
                    <th className="px-3 py-2 text-left">Risk</th>
                    <th className="px-3 py-2 text-left">Classification</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.length === 0 ? (
                    <tr>
                      <td className="px-3 py-4 text-slate-500" colSpan={5}>
                        No scans match the current filter.
                      </td>
                    </tr>
                  ) : (
                    filteredHistory.map((item) => (
                      <tr key={item.id} className="border-t border-slate-200">
                        <td className="px-3 py-2 text-slate-600">{formatTime(item.created_at)}</td>
                        <td className="max-w-[420px] truncate px-3 py-2 text-slate-800">{item.url ?? 'Text-only scan'}</td>
                        <td className="px-3 py-2 text-slate-600">{item.scan_type}</td>
                        <td className="px-3 py-2 text-slate-800">{item.risk_score}/100</td>
                        <td className="px-3 py-2">
                          <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${classificationTone(item.classification)}`}>
                            {item.classification}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {activePage === 'Technical Analysis' && (
          <section className="grid gap-5 xl:grid-cols-[1fr_1fr]">
            <div className="soft-panel rounded-3xl p-6 shadow-sm">
              <h2 className="text-lg font-semibold text-slate-900">Component Scores</h2>
              {!latestScan?.threat_report ? (
                <p className="mt-3 text-sm text-slate-600">Run a scan to view score composition and indicator groups.</p>
              ) : (
                <div className="mt-4 space-y-4">
                  <div className="grid gap-3 sm:grid-cols-2">
                    {Object.entries(latestScan.threat_report.component_scores).map(([key, value]) => (
                      <div key={key} className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2">
                        <p className="font-mono text-xs text-slate-500">{key}</p>
                        <p className="mt-1 text-sm font-semibold text-slate-900">{value}/100</p>
                      </div>
                    ))}
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Indicators</p>
                    <div className="mt-2 space-y-2 text-sm">
                      {Object.entries(latestScan.threat_report.indicators).map(([source, codes]) => (
                        <div key={source}>
                          <p className="font-medium text-slate-700">{source}</p>
                          <p className="font-mono text-xs text-slate-600">{codes.join(', ')}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="soft-panel rounded-3xl p-6 shadow-sm">
              <h2 className="text-lg font-semibold text-slate-900">Raw Signal Findings</h2>
              {!latestScan?.technical_findings ? (
                <p className="mt-3 text-sm text-slate-600">Technical findings are available after running a scan.</p>
              ) : (
                <div className="mt-4 space-y-4">
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">
                    <p>Normalized URL: <span className="font-mono">{latestScan.technical_findings.normalized_url ?? 'N/A'}</span></p>
                    <p className="mt-1">Fetched HTML: {latestScan.technical_findings.fetched_html ? 'yes' : 'no'}</p>
                    <p className="mt-1">Redirect Chain: {latestScan.technical_findings.redirect_chain.length || 0}</p>
                  </div>

                  {(
                    [
                      { label: 'URL Signals', signals: latestScan.technical_findings.url_signals },
                      { label: 'DOM Signals', signals: latestScan.technical_findings.dom_signals },
                      { label: 'Content Signals', signals: latestScan.technical_findings.content_signals },
                      { label: 'Reputation Signals', signals: latestScan.technical_findings.reputation_signals },
                      { label: 'Model Signals', signals: latestScan.technical_findings.model_signals },
                    ] as Array<{ label: string; signals: EvidenceItem[] }>
                  ).map((group) => (
                    <div key={group.label} className="rounded-xl border border-slate-200 bg-white p-3">
                      <p className="text-sm font-semibold text-slate-800">{group.label}</p>
                      {!Array.isArray(group.signals) || group.signals.length === 0 ? (
                        <p className="mt-1 text-xs text-slate-500">No indicators in this category.</p>
                      ) : (
                        <ul className="mt-2 space-y-2">
                          {group.signals.slice(0, 5).map((signal) => (
                            <li key={`${signal.code}-${signal.title}`} className="text-xs text-slate-700">
                              <span className={`mr-2 inline-block rounded-full border px-2 py-0.5 text-[10px] ${severityTone(signal.severity)}`}>
                                {signal.severity}
                              </span>
                              <span className="font-medium">{signal.title}</span>
                              <p className="mt-1 text-[11px] text-slate-600">{signal.description}</p>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        )}
      </div>
    </main>
  )
}

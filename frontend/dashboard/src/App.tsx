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
  reliability: number
  reasoning_context?: string | null
  escalation_contribution: number
  source_module?: string | null
  analyst_details?: Record<string, unknown>
  value?: unknown
}

type TimelineEvent = {
  event_id: string
  timestamp: string
  stage: string
  source: string
  title: string
  detail: string
  severity: string
  score_before: number
  score_after: number
  score_delta: number
  confidence_before: number
  confidence_after: number
  classification_after: string
  evidence_codes: string[]
}

type AttackPattern = {
  code: string
  title: string
  description: string
  confidence: number
  evidence_codes: string[]
}

type InteractionReplayEvent = {
  step_id: string
  timestamp: string
  action: string
  target: string
  url_before: string
  url_after: string
  redirect_triggered: boolean
  new_indicator_codes: string[]
  dom_mutations: Record<string, unknown>
  confidence_after: number
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
  attack_patterns: AttackPattern[]
  confidence_progression: Array<Record<string, unknown>>
  social_engineering_analysis: Record<string, unknown>
  timeline: TimelineEvent[]
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
  interaction_events: InteractionReplayEvent[]
  attack_patterns: AttackPattern[]
  social_engineering_analysis: Record<string, unknown>
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

function stageLabel(stage: string): string {
  const map: Record<string, string> = {
    collection: 'Collection',
    'url-analysis': 'URL Analysis',
    'delivery-analysis': 'Delivery Path',
    'dom-analysis': 'DOM Behavior',
    'content-analysis': 'Content Analysis',
    'model-correlation': 'Model Correlation',
    'intel-correlation': 'Intel Correlation',
    'interaction-simulation': 'Interaction Probe',
    reasoning: 'Reasoning',
    escalation: 'Escalation',
    conclusion: 'Conclusion',
  }
  return map[stage] ?? stage
}

function confidenceTone(confidence: number): string {
  if (confidence >= 0.85) return 'text-red-700'
  if (confidence >= 0.65) return 'text-amber-700'
  return 'text-slate-700'
}

function extractApiErrorDetail(payload: unknown): string | null {
  if (typeof payload === 'string') return payload
  if (!payload || typeof payload !== 'object') return null

  const detail = (payload as { detail?: unknown }).detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0]
    if (first && typeof first === 'object' && 'msg' in first && typeof first.msg === 'string') {
      return first.msg
    }
  }
  return null
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
  const [analystMode, setAnalystMode] = useState(false)
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
        const detail = extractApiErrorDetail(error.response?.data)
        if (!error.response) {
          setAuthError('Could not reach the API server. Make sure backend is running on the configured URL.')
        } else if (error.response.status === 422) {
          setAuthError(detail ?? 'Invalid email or password format.')
        } else if (error.response?.status === 409) {
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
            onClick={() => setAnalystMode((value) => !value)}
            className={`rounded-xl border px-4 py-2 text-sm font-medium ${
              analystMode ? 'border-sky-500 bg-sky-50 text-sky-800' : 'border-slate-300 text-slate-700 hover:bg-slate-100'
            }`}
          >
            {analystMode ? 'Analyst Mode On' : 'Analyst Mode Off'}
          </button>
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
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Threat Timeline</p>
                    <div className="mt-3 space-y-3">
                      {latestScan.threat_report.timeline?.length ? (
                        latestScan.threat_report.timeline.map((event) => (
                          <article key={event.event_id} className="rounded-xl border border-slate-200 bg-white p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${severityTone(event.severity)}`}>
                                {event.severity}
                              </span>
                              <span className="text-xs font-medium text-slate-700">{stageLabel(event.stage)}</span>
                              <span className="font-mono text-[10px] text-slate-500">{new Date(event.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <p className="mt-2 text-sm font-medium text-slate-800">{event.title}</p>
                            <p className="mt-1 text-xs leading-5 text-slate-600">{event.detail}</p>
                            <p className="mt-2 text-[11px] text-slate-600">
                              Score {event.score_before}
                              {' -> '}
                              {event.score_after} ({event.classification_after})
                            </p>
                            <p className={`mt-1 text-[11px] ${confidenceTone(event.confidence_after)}`}>
                              Confidence {Math.round(event.confidence_before * 100)}%
                              {' -> '}
                              {Math.round(event.confidence_after * 100)}%
                            </p>
                            {event.evidence_codes.length > 0 && (
                              <p className="mt-1 font-mono text-[10px] text-slate-500">{event.evidence_codes.join(', ')}</p>
                            )}
                          </article>
                        ))
                      ) : (
                        <p className="text-xs text-slate-500">Timeline is unavailable for this scan.</p>
                      )}
                    </div>
                  </div>

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

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Confidence Escalation View</p>
                    <div className="mt-2 space-y-2">
                      {latestScan.threat_report.timeline
                        .filter((event) => event.stage === 'escalation' || event.stage === 'interaction-simulation' || event.stage === 'conclusion')
                        .map((event) => (
                          <div key={`${event.event_id}-confidence`} className="rounded-lg border border-slate-200 bg-white p-2">
                            <p className="text-xs font-medium text-slate-800">{event.title}</p>
                            <p className={`mt-1 text-[11px] ${confidenceTone(event.confidence_after)}`}>
                              {new Date(event.timestamp).toLocaleTimeString()} | Score {event.score_after} | Confidence {Math.round(event.confidence_after * 100)}%
                            </p>
                          </div>
                        ))}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Attack Pattern Classification</p>
                    {latestScan.threat_report.attack_patterns?.length ? (
                      <div className="mt-2 grid gap-2">
                        {latestScan.threat_report.attack_patterns.map((pattern) => (
                          <article key={pattern.code} className="rounded-lg border border-slate-200 bg-white p-3">
                            <div className="flex items-center justify-between gap-2">
                              <p className="text-sm font-semibold text-slate-800">{pattern.title}</p>
                              <span className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 text-[10px] text-slate-700">
                                {Math.round(pattern.confidence * 100)}%
                              </span>
                            </div>
                            <p className="mt-1 text-xs text-slate-600">{pattern.description}</p>
                            <p className="mt-1 font-mono text-[10px] text-slate-500">{pattern.evidence_codes.join(', ')}</p>
                          </article>
                        ))}
                      </div>
                    ) : (
                      <p className="mt-2 text-xs text-slate-500">No dominant attack pattern labels were inferred.</p>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Social Engineering Analysis</p>
                    <p className="mt-2 text-sm text-slate-700">
                      {String(latestScan.threat_report.social_engineering_analysis?.narrative_summary ?? 'Narrative analysis unavailable.')}
                    </p>
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-700">
                      <p>Coercion Score: {String(latestScan.threat_report.social_engineering_analysis?.coercion_score ?? 'N/A')}</p>
                      <p>Authority Impersonation: {String(latestScan.threat_report.social_engineering_analysis?.authority_impersonation ?? false)}</p>
                      <p>Fear Coercion: {String(latestScan.threat_report.social_engineering_analysis?.fear_coercion ?? false)}</p>
                      <p>Urgency Manipulation: {String(latestScan.threat_report.social_engineering_analysis?.urgency_manipulation ?? false)}</p>
                    </div>
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
              <h2 className="text-lg font-semibold text-slate-900">Evidence Chain</h2>
              {!latestScan?.threat_report ? (
                <p className="mt-3 text-sm text-slate-600">Evidence appears after the first scan.</p>
              ) : (
                <div className="mt-4 space-y-4">
                  {latestScan.threat_report.evidence.slice(0, 8).map((item) => (
                    <article key={item.code} className="rounded-xl border border-slate-200 bg-white p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${severityTone(item.severity)}`}>{item.severity}</span>
                        <span className="font-mono text-[11px] text-slate-500">{item.code}</span>
                      </div>
                      <p className="mt-2 text-sm font-medium text-slate-800">{item.title}</p>
                      <p className="mt-1 text-xs leading-5 text-slate-600">{item.description}</p>
                      <p className="mt-2 text-[11px] text-slate-600">
                        Source: {item.source} | Category: {item.category} | Impact: {item.score_impact}
                      </p>
                      <p className="mt-1 text-[11px] text-slate-600">
                        Confidence: {Math.round(item.confidence * 100)}% | Reliability: {Math.round(item.reliability * 100)}% | Escalation: +{item.escalation_contribution}
                      </p>
                      {analystMode && (
                        <div className="mt-2 rounded-lg border border-slate-200 bg-slate-50 p-2">
                          <p className="text-[11px] text-slate-700">Reasoning: {item.reasoning_context ?? 'N/A'}</p>
                          <p className="mt-1 text-[11px] text-slate-700">Source Module: {item.source_module ?? 'N/A'}</p>
                          {item.analyst_details && (
                            <pre className="mt-1 overflow-x-auto whitespace-pre-wrap text-[10px] text-slate-600">
                              {JSON.stringify(item.analyst_details, null, 2)}
                            </pre>
                          )}
                        </div>
                      )}
                    </article>
                  ))}
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Threat Intel Correlation</p>
                    {latestScan.technical_findings?.reputation_signals.length ? (
                      <div className="mt-2 space-y-2">
                        {latestScan.technical_findings.reputation_signals.slice(0, 4).map((signal) => (
                          <div key={signal.code} className="rounded-lg border border-slate-200 bg-white p-2">
                            <p className="text-xs font-medium text-slate-800">{signal.title}</p>
                            <p className="mt-1 text-[11px] text-slate-600">{signal.description}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="mt-2 text-xs text-slate-500">No provider flags in this scan.</p>
                    )}
                  </div>
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
              <h2 className="text-lg font-semibold text-slate-900">Risk Factor Breakdown</h2>
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
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Weighted Contributions</p>
                    <div className="mt-2 space-y-2">
                      {Object.entries(latestScan.threat_report.weighted_contributions).map(([key, value]) => (
                        <div key={key}>
                          <div className="flex items-center justify-between text-xs text-slate-600">
                            <span className="font-mono">{key}</span>
                            <span>{value.toFixed(1)} pts</span>
                          </div>
                          <div className="mt-1 h-2 w-full rounded-full bg-slate-200">
                            <div
                              className="h-2 rounded-full bg-sky-600"
                              style={{ width: `${Math.min(100, value)}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Severity Escalation Path</p>
                    <div className="mt-2 space-y-2">
                      {(latestScan.threat_report.timeline ?? [])
                        .filter((event) => event.stage === 'escalation' || event.stage === 'conclusion')
                        .map((event) => (
                          <div key={event.event_id} className="rounded-lg border border-slate-200 bg-white p-2">
                            <p className="text-xs font-medium text-slate-800">{event.title}</p>
                            <p className="mt-1 text-[11px] text-slate-600">
                              {new Date(event.timestamp).toLocaleTimeString()} | Score {event.score_after}
                            </p>
                          </div>
                        ))}
                    </div>
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
              <h2 className="text-lg font-semibold text-slate-900">Technical Findings</h2>
              {!latestScan?.technical_findings ? (
                <p className="mt-3 text-sm text-slate-600">Technical findings are available after running a scan.</p>
              ) : (
                <div className="mt-4 space-y-4">
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">
                    <p>Normalized URL: <span className="font-mono">{latestScan.technical_findings.normalized_url ?? 'N/A'}</span></p>
                    <p className="mt-1">Fetched HTML: {latestScan.technical_findings.fetched_html ? 'yes' : 'no'}</p>
                    <p className="mt-1">Redirect Chain: {latestScan.technical_findings.redirect_chain.length || 0}</p>
                  </div>

                  {analystMode && (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Calibration & Suppression Notes</p>
                      {Array.isArray((latestScan.technical_findings.metadata?.suppressed_detections as Array<unknown> | undefined)) &&
                      (latestScan.technical_findings.metadata?.suppressed_detections as Array<unknown>).length > 0 ? (
                        <div className="mt-2 space-y-2">
                          {(latestScan.technical_findings.metadata.suppressed_detections as Array<unknown>).map((item, idx) => (
                            <div key={`suppression-${idx}`} className="rounded-lg border border-slate-200 bg-white p-2">
                              <pre className="overflow-x-auto whitespace-pre-wrap text-[10px] text-slate-700">{JSON.stringify(item, null, 2)}</pre>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="mt-2 text-xs text-slate-500">No signal suppression adjustments recorded for this scan.</p>
                      )}
                      {Array.isArray((latestScan.technical_findings.metadata?.interaction_simulation as Record<string, unknown> | undefined)?.suppressed_interaction_indicators as Array<unknown> | undefined) &&
                      ((latestScan.technical_findings.metadata?.interaction_simulation as Record<string, unknown>).suppressed_interaction_indicators as Array<unknown>).length > 0 && (
                        <div className="mt-2 space-y-2">
                          {((latestScan.technical_findings.metadata?.interaction_simulation as Record<string, unknown>).suppressed_interaction_indicators as Array<unknown>).map((item, idx) => (
                            <div key={`interaction-suppression-${idx}`} className="rounded-lg border border-slate-200 bg-white p-2">
                              <pre className="overflow-x-auto whitespace-pre-wrap text-[10px] text-slate-700">{JSON.stringify(item, null, 2)}</pre>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Interaction Replay Timeline</p>
                    {!latestScan.technical_findings.interaction_events?.length ? (
                      <p className="mt-2 text-xs text-slate-500">No interaction replay events were captured in this scan.</p>
                    ) : (
                      <div className="mt-2 space-y-2">
                        {latestScan.technical_findings.interaction_events.map((event) => (
                          <article key={event.step_id} className="rounded-lg border border-slate-200 bg-white p-2">
                            <p className="text-xs font-medium text-slate-800">
                              {event.step_id} | {event.action} | {new Date(event.timestamp).toLocaleTimeString()}
                            </p>
                            <p className="mt-1 font-mono text-[10px] text-slate-600">{event.target}</p>
                            <p className="mt-1 text-[11px] text-slate-600">
                              {event.url_before} {' -> '} {event.url_after}
                            </p>
                            <p className={`mt-1 text-[11px] ${confidenceTone(event.confidence_after)}`}>
                              Confidence after step: {Math.round(event.confidence_after * 100)}%
                            </p>
                            {event.new_indicator_codes.length > 0 && (
                              <p className="mt-1 font-mono text-[10px] text-slate-500">{event.new_indicator_codes.join(', ')}</p>
                            )}
                          </article>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Behavioral Findings Panel</p>
                    <div className="mt-2 space-y-2">
                      {latestScan.technical_findings.dom_signals
                        .filter((signal) => signal.code.startsWith('interaction-') || signal.category.includes('behavior'))
                        .slice(0, 8)
                        .map((signal) => (
                          <div key={signal.code} className="rounded-lg border border-slate-200 bg-white p-2">
                            <p className="text-xs font-medium text-slate-800">{signal.title}</p>
                            <p className="mt-1 text-[11px] text-slate-600">{signal.description}</p>
                          </div>
                        ))}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Dynamic Redirect Visualization</p>
                    {!latestScan.technical_findings.interaction_events?.length ? (
                      <p className="mt-2 text-xs text-slate-500">No dynamic redirect path observed.</p>
                    ) : (
                      <div className="mt-2 space-y-2">
                        {latestScan.technical_findings.interaction_events
                          .filter((event) => event.redirect_triggered)
                          .map((event) => (
                            <div key={`${event.step_id}-redirect`} className="rounded-lg border border-slate-200 bg-white p-2">
                              <p className="text-xs font-medium text-slate-800">{event.step_id} redirect trigger</p>
                              <p className="mt-1 font-mono text-[10px] text-slate-600">{event.url_before}</p>
                              <p className="text-[10px] text-slate-500">to</p>
                              <p className="font-mono text-[10px] text-slate-600">{event.url_after}</p>
                            </div>
                          ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">DOM Mutation Viewer</p>
                    {!latestScan.technical_findings.interaction_events?.length ? (
                      <p className="mt-2 text-xs text-slate-500">No mutation replay data available.</p>
                    ) : (
                      <div className="mt-2 space-y-2">
                        {latestScan.technical_findings.interaction_events.map((event) => (
                          <div key={`${event.step_id}-mutation`} className="rounded-lg border border-slate-200 bg-white p-2">
                            <p className="text-xs font-medium text-slate-800">{event.step_id}</p>
                            <p className="mt-1 text-[11px] text-slate-600">
                              {Object.entries(event.dom_mutations)
                                .map(([key, value]) => `${key}:${typeof value === 'string' ? value : JSON.stringify(value)}`)
                                .join(' | ')}
                            </p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-slate-500">DOM Findings Viewer</p>
                    {!latestScan.technical_findings.dom_signals.length ? (
                      <p className="mt-2 text-xs text-slate-500">No DOM findings captured.</p>
                    ) : (
                      <div className="mt-2 space-y-2">
                        {latestScan.technical_findings.dom_signals.slice(0, 8).map((signal) => (
                          <div key={signal.code} className="rounded-lg border border-slate-200 bg-white p-2">
                            <p className="text-xs font-medium text-slate-800">{signal.title}</p>
                            <p className="mt-1 text-[11px] text-slate-600">{signal.description}</p>
                          </div>
                        ))}
                      </div>
                    )}
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
                              <p className="mt-1 text-[10px] text-slate-600">
                                Confidence {Math.round(signal.confidence * 100)}% | Reliability {Math.round(signal.reliability * 100)}% | Escalation +{signal.escalation_contribution}
                              </p>
                              {analystMode && (
                                <div className="mt-1 rounded border border-slate-200 bg-slate-50 p-1">
                                  <p className="text-[10px] text-slate-700">Context: {signal.reasoning_context ?? 'N/A'}</p>
                                  <p className="text-[10px] text-slate-700">Module: {signal.source_module ?? 'N/A'}</p>
                                  {signal.analyst_details && (
                                    <pre className="mt-1 overflow-x-auto whitespace-pre-wrap text-[10px] text-slate-600">
                                      {JSON.stringify(signal.analyst_details, null, 2)}
                                    </pre>
                                  )}
                                </div>
                              )}
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

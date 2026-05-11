import axios from 'axios'
import { useEffect, useMemo, useState } from 'react'
import {
  CollapsibleBlock,
  EvidenceCard,
  InvestigationPanel,
  KeyFindingList,
  ScoreBadge,
  SimpleIssue,
  SimpleTimelineEvent,
  TimelineFeed,
  VerdictBadge,
} from './components/investigation-ui'
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

type HistoryDeleteResponse = {
  deleted_count: number
  remaining: number
}

type PageKey = 'Home' | 'Threat Report' | 'History' | 'Technical Analysis'

const pages: PageKey[] = ['Home', 'Threat Report', 'History', 'Technical Analysis']

function formatTime(value: string | null): string {
  if (!value) return 'Unknown'
  return new Date(value).toLocaleString()
}

function riskBand(score: number): string {
  if (score >= 70) return 'High Risk'
  if (score >= 40) return 'Elevated Risk'
  if (score >= 20) return 'Low Risk'
  return 'Minimal Risk'
}

function severityWeight(severity: string): number {
  const normalized = severity.toLowerCase()
  if (normalized === 'critical') return 5
  if (normalized === 'high') return 4
  if (normalized === 'medium') return 3
  if (normalized === 'low') return 2
  return 1
}

function summaryLine(text: string, maxLength = 120): string {
  const clean = text.replace(/\s+/g, ' ').trim()
  if (clean.length <= maxLength) return clean
  return `${clean.slice(0, maxLength - 1)}…`
}

function classificationTone(classification: string): string {
  const normalized = classification.toLowerCase()
  if (normalized === 'critical' || normalized === 'dangerous') return 'tone-danger'
  if (normalized === 'suspicious') return 'tone-suspicious'
  if (normalized === 'safe') return 'tone-safe'
  return 'tone-neutral'
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

function EmptyState({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <div className="rounded-2xl border border-dashed border-slate-300 bg-white px-5 py-10 text-center">
      <h3 className="text-base font-semibold text-slate-900">{title}</h3>
      <p className="mt-2 text-sm text-slate-600">{description}</p>
    </div>
  )
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
  const [historySelection, setHistorySelection] = useState<number[]>([])
  const [historyActionBusy, setHistoryActionBusy] = useState(false)
  const [historyActionError, setHistoryActionError] = useState<string | null>(null)
  const [historyActionMessage, setHistoryActionMessage] = useState<string | null>(null)

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
      setHistorySelection([])
      setHistoryActionError(null)
      setHistoryActionMessage(null)
      return
    }
    void refreshWorkspace()
  }, [token])

  useEffect(() => {
    const ids = new Set(history.map((item) => item.id))
    setHistorySelection((previous) => previous.filter((id) => ids.has(id)))
  }, [history])

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
      const trimmedUrl = scanUrl.trim()
      if (!trimmedUrl) {
        setScanError('Please enter a URL before scanning.')
        return
      }
      const normalizedUrl = trimmedUrl.match(/^https?:\/\//i) ? trimmedUrl : `https://${trimmedUrl}`
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

      const response = await api.post<ScanResponse>(endpoint, body, { timeout: 90000 })
      setLatestScan(response.data)
      setLatestAnalyzedUrl(normalizedUrl)
      setLatestTextPayload(textPayload)
      setActivePage('Threat Report')
      await refreshWorkspace()
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.code === 'ECONNABORTED') {
          setScanError('Scan timed out after 90 seconds. The target may be slow or unreachable; retry in a moment.')
        } else if (!error.response) {
          setScanError(
            'Could not reach the API server. Confirm backend is running at http://localhost:8000 and CORS origin matches the dashboard URL.',
          )
        } else {
          const detail = extractApiErrorDetail(error.response?.data)
          setScanError(detail ?? 'Scan failed. Verify the URL and retry.')
        }
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
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = extractApiErrorDetail(error.response?.data)
        setDeepAnalysis(detail ?? 'Deep AI narrative is unavailable. Check OpenRouter configuration and retry.')
      } else {
        setDeepAnalysis('Deep AI narrative is unavailable. Check OpenRouter configuration and retry.')
      }
    } finally {
      setDeepBusy(false)
    }
  }

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesFilter = historyFilter === 'all' || item.classification === historyFilter
      const query = historyQuery.trim().toLowerCase()
      const matchesQuery =
        !query || (item.url ?? '').toLowerCase().includes(query) || item.explanation.toLowerCase().includes(query)
      return matchesFilter && matchesQuery
    })
  }, [history, historyFilter, historyQuery])

  const filteredHistoryIds = useMemo(() => filteredHistory.map((item) => item.id), [filteredHistory])

  const selectedVisibleCount = useMemo(
    () => filteredHistoryIds.filter((id) => historySelection.includes(id)).length,
    [filteredHistoryIds, historySelection],
  )

  const allVisibleSelected = filteredHistoryIds.length > 0 && selectedVisibleCount === filteredHistoryIds.length

  const classificationMap = useMemo(() => {
    return new Map((dashboardStats?.classification_breakdown ?? []).map((row) => [row.classification, row.count]))
  }, [dashboardStats])

  const keyFindings = useMemo(() => {
    if (!latestScan) return []
    const candidates: string[] = []
    const evidence = [...(latestScan.threat_report?.evidence ?? [])].sort((left, right) => {
      const sevDelta = severityWeight(right.severity) - severityWeight(left.severity)
      if (sevDelta !== 0) return sevDelta
      return (right.score_impact ?? 0) - (left.score_impact ?? 0)
    })
    evidence.slice(0, 5).forEach((item) => {
      candidates.push(summaryLine(`${item.title}: ${item.description}`))
    })
    if (!candidates.length) {
      latestScan.detected_issues.slice(0, 5).forEach((item) => {
        candidates.push(summaryLine(`${item.title}: ${item.description}`))
      })
    }
    if (latestScan.threat_report?.fetch_error) {
      candidates.push(summaryLine(`Collection note: ${latestScan.threat_report.fetch_error}`))
    }
    if (!candidates.length) {
      candidates.push('No significant phishing behavior indicators were detected in this investigation run.')
    }
    return Array.from(new Set(candidates)).slice(0, 5)
  }, [latestScan])

  const investigationIssues = useMemo((): SimpleIssue[] => {
    if (!latestScan) return []
    const reportEvidence = latestScan.threat_report?.evidence ?? []
    if (reportEvidence.length > 0) {
      return [...reportEvidence]
        .sort((left, right) => {
          const sevDelta = severityWeight(right.severity) - severityWeight(left.severity)
          if (sevDelta !== 0) return sevDelta
          return (right.score_impact ?? 0) - (left.score_impact ?? 0)
        })
        .slice(0, 10)
    }
    return latestScan.detected_issues.map((item) => ({
      ...item,
      confidence: latestScan.confidence,
      escalation_contribution: 0,
    }))
  }, [latestScan])

  const timelineEvents = useMemo((): SimpleTimelineEvent[] => {
    return (latestScan?.threat_report?.timeline ?? []).map((event) => ({
      event_id: event.event_id,
      timestamp: event.timestamp,
      title: event.title,
      detail: summaryLine(event.detail, 160),
      severity: event.severity,
      score_delta: event.score_delta,
      confidence_before: event.confidence_before,
      confidence_after: event.confidence_after,
    }))
  }, [latestScan])

  const behavioralFindings = useMemo(() => {
    return (latestScan?.technical_findings?.dom_signals ?? []).filter(
      (signal) => signal.code.startsWith('interaction-') || signal.category.includes('behavior') || signal.category.includes('credential'),
    )
  }, [latestScan])

  const attackPatterns = useMemo(() => {
    const reportPatterns = latestScan?.threat_report?.attack_patterns ?? []
    if (reportPatterns.length > 0) return reportPatterns
    return latestScan?.technical_findings?.attack_patterns ?? []
  }, [latestScan])

  const socialEngineeringEntries = useMemo(() => {
    const reportEntries = Object.entries(latestScan?.threat_report?.social_engineering_analysis ?? {})
    if (reportEntries.length > 0) return reportEntries
    return Object.entries(latestScan?.technical_findings?.social_engineering_analysis ?? {})
  }, [latestScan])

  const threatIntelSignals = useMemo(() => latestScan?.technical_findings?.reputation_signals ?? [], [latestScan])

  const recommendedActions = useMemo(() => {
    const actions = latestScan?.threat_report?.recommended_actions ?? []
    if (actions.length > 0) return actions.slice(0, 4)
    if (!latestScan) return []
    if (latestScan.classification === 'Safe') return ['No immediate action required. Continue passive monitoring.']
    return ['Escalate for analyst review.', 'Validate domain ownership and redirect behavior.', 'Block user interaction until verified.']
  }, [latestScan])

  const toggleHistorySelection = (scanId: number) => {
    setHistorySelection((previous) => (previous.includes(scanId) ? previous.filter((id) => id !== scanId) : [...previous, scanId]))
  }

  const toggleSelectAllVisible = () => {
    setHistorySelection((previous) => {
      if (allVisibleSelected) {
        return previous.filter((id) => !filteredHistoryIds.includes(id))
      }
      const merged = new Set(previous)
      filteredHistoryIds.forEach((id) => merged.add(id))
      return Array.from(merged)
    })
  }

  const deleteSelectedHistory = async () => {
    if (!historySelection.length) return
    const confirmed = window.confirm(
      `Delete ${historySelection.length} selected history entr${historySelection.length === 1 ? 'y' : 'ies'}?`,
    )
    if (!confirmed) return
    setHistoryActionBusy(true)
    setHistoryActionError(null)
    setHistoryActionMessage(null)
    try {
      const response = await api.post<HistoryDeleteResponse>('/api/v1/history/delete', {
        ids: historySelection,
        delete_all: false,
      })
      setHistoryActionMessage(`Deleted ${response.data.deleted_count} entr${response.data.deleted_count === 1 ? 'y' : 'ies'}.`)
      setHistorySelection([])
      await refreshWorkspace()
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = extractApiErrorDetail(error.response?.data)
        setHistoryActionError(detail ?? 'Failed to delete selected history items.')
      } else {
        setHistoryActionError('Failed to delete selected history items.')
      }
    } finally {
      setHistoryActionBusy(false)
    }
  }

  const deleteAllHistory = async () => {
    if (!history.length) return
    const confirmed = window.confirm('Delete all history results? This cannot be undone.')
    if (!confirmed) return
    setHistoryActionBusy(true)
    setHistoryActionError(null)
    setHistoryActionMessage(null)
    try {
      const response = await api.post<HistoryDeleteResponse>('/api/v1/history/delete', {
        ids: [],
        delete_all: true,
      })
      setHistoryActionMessage(`Deleted ${response.data.deleted_count} entr${response.data.deleted_count === 1 ? 'y' : 'ies'}.`)
      setHistorySelection([])
      await refreshWorkspace()
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = extractApiErrorDetail(error.response?.data)
        setHistoryActionError(detail ?? 'Failed to delete history.')
      } else {
        setHistoryActionError('Failed to delete history.')
      }
    } finally {
      setHistoryActionBusy(false)
    }
  }

  const deleteSingleHistory = async (scanId: number) => {
    const confirmed = window.confirm('Delete this history result?')
    if (!confirmed) return
    setHistoryActionBusy(true)
    setHistoryActionError(null)
    setHistoryActionMessage(null)
    try {
      await api.delete(`/api/v1/history/${scanId}`)
      setHistoryActionMessage('Deleted 1 entry.')
      setHistorySelection((previous) => previous.filter((id) => id !== scanId))
      await refreshWorkspace()
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = extractApiErrorDetail(error.response?.data)
        setHistoryActionError(detail ?? 'Failed to delete history entry.')
      } else {
        setHistoryActionError('Failed to delete history entry.')
      }
    } finally {
      setHistoryActionBusy(false)
    }
  }

  if (!token) {
    return (
      <main className="min-h-screen px-5 py-10">
        <div className="mx-auto grid max-w-6xl gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <section className="soft-panel rounded-3xl p-8">
            <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">PhishLens</p>
            <h1 className="mt-4 text-4xl font-semibold tracking-tight text-slate-900">
              Investigation-Grade Phishing Analysis
            </h1>
            <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-600">
              Structured URL and behavioral analysis designed for quick triage, clear evidence review, and explainable threat reasoning.
            </p>
            <div className="mt-8 grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Threat Overview</p>
                <p className="mt-2 text-sm text-slate-700">Risk verdict, confidence, and priority actions are surfaced first.</p>
              </div>
              <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Evidence Chain</p>
                <p className="mt-2 text-sm text-slate-700">Analyst details stay expandable so normal workflows remain focused.</p>
              </div>
            </div>
          </section>

          <section className="soft-panel rounded-3xl p-8">
            <div className="grid grid-cols-2 gap-2 rounded-xl bg-slate-100 p-1">
              <button
                onClick={() => setAuthMode('login')}
                className={`rounded-lg px-3 py-2 text-sm font-medium ${authMode === 'login' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'}`}
              >
                Login
              </button>
              <button
                onClick={() => setAuthMode('register')}
                className={`rounded-lg px-3 py-2 text-sm font-medium ${authMode === 'register' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'}`}
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
              className="mt-6 w-full rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60"
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
        <header className="soft-panel rounded-2xl p-5">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.26em] text-slate-500">PhishLens</p>
              <h1 className="mt-2 text-2xl font-semibold text-slate-900">Threat Reasoning Console</h1>
              <p className="mt-2 text-sm text-slate-600">Complex intelligence underneath. Simple investigation flow on top.</p>
            </div>
            <div className="grid gap-2 sm:grid-cols-3">
              <ScoreBadge label="Runtime" value={healthLoading ? 'Checking' : health ? 'Online' : 'Offline'} />
              <ScoreBadge label="Total Scans" value={`${dashboardStats?.total_scans ?? 0}`} />
              <ScoreBadge
                label="High Risk"
                value={`${(classificationMap.get('Dangerous') ?? 0) + (classificationMap.get('Critical') ?? 0)}`}
              />
            </div>
          </div>
        </header>

        <nav className="soft-panel flex flex-wrap items-center gap-2 rounded-2xl p-2">
          {pages.map((page) => (
            <button
              key={page}
              onClick={() => setActivePage(page)}
              className={`rounded-xl px-4 py-2 text-sm font-medium ${
                activePage === page ? 'bg-slate-900 text-white' : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              {page}
            </button>
          ))}
          <button
            onClick={() => setAnalystMode((value) => !value)}
            className={`rounded-xl border px-4 py-2 text-sm font-medium ${
              analystMode ? 'border-sky-300 bg-sky-50 text-sky-800' : 'border-slate-300 text-slate-700 hover:bg-slate-100'
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
          <section className="grid gap-5 xl:grid-cols-[1.25fr_0.75fr]">
            <InvestigationPanel
              title="Run Threat Analysis"
              subtitle="Submit a URL with optional page text/HTML to generate a structured investigation report."
            >
              <div className="space-y-3">
                <label className="block text-sm text-slate-700">
                  Target URL
                  <input
                    value={scanUrl}
                    onChange={(event) => setScanUrl(event.target.value)}
                    className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none focus:border-sky-500"
                    placeholder="https://target.example"
                  />
                </label>
                <label className="block text-sm text-slate-700">
                  Optional page text
                  <textarea
                    value={scanText}
                    onChange={(event) => setScanText(event.target.value)}
                    rows={4}
                    className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none focus:border-sky-500"
                    placeholder="Paste suspicious content for language signal analysis."
                  />
                </label>
                <label className="block text-sm text-slate-700">
                  Optional page HTML
                  <textarea
                    value={scanHtml}
                    onChange={(event) => setScanHtml(event.target.value)}
                    rows={4}
                    className="mt-2 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none focus:border-sky-500"
                    placeholder="<html>...</html>"
                  />
                </label>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={runScan}
                    disabled={scanBusy}
                    className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-60"
                  >
                    {scanBusy ? 'Analyzing…' : 'Analyze Threat'}
                  </button>
                  <button
                    onClick={() => {
                      setScanText('')
                      setScanHtml('')
                      setScanError(null)
                    }}
                    className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
                  >
                    Clear Inputs
                  </button>
                </div>
                {scanError && <p className="text-sm text-red-700">{scanError}</p>}
              </div>
            </InvestigationPanel>

            <div className="space-y-5">
              <InvestigationPanel title="Latest Snapshot" subtitle="Immediate triage view from the most recent scan.">
                {!latestScan ? (
                  <p className="text-sm text-slate-500">No scan has been run yet.</p>
                ) : (
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <VerdictBadge classification={latestScan.classification} />
                      <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${classificationTone(latestScan.classification)}`}>
                        {riskBand(latestScan.risk_score)}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <ScoreBadge label="Risk" value={`${latestScan.risk_score}/100`} />
                      <ScoreBadge label="Confidence" value={`${Math.round(latestScan.confidence * 100)}%`} />
                    </div>
                    <p className="text-sm text-slate-700">{summaryLine(latestScan.explanation.explanation, 180)}</p>
                  </div>
                )}
              </InvestigationPanel>

              <InvestigationPanel title="Recent Investigations" subtitle="Latest investigations for quick resume.">
                {!history.length ? (
                  <p className="text-sm text-slate-500">No history entries yet.</p>
                ) : (
                  <div className="space-y-2">
                    {history.slice(0, 5).map((item) => (
                      <article key={item.id} className="rounded-xl border border-slate-200 bg-white p-3">
                        <div className="flex items-center justify-between gap-2">
                          <p className="truncate text-sm font-medium text-slate-800">{item.url ?? 'Text-only scan'}</p>
                          <span className={`rounded-full border px-2 py-0.5 text-[11px] ${classificationTone(item.classification)}`}>
                            {item.classification}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-slate-500">{formatTime(item.created_at)} • {item.risk_score}/100</p>
                      </article>
                    ))}
                  </div>
                )}
              </InvestigationPanel>
            </div>
          </section>
        )}

        {activePage === 'Threat Report' && (
          <section className="space-y-5">
            {!latestScan ? (
              <EmptyState
                title="No investigation loaded"
                description="Run a scan from Home to populate the threat report and evidence chain."
              />
            ) : (
              <>
                <InvestigationPanel title="Threat Overview" subtitle="Primary verdict and investigation summary.">
                  <div className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
                    <div className="space-y-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <VerdictBadge classification={latestScan.classification} />
                        <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${classificationTone(latestScan.classification)}`}>
                          {riskBand(latestScan.risk_score)}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 sm:max-w-sm">
                        <ScoreBadge label="Risk Score" value={`${latestScan.risk_score}/100`} />
                        <ScoreBadge label="Confidence" value={`${Math.round(latestScan.confidence * 100)}%`} />
                      </div>
                      <p className="text-sm text-slate-700">
                        {latestScan.threat_report?.executive_summary
                          ? summaryLine(latestScan.threat_report.executive_summary, 300)
                          : summaryLine(latestScan.explanation.explanation, 300)}
                      </p>
                      <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-700">
                        Target: <span className="font-mono">{latestAnalyzedUrl ?? latestScan.technical_findings?.normalized_url ?? 'N/A'}</span>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <h4 className="text-sm font-semibold text-slate-900">Recommended Action</h4>
                      <ul className="space-y-2">
                        {recommendedActions.map((action, index) => (
                          <li key={`${action}-${index}`} className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700">
                            {action}
                          </li>
                        ))}
                      </ul>
                      <button
                        onClick={runDeepAnalysis}
                        disabled={deepBusy}
                        className="w-full rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-60"
                      >
                        {deepBusy ? 'Generating AI Narrative…' : 'Generate AI Narrative'}
                      </button>
                      {deepAnalysis && (
                        <div className="rounded-xl border border-sky-200 bg-sky-50 p-3 text-sm text-slate-700">
                          {deepAnalysis}
                        </div>
                      )}
                    </div>
                  </div>
                </InvestigationPanel>

                <div className="grid gap-5 xl:grid-cols-2">
                  <InvestigationPanel title="Why This Was Flagged" subtitle="Most important findings only.">
                    <KeyFindingList items={keyFindings} />
                  </InvestigationPanel>
                  <InvestigationPanel title="Investigation Timeline" subtitle="Event feed with score and confidence change.">
                    <TimelineFeed events={timelineEvents} />
                  </InvestigationPanel>
                </div>

                <InvestigationPanel title="Evidence Summary" subtitle="Prioritized evidence cards with severity and confidence.">
                  {!investigationIssues.length ? (
                    <p className="text-sm text-slate-500">No evidence records were generated for this run.</p>
                  ) : (
                    <div className="grid gap-3 md:grid-cols-2">
                      {investigationIssues.map((issue) => (
                        <EvidenceCard key={`${issue.code}-${issue.title}`} issue={issue} analystMode={analystMode} />
                      ))}
                    </div>
                  )}
                </InvestigationPanel>

                <div className="grid gap-5 xl:grid-cols-3">
                  <InvestigationPanel title="Behavioral Findings" subtitle="Interaction and DOM-driven signals.">
                    {!behavioralFindings.length ? (
                      <p className="text-sm text-slate-500">No behavioral phishing indicators were observed.</p>
                    ) : (
                      <div className="space-y-2">
                        {behavioralFindings.slice(0, 8).map((signal) => (
                          <article key={signal.code} className="rounded-xl border border-slate-200 bg-white p-3">
                            <p className="text-sm font-semibold text-slate-900">{signal.title}</p>
                            <p className="mt-1 text-sm text-slate-700">{summaryLine(signal.description, 130)}</p>
                          </article>
                        ))}
                      </div>
                    )}
                  </InvestigationPanel>

                  <InvestigationPanel title="Attack Patterns" subtitle="Mapped adversary behavior patterns.">
                    {!attackPatterns.length ? (
                      <p className="text-sm text-slate-500">No high-confidence attack patterns mapped.</p>
                    ) : (
                      <div className="space-y-2">
                        {attackPatterns.map((pattern) => (
                          <article key={pattern.code} className="rounded-xl border border-slate-200 bg-white p-3">
                            <p className="text-sm font-semibold text-slate-900">{pattern.title}</p>
                            <p className="mt-1 text-sm text-slate-700">{summaryLine(pattern.description, 120)}</p>
                            <p className="mt-1 text-xs text-slate-500">Confidence {Math.round(pattern.confidence * 100)}%</p>
                          </article>
                        ))}
                      </div>
                    )}
                  </InvestigationPanel>

                  <InvestigationPanel title="Threat Intelligence" subtitle="External reputation and provider correlation.">
                    {!threatIntelSignals.length ? (
                      <p className="text-sm text-slate-500">No external provider alerts in this scan.</p>
                    ) : (
                      <div className="space-y-2">
                        {threatIntelSignals.map((signal) => (
                          <article key={`${signal.code}-${signal.title}`} className="rounded-xl border border-slate-200 bg-white p-3">
                            <p className="text-sm font-semibold text-slate-900">{signal.title}</p>
                            <p className="mt-1 text-sm text-slate-700">{summaryLine(signal.description, 120)}</p>
                          </article>
                        ))}
                      </div>
                    )}
                  </InvestigationPanel>
                </div>

                <InvestigationPanel title="Social Engineering Analysis" subtitle="Language and persuasion pattern interpretation.">
                  {!socialEngineeringEntries.length ? (
                    <p className="text-sm text-slate-500">No social engineering narrative details were produced.</p>
                  ) : (
                    <div className="grid gap-2 md:grid-cols-2">
                      {socialEngineeringEntries.map(([key, value]) => (
                        <article key={key} className="rounded-xl border border-slate-200 bg-white p-3">
                          <p className="text-xs uppercase tracking-[0.14em] text-slate-500">{key.replace(/_/g, ' ')}</p>
                          <p className="mt-1 text-sm text-slate-700">
                            {typeof value === 'string' ? value : summaryLine(JSON.stringify(value), 140)}
                          </p>
                        </article>
                      ))}
                    </div>
                  )}
                </InvestigationPanel>

                {analystMode && (
                  <InvestigationPanel title="Analyst Details" subtitle="Expanded technical context and raw structures.">
                    <div className="space-y-3">
                      <CollapsibleBlock title="Reasoning Chain">
                        <ul className="space-y-2">
                          {(latestScan.threat_report?.reasoning_chain ?? []).map((line, index) => (
                            <li key={`${line}-${index}`} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700">
                              {line}
                            </li>
                          ))}
                        </ul>
                      </CollapsibleBlock>
                      <CollapsibleBlock title="Score Breakdown (raw)">
                        <pre className="overflow-x-auto whitespace-pre-wrap text-[11px] text-slate-700">
                          {JSON.stringify(
                            {
                              component_scores: latestScan.threat_report?.component_scores ?? {},
                              weighted_contributions: latestScan.threat_report?.weighted_contributions ?? {},
                              source_breakdown: latestScan.source_breakdown ?? {},
                            },
                            null,
                            2,
                          )}
                        </pre>
                      </CollapsibleBlock>
                      <CollapsibleBlock title="Technical Metadata">
                        <pre className="overflow-x-auto whitespace-pre-wrap text-[11px] text-slate-700">
                          {JSON.stringify(latestScan.technical_findings?.metadata ?? {}, null, 2)}
                        </pre>
                      </CollapsibleBlock>
                    </div>
                  </InvestigationPanel>
                )}
              </>
            )}
          </section>
        )}

        {activePage === 'History' && (
          <section className="soft-panel rounded-2xl p-5">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-slate-900">Investigation History</h2>
                <p className="text-sm text-slate-600">Review previous investigations and filter by risk classification.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => void refreshWorkspace()}
                  disabled={historyActionBusy}
                  className="rounded-xl border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-60"
                >
                  Refresh
                </button>
                <button
                  onClick={() => void deleteSelectedHistory()}
                  disabled={historyActionBusy || historySelection.length === 0}
                  className="rounded-xl border border-red-300 bg-red-50 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-100 disabled:opacity-60"
                >
                  Delete selected ({historySelection.length})
                </button>
                <button
                  onClick={() => void deleteAllHistory()}
                  disabled={historyActionBusy || history.length === 0}
                  className="rounded-xl border border-red-300 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50 disabled:opacity-60"
                >
                  Delete all
                </button>
              </div>
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

            {historyActionMessage && <p className="mt-3 text-sm text-emerald-700">{historyActionMessage}</p>}
            {historyActionError && <p className="mt-3 text-sm text-red-700">{historyActionError}</p>}

            <div className="mt-4 overflow-x-auto rounded-xl border border-slate-200">
              <table className="min-w-full bg-white text-sm">
                <thead className="bg-slate-100 text-slate-700">
                  <tr>
                    <th className="px-3 py-2 text-left">
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        onChange={toggleSelectAllVisible}
                        aria-label="Select all visible history rows"
                      />
                    </th>
                    <th className="px-3 py-2 text-left">Time</th>
                    <th className="px-3 py-2 text-left">Target</th>
                    <th className="px-3 py-2 text-left">Type</th>
                    <th className="px-3 py-2 text-left">Risk</th>
                    <th className="px-3 py-2 text-left">Classification</th>
                    <th className="px-3 py-2 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.length === 0 ? (
                    <tr>
                      <td className="px-3 py-4 text-slate-500" colSpan={7}>
                        No investigations match the current filter.
                      </td>
                    </tr>
                  ) : (
                    filteredHistory.map((item) => (
                      <tr key={item.id} className="border-t border-slate-200">
                        <td className="px-3 py-2 text-slate-600">
                          <input
                            type="checkbox"
                            checked={historySelection.includes(item.id)}
                            onChange={() => toggleHistorySelection(item.id)}
                            aria-label={`Select history row ${item.id}`}
                          />
                        </td>
                        <td className="px-3 py-2 text-slate-600">{formatTime(item.created_at)}</td>
                        <td className="max-w-[420px] truncate px-3 py-2 text-slate-800">{item.url ?? 'Text-only scan'}</td>
                        <td className="px-3 py-2 text-slate-600">{item.scan_type}</td>
                        <td className="px-3 py-2 text-slate-800">{item.risk_score}/100</td>
                        <td className="px-3 py-2">
                          <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${classificationTone(item.classification)}`}>
                            {item.classification}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <button
                            onClick={() => void deleteSingleHistory(item.id)}
                            disabled={historyActionBusy}
                            className="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-700 hover:bg-red-50 disabled:opacity-60"
                          >
                            Delete
                          </button>
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
          <section className="space-y-5">
            {!latestScan?.technical_findings ? (
              <EmptyState
                title="No technical analysis loaded"
                description="Run a scan to inspect URL, DOM, content, model, and interaction evidence groups."
              />
            ) : (
              <>
                <div className="grid gap-5 xl:grid-cols-3">
                  <InvestigationPanel title="Technical Snapshot">
                    <div className="space-y-2 text-sm text-slate-700">
                      <p>
                        Normalized URL: <span className="font-mono text-xs">{latestScan.technical_findings.normalized_url ?? 'N/A'}</span>
                      </p>
                      <p>Fetched HTML: {latestScan.technical_findings.fetched_html ? 'Yes' : 'No'}</p>
                      <p>Redirect chain length: {latestScan.technical_findings.redirect_chain.length}</p>
                    </div>
                  </InvestigationPanel>
                  <InvestigationPanel title="Signal Counts">
                    <div className="grid grid-cols-2 gap-2">
                      <ScoreBadge label="URL" value={`${latestScan.technical_findings.url_signals.length}`} />
                      <ScoreBadge label="DOM" value={`${latestScan.technical_findings.dom_signals.length}`} />
                      <ScoreBadge label="Content" value={`${latestScan.technical_findings.content_signals.length}`} />
                      <ScoreBadge label="Reputation" value={`${latestScan.technical_findings.reputation_signals.length}`} />
                    </div>
                  </InvestigationPanel>
                  <InvestigationPanel title="Interaction Replay">
                    <p className="text-sm text-slate-700">{latestScan.technical_findings.interaction_events.length} captured steps</p>
                  </InvestigationPanel>
                </div>

                <InvestigationPanel title="Technical Findings" subtitle="Grouped indicators with progressive disclosure.">
                  <div className="space-y-3">
                    {(
                      [
                        { label: 'URL Signals', signals: latestScan.technical_findings.url_signals },
                        { label: 'DOM Signals', signals: latestScan.technical_findings.dom_signals },
                        { label: 'Content Signals', signals: latestScan.technical_findings.content_signals },
                        { label: 'Reputation Signals', signals: latestScan.technical_findings.reputation_signals },
                        { label: 'Model Signals', signals: latestScan.technical_findings.model_signals },
                      ] as Array<{ label: string; signals: EvidenceItem[] }>
                    ).map((group) => (
                      <CollapsibleBlock key={group.label} title={`${group.label} (${group.signals.length})`}>
                        {!group.signals.length ? (
                          <p className="text-sm text-slate-500">No indicators in this category.</p>
                        ) : (
                          <div className="grid gap-2 md:grid-cols-2">
                            {group.signals.slice(0, 12).map((signal) => (
                              <EvidenceCard key={`${group.label}-${signal.code}-${signal.title}`} issue={signal} analystMode={analystMode} />
                            ))}
                          </div>
                        )}
                      </CollapsibleBlock>
                    ))}
                  </div>
                </InvestigationPanel>

                <InvestigationPanel title="Investigation Timeline (Interaction)" subtitle="Replay events from controlled interaction simulation.">
                  {!latestScan.technical_findings.interaction_events.length ? (
                    <p className="text-sm text-slate-500">No interaction replay events were captured in this scan.</p>
                  ) : (
                    <div className="space-y-2">
                      {latestScan.technical_findings.interaction_events.map((event) => (
                        <article key={event.step_id} className="rounded-xl border border-slate-200 bg-white p-3">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="text-sm font-semibold text-slate-900">{event.step_id} • {event.action}</p>
                            <span className="text-xs text-slate-500">{new Date(event.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="mt-1 font-mono text-[11px] text-slate-600">{event.target}</p>
                          <p className="mt-1 text-xs text-slate-600">
                            {event.url_before} → {event.url_after}
                          </p>
                          {event.new_indicator_codes.length > 0 && (
                            <p className="mt-1 text-xs text-slate-600">Indicators: {event.new_indicator_codes.join(', ')}</p>
                          )}
                          {analystMode && (
                            <details className="mt-2 rounded-lg border border-slate-200 bg-slate-50 p-2">
                              <summary className="cursor-pointer text-xs font-medium text-slate-700">DOM mutations</summary>
                              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap text-[11px] text-slate-600">
                                {JSON.stringify(event.dom_mutations, null, 2)}
                              </pre>
                            </details>
                          )}
                        </article>
                      ))}
                    </div>
                  )}
                </InvestigationPanel>
              </>
            )}
          </section>
        )}
      </div>
    </main>
  )
}

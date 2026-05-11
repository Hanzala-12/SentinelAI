import { ReactNode } from 'react'

export type SimpleIssue = {
  code: string
  title: string
  description: string
  severity: string
  confidence?: number
  escalation_contribution?: number
  source?: string
  category?: string
  analyst_details?: Record<string, unknown>
}

export type SimpleTimelineEvent = {
  event_id: string
  timestamp: string
  title: string
  detail: string
  severity: string
  score_delta: number
  confidence_before: number
  confidence_after: number
}

function toTone(value: string): string {
  const normalized = value.toLowerCase()
  if (normalized === 'critical' || normalized === 'dangerous' || normalized === 'high') return 'tone-danger'
  if (normalized === 'suspicious' || normalized === 'medium') return 'tone-suspicious'
  if (normalized === 'safe' || normalized === 'low') return 'tone-safe'
  return 'tone-neutral'
}

export function InvestigationPanel({
  title,
  subtitle,
  actions,
  children,
  className = '',
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`soft-panel rounded-2xl p-5 ${className}`}>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-900">{title}</h3>
          {subtitle && <p className="mt-1 text-sm text-slate-600">{subtitle}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}

export function VerdictBadge({ classification }: { classification: string }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold ${toTone(classification)}`}>
      {classification}
    </span>
  )
}

export function ScoreBadge({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2">
      <p className="text-[11px] uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-slate-900">{value}</p>
    </div>
  )
}

export function KeyFindingList({ items }: { items: string[] }) {
  return (
    <ul className="space-y-2">
      {items.map((item, index) => (
        <li key={`${item}-${index}`} className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700">
          {item}
        </li>
      ))}
    </ul>
  )
}

export function EvidenceCard({ issue, analystMode }: { issue: SimpleIssue; analystMode: boolean }) {
  const confidence = typeof issue.confidence === 'number' ? Math.round(issue.confidence * 100) : null
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h4 className="text-sm font-semibold text-slate-900">{issue.title}</h4>
          <p className="mt-1 text-xs text-slate-500">{issue.code}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${toTone(issue.severity)}`}>{issue.severity}</span>
          {confidence !== null && <span className="text-xs font-medium text-slate-600">{confidence}%</span>}
        </div>
      </div>
      <p className="mt-2 text-sm text-slate-700">{issue.description}</p>
      <p className="mt-2 text-xs text-slate-500">
        Why it matters: contributes to escalation scoring
        {typeof issue.escalation_contribution === 'number' ? ` (+${issue.escalation_contribution})` : ''}.
      </p>
      {analystMode && issue.analyst_details && (
        <details className="mt-2 rounded-lg border border-slate-200 bg-slate-50 p-2">
          <summary className="cursor-pointer text-xs font-medium text-slate-700">Analyst details</summary>
          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap text-[11px] text-slate-600">
            {JSON.stringify(issue.analyst_details, null, 2)}
          </pre>
        </details>
      )}
    </article>
  )
}

export function TimelineFeed({ events }: { events: SimpleTimelineEvent[] }) {
  if (!events.length) {
    return <p className="text-sm text-slate-500">Timeline is unavailable for this investigation.</p>
  }

  return (
    <div className="space-y-2">
      {events.map((event) => {
        const confidenceDelta = Math.round((event.confidence_after - event.confidence_before) * 100)
        return (
          <article key={event.event_id} className="rounded-xl border border-slate-200 bg-white p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className={`inline-block h-2.5 w-2.5 rounded-full ${toTone(event.severity)}`} />
                <h4 className="text-sm font-semibold text-slate-900">{event.title}</h4>
              </div>
              <span className="text-xs text-slate-500">{new Date(event.timestamp).toLocaleTimeString()}</span>
            </div>
            <p className="mt-1 text-sm text-slate-700">{event.detail}</p>
            <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-600">
              <span className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5">Score {event.score_delta >= 0 ? '+' : ''}{event.score_delta}</span>
              <span className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5">Confidence {confidenceDelta >= 0 ? '+' : ''}{confidenceDelta}%</span>
            </div>
          </article>
        )
      })}
    </div>
  )
}

export function CollapsibleBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="rounded-xl border border-slate-200 bg-slate-50 p-3">
      <summary className="cursor-pointer text-sm font-medium text-slate-800">{title}</summary>
      <div className="mt-3">{children}</div>
    </details>
  )
}

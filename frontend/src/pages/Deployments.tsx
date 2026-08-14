import { useCallback, useEffect, useState } from 'react'
import { apiGet, apiPost } from '../api/client'
import { useData } from './SimplePages'

interface JobRow {
  id: string; status: string; strategy: string; requestedBy: string; approvedBy: string | null
  certificate: string; targetCount: number; createdAt: string; completedAt: string | null
}
interface JobDetail {
  id: string; status: string; certificate: string
  targets: {
    id: string; status: string; target: string; adapter: string; store: string
    steps: { step: string; status: string; safeLog: string | null; completedAt: string | null }[]
  }[]
}
interface JobEvent {
  at: string; kind: string; source: string | null; name: string; result: string | null; detail: string | null
}

interface ManifestTarget { target: string; adapter: string; environment: string | null; store: string }
interface ManifestResolution {
  ok: boolean; errors: string[]; warnings: string[]
  certificate: string | null; thumbprint: string | null; strategy: string
  maxConcurrency: number; approvalRequired: boolean; targets: ManifestTarget[]
}
interface ManifestPlan {
  strategy: string; maxConcurrency: number; approvalRequired: boolean
  windowRequired: boolean; windowOpen: boolean
  targets: { target: string; adapter: string; runnerStatus: string; currentDaysLeft: number | null }[]
  warnings: string[]; blockers: string[]
}

const SAMPLE_MANIFEST = `apiVersion: remotessl/v1
kind: CertificateDeployment
metadata:
  name: web-tier-renewal
spec:
  certificate:
    commonName: www.example.com
    version: latest
  targets:
    - environment: production
      adapter: nginx
  strategy:
    type: wave
    maxConcurrency: 2
  verification:
    remoteTlsVerify: true
    host: www.example.com
    port: 443
`

/**
 * Declarative manifest import (§38). The manifest is meant to live in the same repository as the
 * service it renews, so this screen is deliberately a review step rather than an editor: paste the
 * file, see exactly which targets it resolves to and what would block it, then apply.
 */
function ManifestPanel({ onApplied }: { onApplied: () => void }) {
  const [text, setText] = useState(SAMPLE_MANIFEST)
  const [resolution, setResolution] = useState<ManifestResolution | null>(null)
  const [plan, setPlan] = useState<ManifestPlan | null>(null)
  const [errors, setErrors] = useState<string[]>([])
  const [message, setMessage] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function dryRun() {
    setBusy(true); setMessage(null); setErrors([]); setResolution(null); setPlan(null)
    try {
      const res = await apiPost('/api/v1/deployments/manifest/plan', { manifest: text })
      const body = await res.json()
      if (!res.ok || body.ok === false) {
        setErrors(body.errors ?? [body.title ?? `Dry run failed (${res.status})`])
        setResolution(body.resolution ?? null)
        return
      }
      setResolution(body.resolution); setPlan(body.plan)
    } finally { setBusy(false) }
  }

  async function apply() {
    if (!window.confirm('Apply this manifest? A deployment job is created for every target it resolves to.')) return
    setBusy(true); setMessage(null); setErrors([])
    try {
      const res = await apiPost('/api/v1/deployments/manifest/apply', { manifest: text, requestedBy: 'ui' })
      const body = await res.json()
      if (!res.ok || body.ok === false) {
        setErrors(body.errors ?? [body.title ?? `Apply failed (${res.status})`])
        return
      }
      setMessage(`Job ${body.jobId} created (${body.status}) for ${body.targets.length} target(s).`)
      onApplied()
    } finally { setBusy(false) }
  }

  // Applying is only offered once a dry run has actually resolved the file, so nobody deploys
  // a manifest whose blast radius they have not seen.
  const applicable = resolution?.ok === true && (plan?.blockers.length ?? 1) === 0

  return (
    <div className="detail-panel">
      <h2>Apply a manifest</h2>
      <p className="muted small">
        Paste a <code>remotessl/v1 CertificateDeployment</code> manifest. Dry run resolves the certificate and
        the target selectors and shows the impact; nothing is created until you apply. Applying goes through
        the same governance, approval and adapter checks as a deployment started from the UI.
      </p>
      <textarea
        className="manifest-editor"
        rows={18}
        spellCheck={false}
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div className="actions">
        <button onClick={dryRun} disabled={busy}>Dry run</button>
        <button onClick={apply} disabled={busy || !applicable}>Apply</button>
      </div>

      {message && <p className="small ok">{message}</p>}
      {errors.length > 0 && (
        <ul className="step-list">
          {errors.map((e, i) => <li key={i} className="bad">{e}</li>)}
        </ul>
      )}
      {(resolution?.warnings ?? []).map((w, i) => <p key={i} className="warn small">{w}</p>)}

      {resolution?.ok && (
        <>
          <p className="small">
            <strong>{resolution.certificate}</strong>{' '}
            <span className="muted">{resolution.thumbprint?.slice(0, 16)}…</span> — strategy{' '}
            <strong>{resolution.strategy}</strong>
            {resolution.maxConcurrency > 0 && <> (max {resolution.maxConcurrency} at a time)</>}
            {resolution.approvalRequired && <> — approval required</>}
          </p>
          <table className="data-table">
            <thead><tr><th>Target</th><th>Adapter</th><th>Environment</th><th>Store</th></tr></thead>
            <tbody>
              {resolution.targets.map((t, i) => (
                <tr key={i}>
                  <td>{t.target}</td><td className="small">{t.adapter}</td>
                  <td className="small">{t.environment ?? '—'}</td>
                  <td className="small muted">{t.store}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {plan && plan.blockers.length > 0 && (
        <>
          <h3>Blockers</h3>
          <ul className="step-list">
            {plan.blockers.map((b, i) => <li key={i} className="bad">{b}</li>)}
          </ul>
        </>
      )}
      {plan && plan.warnings.length > 0 && (
        <ul className="step-list">
          {plan.warnings.map((w, i) => <li key={i} className="warn">{w}</li>)}
        </ul>
      )}
    </div>
  )
}

function statusClass(s: string) {
  if (['Succeeded'].includes(s)) return 'ok'
  if (['Running', 'Pending', 'PendingApproval', 'Approved', 'Scheduled'].includes(s)) return 'warn'
  return 'bad'
}

export default function Deployments() {
  const [jobs, reloadJobs] = useData<JobRow[]>('/api/v1/deployments', 10000)
  const [detail, setDetail] = useState<JobDetail | null>(null)
  const [events, setEvents] = useState<JobEvent[]>([])
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [showManifest, setShowManifest] = useState(false)

  const load = useCallback((id: string) => {
    apiGet<JobDetail>(`/api/v1/deployments/${id}`).then(setDetail).catch(() => {})
    apiGet<{ events: JobEvent[] }>(`/api/v1/deployments/${id}/events`)
      .then((d) => setEvents(d.events ?? [])).catch(() => setEvents([]))
  }, [])

  // A running job changes underneath us; keep the open panel current.
  useEffect(() => {
    if (!detail || detail.status !== 'Running') return
    const timer = setInterval(() => load(detail.id), 5000)
    return () => clearInterval(timer)
  }, [detail, load])

  /** §21.4: release the next wave of a canary/manual deployment. */
  async function continueJob(id: string) {
    setBusy(true); setMessage(null)
    try {
      const res = await apiPost(`/api/v1/deployments/${id}/continue`, { requestedBy: 'ui' })
      const body = await res.json()
      setMessage(res.ok ? `Dispatched ${body.dispatched} target(s).` : body.title ?? `Continue failed (${res.status})`)
      load(id); reloadJobs()
    } finally { setBusy(false) }
  }

  /** FR-018: put the previous certificate version back on the targets this job changed. */
  async function rollback(id: string) {
    if (!window.confirm('Roll back this job? The previous certificate version is redeployed to its targets.')) return
    setBusy(true); setMessage(null)
    try {
      const res = await apiPost(`/api/v1/deployments/${id}/rollback`, { requestedBy: 'ui' })
      const body = await res.json()
      setMessage(res.ok
        ? `Rollback started: ${(body.rollbackJobs ?? []).length} job(s).`
          + ((body.skipped ?? []).length ? ` Skipped: ${body.skipped.join('; ')}` : '')
        : body.title ?? `Rollback failed (${res.status})`)
      load(id); reloadJobs()
    } finally { setBusy(false) }
  }

  /** §21.3: a job that never started keeps its bindings locked until it is cancelled. */
  async function cancel(id: string) {
    if (!window.confirm('Cancel this job? Its bindings are released for other deployments.')) return
    setBusy(true); setMessage(null)
    try {
      const res = await apiPost(`/api/v1/deployments/${id}/cancel`, { requestedBy: 'ui' })
      setMessage(res.ok ? 'Job cancelled.' : (await res.json()).title ?? `Cancel failed (${res.status})`)
      load(id); reloadJobs()
    } finally { setBusy(false) }
  }

  const cancellable = detail && ['PendingApproval', 'Approved', 'Scheduled', 'Pending'].includes(detail.status)
  const awaitingContinue = detail?.status === 'Running'
    && detail.targets.some((t) => t.status === 'Pending')
    && !detail.targets.some((t) => t.status === 'Running')
  const rollbackable = detail && ['Succeeded', 'PartiallyFailed', 'Failed'].includes(detail.status)

  return (
    <div className="page">
      <h1>Deployments</h1>
      <p className="muted small">
        Create deployments from the Certificates screen or the API; jobs run transactionally with automatic
        rollback. Open a job to follow its steps, continue a paused canary wave, or roll it back manually.
      </p>
      <div className="actions">
        <button onClick={() => setShowManifest((v) => !v)}>
          {showManifest ? 'Hide manifest' : 'Apply a manifest'}
        </button>
      </div>
      {showManifest && <ManifestPanel onApplied={reloadJobs} />}
      <table className="data-table">
        <thead><tr><th>Certificate</th><th>Status</th><th>Strategy</th><th>Targets</th><th>Requested by</th><th>Created</th><th>Completed</th></tr></thead>
        <tbody>
          {(jobs ?? []).map((j) => (
            <tr key={j.id} className="clickable" onClick={() => { setMessage(null); load(j.id) }}>
              <td>{j.certificate}</td>
              <td><span className={statusClass(j.status)}>{j.status}</span></td>
              <td className="small">{j.strategy}</td>
              <td>{j.targetCount}</td><td>{j.requestedBy}</td>
              <td className="small muted">{new Date(j.createdAt).toLocaleString()}</td>
              <td className="small muted">{j.completedAt ? new Date(j.completedAt).toLocaleString() : '—'}</td>
            </tr>
          ))}
          {(jobs ?? []).length === 0 && <tr><td colSpan={7} className="muted">No deployment jobs yet — this list fills up once you deploy. To create one: open a certificate on the Certificates screen and use its Deploy section (needs a target with a store + binding), or let a renewal policy auto-deploy.</td></tr>}
        </tbody>
      </table>

      {detail && (
        <div className="detail-panel">
          <div className="detail-header">
            <h2>{detail.certificate} — <span className={statusClass(detail.status)}>{detail.status}</span></h2>
            <div className="actions">
              {awaitingContinue && (
                <button onClick={() => continueJob(detail.id)} disabled={busy}>Continue next wave</button>
              )}
              {cancellable && (
                <button onClick={() => cancel(detail.id)} disabled={busy}>Cancel job</button>
              )}
              {rollbackable && (
                <button className="danger" onClick={() => rollback(detail.id)} disabled={busy}>Roll back</button>
              )}
              <button onClick={() => { setDetail(null); setEvents([]); setMessage(null) }}>Close</button>
            </div>
          </div>
          {message && <p className="small">{message}</p>}
          {awaitingContinue && (
            <p className="warn small">
              This deployment pauses between waves. Verify the targets that already ran, then continue.
            </p>
          )}

          {detail.targets.map((t) => (
            <div key={t.id} className="version-card">
              <strong>{t.target}</strong> ({t.adapter}, {t.store}) — <span className={statusClass(t.status)}>{t.status}</span>
              <ul className="step-list">
                {t.steps.map((s, i) => (
                  <li key={i}>
                    <span className={s.status === 'Succeeded' ? 'ok' : 'bad'}>[{s.status === 'Succeeded' ? 'OK' : 'FAIL'}]</span>{' '}
                    {s.step} <span className="muted small">— {s.safeLog}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}

          <h3>Progress timeline</h3>
          <table className="data-table">
            <thead><tr><th>Time</th><th>Kind</th><th>Source</th><th>Event</th><th>Result</th></tr></thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i}>
                  <td className="small muted">{new Date(e.at).toLocaleString()}</td>
                  <td className="small">{e.kind}</td>
                  <td className="small">{e.source ?? '—'}</td>
                  <td className="small">
                    {e.name}
                    {e.detail && <div className="muted" style={{ wordBreak: 'break-all' }}>{e.detail}</div>}
                  </td>
                  <td className="small">
                    <span className={e.result && /FAIL|Failed/.test(e.result) ? 'bad' : 'ok'}>{e.result ?? '—'}</span>
                  </td>
                </tr>
              ))}
              {events.length === 0 && <tr><td colSpan={5} className="muted">No events recorded for this job.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

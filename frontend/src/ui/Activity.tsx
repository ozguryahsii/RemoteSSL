import { useNavigate, useParams } from 'react-router-dom'
import { apiPost } from '../api/client'
import { Page, Card, Loading, Problem, Empty, useApi, Pill, shortDateTime } from './kit'
import { useState } from 'react'

/**
 * What RemoteSSL has done to the estate: every installation, what it touched, and — when one
 * went wrong — which step failed and whether the old certificate was put back.
 *
 * A deployment is transactional (design doc §21.1), so the interesting thing is never "failed"
 * on its own; it is the step it failed at and what happened next.
 */

interface JobRow {
  id: string
  status: string
  strategy: string
  certificate: string
  requestedBy: string | null
  targetCount: number
  createdAt: string
  completedAt: string | null
}

function tone(status: string): 'critical' | 'warning' | 'calm' | 'plain' {
  if (status === 'Succeeded') return 'calm'
  if (['Failed', 'RolledBack', 'PartiallyFailed'].includes(status)) return 'critical'
  if (['PendingApproval', 'Scheduled'].includes(status)) return 'warning'
  return 'plain'
}

export function Activity() {
  const { data, error, loading, reload } = useApi<JobRow[]>('/api/v1/deployments?take=100')
  const navigate = useNavigate()

  return (
    <Page
      title="Activity"
      lead="Every installation RemoteSSL has run, newest first."
      actions={<button onClick={reload} disabled={loading}>Refresh</button>}
    >
      {error && <Problem error={error} />}
      {loading && !data && <Loading what="recent installations" />}
      {data && data.length === 0 && (
        <Empty title="Nothing has been installed yet.">
          Installations start from a certificate, or from a server’s “What’s on it?” list.
        </Empty>
      )}
      {data && data.length > 0 && (
        <Card>
          <table className="grid">
            <thead>
              <tr><th>When</th><th>Certificate</th><th>Result</th><th>Places</th><th>Started by</th></tr>
            </thead>
            <tbody>
              {data.map((j) => (
                <tr key={j.id} className="clickable" onClick={() => navigate(`/activity/${j.id}`)}>
                  <td className="small">{shortDateTime(j.createdAt)}</td>
                  <td><strong>{j.certificate}</strong></td>
                  <td><Pill tone={tone(j.status)}>{j.status}</Pill></td>
                  <td className="small">{j.targetCount}</td>
                  <td className="small muted">{j.requestedBy ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </Page>
  )
}

interface Step { step: string; status: string; safeLog: string | null; completedAt: string | null }
interface JobTarget {
  id: string; status: string; target: string; adapter: string; store: string; steps: Step[]
}
interface JobDetail {
  id: string
  status: string
  strategy: string
  certificate: string
  requestedBy: string | null
  approvedBy: string | null
  correlationId: string
  createdAt: string
  completedAt: string | null
  targets: JobTarget[]
}

export function ActivityDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { data, error, loading, reload } = useApi<JobDetail>(id ? `/api/v1/deployments/${id}` : null)
  const [busy, setBusy] = useState(false)

  async function act(what: 'continue' | 'rollback' | 'cancel') {
    if (what === 'rollback' && !confirm('Put the previous certificate back on every place this job touched?')) return
    setBusy(true)
    const res = await apiPost(`/api/v1/deployments/${id}/${what}`,
      what === 'cancel' ? { reason: 'cancelled from the UI' } : { actor: 'ui' })
    setBusy(false)
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      alert(body.title ?? `That did not work (${res.status}).`)
    }
    reload()
  }

  if (loading && !data) return <Page title="Installation"><Loading what="this installation" /></Page>
  if (error) return <Page title="Installation"><Problem error={error} /></Page>
  if (!data) return null

  const failed = data.targets.filter((t) => t.status === 'Failed' || t.status === 'RolledBack')

  return (
    <Page
      title={`Installing ${data.certificate}`}
      lead={`${shortDateTime(data.createdAt)} · ${data.strategy} · started by ${data.requestedBy ?? 'unknown'}`}
      actions={
        <>
          <button onClick={() => navigate('/activity')}>Back</button>
          {data.status === 'AwaitingContinuation' && (
            <button className="primary" onClick={() => act('continue')} disabled={busy}>Continue</button>
          )}
          {['Running', 'Scheduled', 'PendingApproval'].includes(data.status) && (
            <button onClick={() => act('cancel')} disabled={busy}>Cancel</button>
          )}
          {data.status === 'Succeeded' && (
            <button className="danger" onClick={() => act('rollback')} disabled={busy}>Roll back</button>
          )}
        </>
      }
    >
      <Card>
        <p className="headline"><Pill tone={tone(data.status)}>{data.status}</Pill></p>
        {failed.length > 0 && (
          <p className="small">
            {failed.length} of {data.targets.length} place(s) did not take the certificate.
          </p>
        )}
        <p className="muted small mono">correlation {data.correlationId}</p>
      </Card>

      {data.targets.map((t) => (
        <Card key={t.id} title={`${t.target} · ${t.store}`}
          aside={<Pill tone={tone(t.status)}>{t.status}</Pill>}>
          {t.steps.length === 0 ? (
            <p className="muted small">Nothing has run here yet.</p>
          ) : (
            <ol className="pipeline">
              {t.steps.map((s, i) => (
                <li key={i} className={s.status === 'Succeeded' ? 'done'
                  : s.status === 'Failed' ? 'failed' : 'skipped'}>
                  <span className="pipeline-step">{s.step}</span>
                  <span className="pipeline-log small muted">{s.safeLog}</span>
                </li>
              ))}
            </ol>
          )}
        </Card>
      ))}
    </Page>
  )
}

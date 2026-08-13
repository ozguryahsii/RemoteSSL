import { useState } from 'react'
import { apiGet } from '../api/client'
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

function statusClass(s: string) {
  if (['Succeeded'].includes(s)) return 'ok'
  if (['Running', 'Pending', 'PendingApproval', 'Approved', 'Scheduled'].includes(s)) return 'warn'
  return 'bad'
}

export default function Deployments() {
  const [jobs] = useData<JobRow[]>('/api/v1/deployments', 10000)
  const [detail, setDetail] = useState<JobDetail | null>(null)

  return (
    <div className="page">
      <h1>Deployments</h1>
      <p className="muted small">Create deployments from the Certificates screen or the API; jobs run transactionally with automatic rollback.</p>
      <table className="data-table">
        <thead><tr><th>Certificate</th><th>Status</th><th>Targets</th><th>Requested by</th><th>Created</th><th>Completed</th></tr></thead>
        <tbody>
          {(jobs ?? []).map((j) => (
            <tr key={j.id} className="clickable" onClick={() => apiGet<JobDetail>(`/api/v1/deployments/${j.id}`).then(setDetail)}>
              <td>{j.certificate}</td>
              <td><span className={statusClass(j.status)}>{j.status}</span></td>
              <td>{j.targetCount}</td><td>{j.requestedBy}</td>
              <td className="small muted">{new Date(j.createdAt).toLocaleString()}</td>
              <td className="small muted">{j.completedAt ? new Date(j.completedAt).toLocaleString() : '—'}</td>
            </tr>
          ))}
          {(jobs ?? []).length === 0 && <tr><td colSpan={6} className="muted">No deployment jobs yet.</td></tr>}
        </tbody>
      </table>

      {detail && (
        <div className="detail-panel">
          <div className="detail-header">
            <h2>{detail.certificate} — <span className={statusClass(detail.status)}>{detail.status}</span></h2>
            <button onClick={() => setDetail(null)}>Close</button>
          </div>
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
        </div>
      )}
    </div>
  )
}

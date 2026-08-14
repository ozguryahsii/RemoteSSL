import { useCallback, useEffect, useState } from 'react'
import { apiGet, apiPost, apiPatch, apiDelete } from '../api/client'

export function useData<T>(path: string, refreshMs = 30000): [T | null, () => void, string | null] {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const reload = useCallback(() => {
    apiGet<T>(path)
      .then((d) => { setData(d); setError(null) })
      // Surface the failure instead of leaving the screen on "Loading…" forever.
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
  }, [path])
  useEffect(() => {
    reload()
    const id = setInterval(reload, refreshMs)
    return () => clearInterval(id)
  }, [reload, refreshMs])
  return [data, reload, error]
}

export const post = apiPost

export function Runners() {
  const [runners] = useData<{
    id: string; name: string; segment: string | null; status: string
    capabilities: string; version: string | null; lastHeartbeatAt: string | null
    hasIdentityCertificate: boolean; identityRevokedAt: string | null; identityRevokedReason: string | null
  }[]>('/api/v1/runners', 10000)
  return (
    <div className="page">
      <h1>Runners</h1>
      <table className="data-table">
        <thead><tr><th>Name</th><th>Segment</th><th>Status</th><th>Identity</th><th>Capabilities</th><th>Version</th><th>Last heartbeat</th></tr></thead>
        <tbody>
          {(runners ?? []).map((r) => (
            <tr key={r.id}>
              <td>{r.name}</td><td>{r.segment ?? '—'}</td>
              <td><span className={r.status === 'Online' ? 'ok' : 'bad'}>{r.status}</span></td>
              <td className="small">
                {r.identityRevokedAt
                  ? <span className="bad">revoked{r.identityRevokedReason ? ` — ${r.identityRevokedReason}` : ''}</span>
                  : r.hasIdentityCertificate
                    ? <span className="ok">client certificate</span>
                    : <span className="muted">API key only</span>}
              </td>
              <td className="small muted">{JSON.parse(r.capabilities || '[]').join(', ')}</td>
              <td>{r.version ?? '—'}</td>
              <td className="small muted">{r.lastHeartbeatAt ? new Date(r.lastHeartbeatAt).toLocaleString() : '—'}</td>
            </tr>
          ))}
          {(runners ?? []).length === 0 && <tr><td colSpan={7} className="muted">No runners registered. Start a runner with the bootstrap token.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

export function Credentials() {
  const [creds, reload] = useData<{
    id: string; name: string; credentialType: string; provider: string; username: string | null; hasSecret: boolean
  }[]>('/api/v1/credentials')
  const [name, setName] = useState(''); const [username, setUsername] = useState('')
  const [password, setPassword] = useState(''); const [privateKey, setPrivateKey] = useState('')
  const [editing, setEditing] = useState<string | null>(null)
  const [eName, setEName] = useState(''); const [eUser, setEUser] = useState('')
  const [ePass, setEPass] = useState(''); const [eKey, setEKey] = useState('')

  async function add(e: React.FormEvent) {
    e.preventDefault()
    await post('/api/v1/credentials', {
      name, credentialType: privateKey ? 'SshPrivateKey' : 'UsernamePassword',
      username, password: password || null, privateKeyPem: privateKey || null,
    })
    setName(''); setUsername(''); setPassword(''); setPrivateKey(''); reload()
  }
  function startEdit(c: { id: string; name: string; username: string | null }) {
    setEditing(c.id); setEName(c.name); setEUser(c.username ?? ''); setEPass(''); setEKey('')
  }
  async function saveEdit(id: string) {
    await apiPatch(`/api/v1/credentials/${id}`, {
      name: eName, username: eUser, password: ePass || null, privateKeyPem: eKey || null,
    })
    setEditing(null); reload()
  }
  async function remove(id: string) {
    if (!window.confirm('Delete this credential?')) return
    const res = await apiDelete(`/api/v1/credentials/${id}`)
    if (!res.ok) alert('Delete failed: ' + ((await res.json()).title ?? res.status))
    reload()
  }
  return (
    <div className="page">
      <h1>Credentials</h1>
      <p className="muted small">Secret values are write-only: stored encrypted, never displayed. Leave secret fields blank on edit to keep the current secret.</p>
      <form className="inline-form" onSubmit={add}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="name" required />
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" required />
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" type="password" />
        <input value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} placeholder="SSH private key PEM (optional)" />
        <button type="submit">Add credential</button>
      </form>
      <table className="data-table">
        <thead><tr><th>Name</th><th>Type</th><th>Provider</th><th>Username</th><th>Secret</th><th></th></tr></thead>
        <tbody>
          {(creds ?? []).map((c) => editing === c.id ? (
            <tr key={c.id} className="editing-row">
              <td><input value={eName} onChange={(e) => setEName(e.target.value)} /></td>
              <td className="muted small">{c.credentialType}</td><td className="muted small">{c.provider}</td>
              <td><input value={eUser} onChange={(e) => setEUser(e.target.value)} style={{ width: 120 }} /></td>
              <td>
                <input value={ePass} onChange={(e) => setEPass(e.target.value)} placeholder="new password" type="password" style={{ width: 130 }} />
                <input value={eKey} onChange={(e) => setEKey(e.target.value)} placeholder="new key PEM" style={{ width: 130 }} />
              </td>
              <td className="actions">
                <button onClick={() => saveEdit(c.id)}>Save</button>
                <button onClick={() => setEditing(null)}>Cancel</button>
              </td>
            </tr>
          ) : (
            <tr key={c.id}>
              <td>{c.name}</td><td>{c.credentialType}</td><td>{c.provider}</td>
              <td>{c.username ?? '—'}</td>
              <td>{c.hasSecret ? <span className="ok">stored (encrypted)</span> : <span className="muted">external</span>}</td>
              <td className="actions">
                <button onClick={() => startEdit(c)}>Edit</button>
                <button className="danger" onClick={() => remove(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {(creds ?? []).length === 0 && <tr><td colSpan={6} className="muted">No credentials yet.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

export function Approvals() {
  const [pending, reload] = useData<{ id: string; deploymentJobId: string; requestedBy: string; createdAt: string }[]>(
    '/api/v1/deployments/approvals/pending', 15000)

  async function decide(jobId: string, approve: boolean) {
    const approver = window.prompt('Approver username:') ?? 'approver'
    await post(`/api/v1/deployments/${jobId}/approve`, { approver, approve })
    reload()
  }
  return (
    <div className="page">
      <h1>Approvals</h1>
      <table className="data-table">
        <thead><tr><th>Deployment job</th><th>Requested by</th><th>Created</th><th></th></tr></thead>
        <tbody>
          {(pending ?? []).map((a) => (
            <tr key={a.id}>
              <td className="small">{a.deploymentJobId}</td><td>{a.requestedBy}</td>
              <td className="small muted">{new Date(a.createdAt).toLocaleString()}</td>
              <td className="actions">
                <button onClick={() => decide(a.deploymentJobId, true)}>Approve</button>
                <button className="danger" onClick={() => decide(a.deploymentJobId, false)}>Reject</button>
              </td>
            </tr>
          ))}
          {(pending ?? []).length === 0 && <tr><td colSpan={4} className="muted">No pending approvals — entries appear here only when a deployment is created with "require approval" (or a renewal policy demands it).</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

interface TraceView {
  correlationId: string
  request: { id: string; commonName: string; state: string; createdAt: string; errorMessage: string | null } | null
  deploymentJobs: { id: string; status: string; strategy: string; certificate: string; targetCount: number; createdAt: string; completedAt: string | null }[]
  runnerJobs: { id: string; jobType: string; status: string; runnerId: string | null; createdAt: string; completedAt: string | null }[]
  events: { timestamp: string; actor: string; action: string; objectType: string; result: string }[]
  metrics: { timestamp: string; metric: string; valueMs: number; label: string | null; success: boolean }[]
}

/** §32.2: the full chain behind one trace id — request → CA → job → runner → target. */
function TracePanel({ correlationId, onClose }: { correlationId: string; onClose: () => void }) {
  const [trace, setTrace] = useState<TraceView | null>(null)
  useEffect(() => {
    apiGet<TraceView>(`/api/v1/audit/trace/${correlationId}`).then(setTrace).catch(() => {})
  }, [correlationId])

  return (
    <div className="detail-panel">
      <div className="detail-header">
        <h2 className="small">Trace {correlationId}</h2>
        <button onClick={onClose}>Close</button>
      </div>
      {!trace ? <p className="muted">Loading…</p> : (
        <>
          <dl className="kv">
            <dt>Certificate request</dt>
            <dd>{trace.request
              ? `${trace.request.commonName} — ${trace.request.state}${trace.request.errorMessage ? ` (${trace.request.errorMessage})` : ''}`
              : '—'}</dd>
            <dt>Deployment jobs</dt>
            <dd>{trace.deploymentJobs.length === 0 ? '—' : trace.deploymentJobs.map((j) => (
              <div key={j.id}>{j.certificate} · {j.strategy} · {j.targetCount} target(s) · <span className={j.status === 'Succeeded' ? 'ok' : 'warn'}>{j.status}</span></div>
            ))}</dd>
            <dt>Runner jobs</dt>
            <dd>{trace.runnerJobs.length === 0 ? '—' : trace.runnerJobs.map((j) => (
              <div key={j.id}>{j.jobType} · <span className={j.status === 'Succeeded' ? 'ok' : j.status === 'Failed' ? 'bad' : 'muted'}>{j.status}</span>
                <span className="muted small"> {new Date(j.createdAt).toLocaleString()}</span></div>
            ))}</dd>
            <dt>Latency samples</dt>
            <dd>{trace.metrics.length === 0 ? '—' : trace.metrics.map((m, i) => (
              <div key={i}>{m.metric} {Math.round(m.valueMs)} ms {m.label && <span className="muted">({m.label})</span>}</div>
            ))}</dd>
          </dl>
          <h3 className="small">Steps</h3>
          <table className="data-table">
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Result</th></tr></thead>
            <tbody>
              {trace.events.map((e, i) => (
                <tr key={i}>
                  <td className="small muted">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="small">{e.actor}</td><td>{e.action}</td>
                  <td className="small">{e.objectType}</td>
                  <td><span className={/FAIL|DRIFT/.test(e.result) ? 'bad' : 'ok'}>{e.result}</span></td>
                </tr>
              ))}
              {trace.events.length === 0 && <tr><td colSpan={5} className="muted">No audit events on this trace.</td></tr>}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

export function Audit() {
  const [events] = useData<{
    id: number; timestamp: string; actor: string; action: string
    objectType: string; result: string; correlationId: string; detailsJson: string
  }[]>('/api/v1/audit?take=100', 15000)
  const [trace, setTrace] = useState<string | null>(null)

  return (
    <div className="page">
      <h1>Audit</h1>
      <p className="muted small">
        Click a trace id to follow one operation end to end: certificate request → CA → deployment job → runner → target.
      </p>
      <table className="data-table">
        <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Result</th><th>Trace</th><th>Details</th></tr></thead>
        <tbody>
          {(events ?? []).map((e) => (
            <tr key={e.id}>
              <td className="small muted">{new Date(e.timestamp).toLocaleString()}</td>
              <td className="small">{e.actor}</td><td>{e.action}</td><td className="small">{e.objectType}</td>
              <td><span className={/FAIL|DRIFT/.test(e.result) ? 'bad' : 'ok'}>{e.result}</span></td>
              <td className="small">
                {e.correlationId
                  ? <button className="link-button" onClick={() => setTrace(e.correlationId)}>{e.correlationId.slice(0, 8)}…</button>
                  : '—'}
              </td>
              <td className="small muted" style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.detailsJson}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {trace && <TracePanel correlationId={trace} onClose={() => setTrace(null)} />}
    </div>
  )
}

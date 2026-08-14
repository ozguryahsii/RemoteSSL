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

const CREDENTIAL_TYPES = [
  'UsernamePassword', 'SshPrivateKey', 'SshCertificate', 'KerberosServiceAccount',
  'ApiKeySecret', 'OAuthClientCredentials', 'BearerToken', 'ClientCertificate', 'ExternalSecretReference',
] as const

const PROVIDERS = ['InternalVault', 'HashiCorpVault', 'CyberArk', 'AzureKeyVault'] as const

type SecretInput = {
  password?: string; privateKeyPem?: string; sshCertificate?: string; realm?: string
  token?: string; clientId?: string; clientSecret?: string; tokenEndpoint?: string
  pkcs12Base64?: string; pkcs12Password?: string
}

/** Which secret fields a credential type actually needs (design doc §7.2). */
const FIELDS_BY_TYPE: Record<string, { key: keyof SecretInput; label: string; secret?: boolean }[]> = {
  UsernamePassword: [{ key: 'password', label: 'password', secret: true }],
  SshPrivateKey: [{ key: 'password', label: 'passphrase (optional)', secret: true }, { key: 'privateKeyPem', label: 'private key PEM' }],
  SshCertificate: [{ key: 'privateKeyPem', label: 'private key PEM' }, { key: 'sshCertificate', label: 'signed SSH certificate' }],
  KerberosServiceAccount: [{ key: 'password', label: 'password', secret: true }, { key: 'realm', label: 'realm' }],
  ApiKeySecret: [{ key: 'token', label: 'api key', secret: true }],
  BearerToken: [{ key: 'token', label: 'bearer token', secret: true }],
  OAuthClientCredentials: [
    { key: 'clientId', label: 'client id' },
    { key: 'clientSecret', label: 'client secret', secret: true },
    { key: 'tokenEndpoint', label: 'token endpoint' },
  ],
  ClientCertificate: [
    { key: 'pkcs12Base64', label: 'PKCS#12 (base64)' },
    { key: 'pkcs12Password', label: 'PKCS#12 password', secret: true },
  ],
  ExternalSecretReference: [],
}

type CredentialRow = {
  id: string; name: string; credentialType: string; provider: string; username: string | null
  secretIdentifier: string; hasSecret: boolean; rotationIntervalDays: number
  lastRotatedAt: string | null; rotationDueAt: string | null; rotationOverdue: boolean
  rotationPending: boolean; lastAccessedAt: string | null; lastAccessedBy: string | null
}

/** The secret half of a credential form; the same control set is used for create, edit and rotate. */
function SecretFields({ type, value, onChange }: {
  type: string; value: SecretInput; onChange: (v: SecretInput) => void
}) {
  const fields = FIELDS_BY_TYPE[type] ?? []
  if (fields.length === 0) return <span className="muted small">This type keeps its secret in the external provider.</span>
  return (
    <>
      {fields.map((f) => (
        <input
          key={f.key}
          value={value[f.key] ?? ''}
          type={f.secret ? 'password' : 'text'}
          placeholder={f.label}
          onChange={(e) => onChange({ ...value, [f.key]: e.target.value })}
        />
      ))}
    </>
  )
}

export function Credentials() {
  const [creds, reload, error] = useData<CredentialRow[]>('/api/v1/credentials')
  const [name, setName] = useState(''); const [username, setUsername] = useState('')
  const [type, setType] = useState<string>('UsernamePassword')
  const [provider, setProvider] = useState<string>('InternalVault')
  const [identifier, setIdentifier] = useState('')
  const [rotationDays, setRotationDays] = useState('0')
  const [secret, setSecret] = useState<SecretInput>({})

  const [editing, setEditing] = useState<string | null>(null)
  const [eName, setEName] = useState(''); const [eUser, setEUser] = useState('')
  const [eRotation, setERotation] = useState('0'); const [eSecret, setESecret] = useState<SecretInput>({})
  const [rotating, setRotating] = useState<CredentialRow | null>(null)
  const [rotateSecret, setRotateSecret] = useState<SecretInput>({})

  async function add(e: React.FormEvent) {
    e.preventDefault()
    await post('/api/v1/credentials', {
      name, credentialType: type, username: username || null, provider,
      secretIdentifier: identifier || null, rotationIntervalDays: Number(rotationDays) || 0,
      secret: provider === 'InternalVault' ? secret : null,
    })
    setName(''); setUsername(''); setIdentifier(''); setSecret({}); setRotationDays('0'); reload()
  }

  function startEdit(c: CredentialRow) {
    setEditing(c.id); setEName(c.name); setEUser(c.username ?? '')
    setERotation(String(c.rotationIntervalDays)); setESecret({})
  }

  async function saveEdit(id: string, c: CredentialRow) {
    await apiPatch(`/api/v1/credentials/${id}`, {
      name: eName, username: eUser, rotationIntervalDays: Number(eRotation) || 0,
      secret: c.provider === 'InternalVault' && Object.keys(eSecret).length > 0 ? eSecret : null,
    })
    setEditing(null); reload()
  }

  async function submitRotation() {
    if (!rotating) return
    await post(`/api/v1/credentials/${rotating.id}/rotate`, {
      secret: rotating.provider === 'InternalVault' ? rotateSecret : null,
    })
    setRotating(null); setRotateSecret({}); reload()
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
      <p className="muted small">
        Secret values are write-only: stored encrypted, never displayed. Leave secret fields blank on edit to keep
        the current secret. External providers hold the secret themselves — only the identifier is stored here.
      </p>
      {error && <p className="bad small">{error}</p>}
      <form className="inline-form" onSubmit={add}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="name" required />
        <select value={type} onChange={(e) => { setType(e.target.value); setSecret({}) }}>
          {CREDENTIAL_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={provider} onChange={(e) => setProvider(e.target.value)}>
          {PROVIDERS.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" />
        {provider === 'InternalVault'
          ? <SecretFields type={type} value={secret} onChange={setSecret} />
          : <input value={identifier} onChange={(e) => setIdentifier(e.target.value)}
              placeholder={provider === 'CyberArk' ? 'cyberark://safe/object'
                : provider === 'AzureKeyVault' ? 'azurekv://vault/secret' : 'vault://mount/path'} required />}
        <input value={rotationDays} onChange={(e) => setRotationDays(e.target.value)}
          type="number" min={0} style={{ width: 110 }} placeholder="rotate (days)" title="Rotation interval in days; 0 = no reminder" />
        <button type="submit">Add credential</button>
      </form>

      {rotating && (
        <div className="inline-form" style={{ marginTop: 8 }}>
          <strong>Rotate “{rotating.name}”</strong>
          {rotating.provider === 'InternalVault'
            ? <SecretFields type={rotating.credentialType} value={rotateSecret} onChange={setRotateSecret} />
            : <span className="muted small">Rotate the secret in {rotating.provider}, then confirm here to reset the clock.</span>}
          <button onClick={submitRotation}>Confirm rotation</button>
          <button onClick={() => { setRotating(null); setRotateSecret({}) }}>Cancel</button>
        </div>
      )}

      <table className="data-table">
        <thead><tr>
          <th>Name</th><th>Type</th><th>Provider</th><th>Username</th><th>Secret</th>
          <th>Rotation</th><th>Last access</th><th></th>
        </tr></thead>
        <tbody>
          {(creds ?? []).map((c) => editing === c.id ? (
            <tr key={c.id} className="editing-row">
              <td><input value={eName} onChange={(e) => setEName(e.target.value)} style={{ width: 120 }} /></td>
              <td className="muted small">{c.credentialType}</td>
              <td className="muted small">{c.provider}</td>
              <td><input value={eUser} onChange={(e) => setEUser(e.target.value)} style={{ width: 110 }} /></td>
              <td><SecretFields type={c.credentialType} value={eSecret} onChange={setESecret} /></td>
              <td><input value={eRotation} onChange={(e) => setERotation(e.target.value)} type="number" min={0} style={{ width: 70 }} /></td>
              <td className="muted small">—</td>
              <td className="actions">
                <button onClick={() => saveEdit(c.id, c)}>Save</button>
                <button onClick={() => setEditing(null)}>Cancel</button>
              </td>
            </tr>
          ) : (
            <tr key={c.id}>
              <td>{c.name}</td><td className="small">{c.credentialType}</td><td className="small">{c.provider}</td>
              <td>{c.username ?? '—'}</td>
              <td className="small">
                {c.hasSecret
                  ? <span className="ok">stored (encrypted)</span>
                  : <span className="muted" title={c.secretIdentifier}>{c.secretIdentifier}</span>}
              </td>
              <td className="small">
                {c.rotationIntervalDays === 0
                  ? <span className="muted">not configured</span>
                  : c.rotationOverdue || c.rotationPending
                    ? <span className="bad">overdue since {c.rotationDueAt ? new Date(c.rotationDueAt).toLocaleDateString() : '—'}</span>
                    : <span className="ok">due {c.rotationDueAt ? new Date(c.rotationDueAt).toLocaleDateString() : '—'}</span>}
              </td>
              <td className="small muted">
                {c.lastAccessedAt ? `${new Date(c.lastAccessedAt).toLocaleString()} — ${c.lastAccessedBy ?? ''}` : 'never'}
              </td>
              <td className="actions">
                <button onClick={() => startEdit(c)}>Edit</button>
                <button onClick={() => { setRotating(c); setRotateSecret({}) }}>Rotate</button>
                <button className="danger" onClick={() => remove(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {(creds ?? []).length === 0 && <tr><td colSpan={8} className="muted">No credentials yet.</td></tr>}
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

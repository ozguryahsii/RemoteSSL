import { useState } from 'react'
import { apiPost, apiPatch, apiPut, apiDelete, setToken, getToken } from '../api/client'
import { useData, post } from './SimplePages'

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  async function login(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    const res = await apiPost('/api/v1/auth/login', { username, password })
    if (!res.ok) { setError('Invalid credentials'); return }
    const body = await res.json()
    setToken(body.token)
    window.location.href = '/'
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={login}>
        <h1>RemoteSSL</h1>
        <p className="muted small">Sign in to continue. If authentication is disabled on the server, any page works without signing in.</p>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" required autoFocus />
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" type="password" required />
        {error && <p className="error small">{error}</p>}
        <button type="submit">Sign in</button>
      </form>
    </div>
  )
}

interface Policy {
  id: string; name: string; enabled: boolean; triggerDays: number; rotateKey: boolean
  autoDeploy: boolean; approvalRequired: boolean; maintenanceWindowJson: string | null
  caConnectorId: string | null
}

export function Policies() {
  const [policies, reload] = useData<Policy[]>('/api/v1/policies')
  const [certs] = useData<{ id: string; commonName: string }[]>('/api/v1/certificates')
  const [connectors] = useData<{ id: string; name: string }[]>('/api/v1/ca-connectors')
  const [name, setName] = useState(''); const [days, setDays] = useState('30')
  const [autoDeploy, setAutoDeploy] = useState(true); const [approval, setApproval] = useState(false)
  const [caId, setCaId] = useState(''); const [window_, setWindow] = useState('')

  async function add(e: React.FormEvent) {
    e.preventDefault()
    await post('/api/v1/policies', {
      name, triggerDays: Number(days), autoDeploy, approvalRequired: approval,
      caConnectorId: caId || null,
      maintenanceWindow: window_ ? JSON.parse(window_) : null,
    })
    setName(''); reload()
  }

  async function assign(policyId: string) {
    const certId = window.prompt(`Certificate id to attach:\n${(certs ?? []).map((c) => `${c.commonName}: ${c.id}`).join('\n')}`)
    if (certId) await post(`/api/v1/policies/${policyId}/assign`, { certificateId: certId.trim() })
  }

  async function toggleEnabled(p: Policy) {
    await apiPatch(`/api/v1/policies/${p.id}`, { enabled: !p.enabled })
    reload()
  }
  async function remove(id: string) {
    if (!window.confirm('Delete this policy? Certificates using it will be unassigned.')) return
    await apiDelete(`/api/v1/policies/${id}`)
    reload()
  }

  return (
    <div className="page">
      <h1>Policies</h1>
      <h2>Renewal policies</h2>
      <form className="inline-form" onSubmit={add}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="policy name" required />
        <input value={days} onChange={(e) => setDays(e.target.value)} type="number" style={{ width: 90 }} title="renew before days" />
        <label className="small"><input type="checkbox" checked={autoDeploy} onChange={(e) => setAutoDeploy(e.target.checked)} /> auto-deploy</label>
        <label className="small"><input type="checkbox" checked={approval} onChange={(e) => setApproval(e.target.checked)} /> approval</label>
        <select value={caId} onChange={(e) => setCaId(e.target.value)}>
          <option value="">no CA (manual)</option>
          {(connectors ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <input value={window_} onChange={(e) => setWindow(e.target.value)}
               placeholder='window e.g. {"days":["SUN"],"start":"01:00","end":"04:00"}' style={{ width: 280 }} />
        <button type="submit">Add policy</button>
      </form>
      <table className="data-table">
        <thead><tr><th>Name</th><th>Trigger</th><th>Auto deploy</th><th>Approval</th><th>Window</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          {(policies ?? []).map((p) => (
            <tr key={p.id}>
              <td>{p.name}</td><td>T-{p.triggerDays}</td>
              <td>{p.autoDeploy ? 'yes' : 'no'}</td><td>{p.approvalRequired ? 'required' : 'no'}</td>
              <td className="small muted">{p.maintenanceWindowJson ?? 'anytime'}</td>
              <td>{p.enabled ? <span className="ok">yes</span> : <span className="muted">no</span>}</td>
              <td className="actions">
                <button onClick={() => assign(p.id)}>Assign</button>
                <button onClick={() => toggleEnabled(p)}>{p.enabled ? 'Disable' : 'Enable'}</button>
                <button className="danger" onClick={() => remove(p.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {(policies ?? []).length === 0 && <tr><td colSpan={7} className="muted">No policies yet.</td></tr>}
        </tbody>
      </table>

      <CertificatePolicies />
    </div>
  )
}

interface CertPolicy {
  id: string; name: string; isDefault: boolean
  minimumRsaBits: number; allowedEcCurves: string[]
  renewBeforeDays: number; rotateKeyOnRenewal: boolean
  requireApprovalIn: string[]; blockWeakSignatureAlgorithms: boolean; requirePostDeploymentProbe: boolean
  allowWildcard: boolean; maxValidityDays: number | null
  allowedDomainSuffixes: string[]; blockedDomainSuffixes: string[]
  warnOnOverlap: boolean; requireOwner: boolean
  requireWindowIn: string[]; enforceSeparationOfDuties: boolean
}

const EMPTY_CERT_POLICY: Omit<CertPolicy, 'id'> = {
  name: '', isDefault: false, minimumRsaBits: 2048, allowedEcCurves: ['P-256', 'P-384'],
  renewBeforeDays: 30, rotateKeyOnRenewal: true, requireApprovalIn: ['PROD'],
  blockWeakSignatureAlgorithms: true, requirePostDeploymentProbe: true,
  allowWildcard: true, maxValidityDays: null, allowedDomainSuffixes: [], blockedDomainSuffixes: [],
  warnOnOverlap: true, requireOwner: false, requireWindowIn: [], enforceSeparationOfDuties: true,
}

const csv = (v: string[]) => v.join(', ')
const parseCsv = (v: string) => v.split(',').map((x) => x.trim()).filter(Boolean)

/**
 * Certificate policy editor (design doc §39 + the §17.2 request rules and the §23.2/§23.3
 * governance switches). One policy is the default; certificates may point at another.
 */
function CertificatePolicies() {
  const [policies, reload] = useData<CertPolicy[]>('/api/v1/certificate-policies')
  const [draft, setDraft] = useState<Omit<CertPolicy, 'id'>>(EMPTY_CERT_POLICY)
  const [editing, setEditing] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  function edit(p: CertPolicy) {
    const { id, ...rest } = p
    setEditing(id); setDraft(rest); setError(null)
  }

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    const res = editing
      ? await apiPatch(`/api/v1/certificate-policies/${editing}`, draft)
      : await apiPost('/api/v1/certificate-policies', draft)
    if (!res.ok) { setError((await res.json()).title ?? `Save failed (${res.status})`); return }
    setEditing(null); setDraft(EMPTY_CERT_POLICY); reload()
  }

  async function remove(id: string) {
    if (!window.confirm('Delete this certificate policy? Certificates using it fall back to the default.')) return
    const res = await apiDelete(`/api/v1/certificate-policies/${id}`)
    if (!res.ok) setError((await res.json()).title ?? `Delete failed (${res.status})`)
    reload()
  }

  const set = <K extends keyof typeof draft>(key: K, value: (typeof draft)[K]) =>
    setDraft({ ...draft, [key]: value })

  return (
    <div style={{ marginTop: 36 }}>
      <h2>Certificate policies</h2>
      <p className="muted small">
        Key strength, naming rules, approval and separation of duties. The default policy applies to every
        certificate that has no policy of its own.
      </p>

      <form className="policy-form" onSubmit={save}>
        <label>Name
          <input value={draft.name} onChange={(e) => set('name', e.target.value)} required />
        </label>
        <label>Minimum RSA bits
          <input type="number" value={draft.minimumRsaBits} onChange={(e) => set('minimumRsaBits', Number(e.target.value))} />
        </label>
        <label>Allowed EC curves
          <input value={csv(draft.allowedEcCurves)} onChange={(e) => set('allowedEcCurves', parseCsv(e.target.value))} placeholder="P-256, P-384" />
        </label>
        <label>Renew before (days)
          <input type="number" value={draft.renewBeforeDays} onChange={(e) => set('renewBeforeDays', Number(e.target.value))} />
        </label>
        <label>Max validity (days)
          <input type="number" value={draft.maxValidityDays ?? ''} placeholder="unlimited"
                 onChange={(e) => set('maxValidityDays', e.target.value ? Number(e.target.value) : null)} />
        </label>
        <label>Approval required in
          <input value={csv(draft.requireApprovalIn)} onChange={(e) => set('requireApprovalIn', parseCsv(e.target.value))} placeholder="PROD" />
        </label>
        <label>Maintenance window required in
          <input value={csv(draft.requireWindowIn)} onChange={(e) => set('requireWindowIn', parseCsv(e.target.value))} placeholder="none" />
        </label>
        <label>Allowed domain suffixes
          <input value={csv(draft.allowedDomainSuffixes)} onChange={(e) => set('allowedDomainSuffixes', parseCsv(e.target.value))} placeholder="any" />
        </label>
        <label>Blocked domain suffixes
          <input value={csv(draft.blockedDomainSuffixes)} onChange={(e) => set('blockedDomainSuffixes', parseCsv(e.target.value))} placeholder=".local, .internal" />
        </label>
        <div className="policy-toggles">
          <label><input type="checkbox" checked={draft.isDefault} onChange={(e) => set('isDefault', e.target.checked)} /> default policy</label>
          <label><input type="checkbox" checked={draft.rotateKeyOnRenewal} onChange={(e) => set('rotateKeyOnRenewal', e.target.checked)} /> rotate key on renewal</label>
          <label><input type="checkbox" checked={draft.blockWeakSignatureAlgorithms} onChange={(e) => set('blockWeakSignatureAlgorithms', e.target.checked)} /> block weak signature algorithms</label>
          <label><input type="checkbox" checked={draft.requirePostDeploymentProbe} onChange={(e) => set('requirePostDeploymentProbe', e.target.checked)} /> require post-deployment probe</label>
          <label><input type="checkbox" checked={draft.allowWildcard} onChange={(e) => set('allowWildcard', e.target.checked)} /> allow wildcard names</label>
          <label><input type="checkbox" checked={draft.warnOnOverlap} onChange={(e) => set('warnOnOverlap', e.target.checked)} /> warn on overlapping names</label>
          <label><input type="checkbox" checked={draft.requireOwner} onChange={(e) => set('requireOwner', e.target.checked)} /> require owner</label>
          <label><input type="checkbox" checked={draft.enforceSeparationOfDuties} onChange={(e) => set('enforceSeparationOfDuties', e.target.checked)} /> enforce separation of duties</label>
        </div>
        <div className="policy-actions">
          <button type="submit">{editing ? 'Save policy' : 'Add policy'}</button>
          {editing && <button type="button" onClick={() => { setEditing(null); setDraft(EMPTY_CERT_POLICY) }}>Cancel</button>}
        </div>
      </form>
      {error && <p className="error small">{error}</p>}

      <table className="data-table">
        <thead>
          <tr><th>Policy</th><th>Key rules</th><th>Naming</th><th>Governance</th><th></th></tr>
        </thead>
        <tbody>
          {(policies ?? []).map((p) => (
            <tr key={p.id} className={editing === p.id ? 'editing-row' : undefined}>
              <td>
                {p.name}
                {p.isDefault && <span className="tag ok">default</span>}
              </td>
              <td className="small muted">
                RSA ≥ {p.minimumRsaBits} · EC {csv(p.allowedEcCurves) || 'any'}
                <div>renew T-{p.renewBeforeDays} · {p.rotateKeyOnRenewal ? 'rotate key' : 'reuse key'}</div>
                {p.blockWeakSignatureAlgorithms && <div>weak signatures blocked</div>}
              </td>
              <td className="small muted">
                {p.allowWildcard ? 'wildcard allowed' : 'no wildcard'}
                {p.maxValidityDays && <div>max {p.maxValidityDays} days</div>}
                {p.allowedDomainSuffixes.length > 0 && <div>only {csv(p.allowedDomainSuffixes)}</div>}
                {p.blockedDomainSuffixes.length > 0 && <div>blocked {csv(p.blockedDomainSuffixes)}</div>}
                {p.requireOwner && <div>owner required</div>}
              </td>
              <td className="small muted">
                approval: {csv(p.requireApprovalIn) || 'never'}
                <div>window: {csv(p.requireWindowIn) || 'not enforced'}</div>
                <div>{p.enforceSeparationOfDuties ? 'separation of duties on' : 'separation of duties off'}</div>
                {p.requirePostDeploymentProbe && <div>post-deployment probe required</div>}
              </td>
              <td className="actions">
                <button onClick={() => edit(p)}>Edit</button>
                <button className="danger" onClick={() => remove(p.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {(policies ?? []).length === 0 && <tr><td colSpan={5} className="muted">No certificate policies yet.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

export function CaIntegrations() {
  const [connectors, reload] = useData<{ id: string; name: string; connectorType: string; enabled: boolean }[]>('/api/v1/ca-connectors')
  const [name, setName] = useState(''); const [type, setType] = useState('manual')
  const [apiKey, setApiKey] = useState(''); const [apiSecret, setApiSecret] = useState('')
  const [baseUrl, setBaseUrl] = useState('https://emea.api.hvca.globalsign.com:8443/v2')
  const [pfx, setPfx] = useState(''); const [pfxPass, setPfxPass] = useState('')
  const [result, setResult] = useState<string | null>(null)

  async function add(e: React.FormEvent) {
    e.preventDefault()
    const config = type === 'globalsign-hvca'
      ? { baseUrl, apiKey, apiSecret, clientPfxBase64: pfx || null, clientPfxPassword: pfxPass || null }
      : {}
    await post('/api/v1/ca-connectors', { name, connectorType: type, config })
    setName(''); reload()
  }

  async function test(id: string) {
    setResult('testing…')
    const res = await post(`/api/v1/ca-connectors/${id}/test`)
    const body = await res.json()
    setResult(body.success ? 'Connection OK' : `Failed: ${body.error}`)
  }

  async function toggleEnabled(c: { id: string; enabled: boolean }) {
    await apiPatch(`/api/v1/ca-connectors/${c.id}`, { enabled: !c.enabled })
    reload()
  }
  async function removeConnector(id: string) {
    if (!window.confirm('Delete this CA connector?')) return
    const res = await apiDelete(`/api/v1/ca-connectors/${id}`)
    if (!res.ok) alert('Delete failed: ' + ((await res.json()).title ?? res.status))
    reload()
  }
  async function rename(c: { id: string; name: string }) {
    const name = window.prompt('New name:', c.name)
    if (name) { await apiPatch(`/api/v1/ca-connectors/${c.id}`, { name }); reload() }
  }

  return (
    <div className="page">
      <h1>CA Integrations</h1>
      <form className="inline-form" onSubmit={add} style={{ flexWrap: 'wrap' }}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="connector name" required />
        <select value={type} onChange={(e) => setType(e.target.value)}>
          <option value="manual">Manual / offline CA</option>
          <option value="globalsign-hvca">GlobalSign (HVCA/Atlas)</option>
        </select>
        {type === 'globalsign-hvca' && (
          <>
            <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="base URL" style={{ width: 300 }} />
            <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="API key" />
            <input value={apiSecret} onChange={(e) => setApiSecret(e.target.value)} placeholder="API secret" type="password" />
            <input value={pfx} onChange={(e) => setPfx(e.target.value)} placeholder="mTLS client PFX (base64)" />
            <input value={pfxPass} onChange={(e) => setPfxPass(e.target.value)} placeholder="PFX password" type="password" />
          </>
        )}
        <button type="submit">Add connector</button>
      </form>
      {result && <p className="small">{result}</p>}
      <table className="data-table">
        <thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          {(connectors ?? []).map((c) => (
            <tr key={c.id}>
              <td>{c.name}</td><td>{c.connectorType}</td>
              <td>{c.enabled ? <span className="ok">yes</span> : <span className="muted">no</span>}</td>
              <td className="actions">
                <button onClick={() => test(c.id)}>Test connection</button>
                <button onClick={() => rename(c)}>Rename</button>
                <button onClick={() => toggleEnabled(c)}>{c.enabled ? 'Disable' : 'Enable'}</button>
                <button className="danger" onClick={() => removeConnector(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">
        GlobalSign connector is implemented against the documented HVCA v2 API and will be validated once account
        credentials are available. Configuration secrets are stored encrypted.
      </p>
    </div>
  )
}

export function Settings() {
  const [users, reload] = useData<{
    id: string; username: string; rolesJson: string; scopesJson: string
    externalSubject: string | null; enabled: boolean
  }[]>('/api/v1/users')
  const [username, setUsername] = useState(''); const [password, setPassword] = useState('')
  const [roles, setRoles] = useState<string[]>(['Viewer'])
  const allRoles = ['Viewer', 'CertificateOperator', 'DeploymentOperator', 'CertificateApprover',
    'SecurityAuditor', 'PlatformAdministrator', 'BreakGlassAdministrator']

  async function addUser(e: React.FormEvent) {
    e.preventDefault()
    const res = await post('/api/v1/users', { username, password, roles })
    if (!res.ok) alert('Create failed (auth may be disabled server-side, or password too short)')
    setUsername(''); setPassword(''); reload()
  }

  async function toggleUser(u: { id: string; enabled: boolean }) {
    await apiPatch(`/api/v1/users/${u.id}?enabled=${!u.enabled}`)
    reload()
  }
  async function resetPassword(u: { id: string; username: string }) {
    const pw = window.prompt(`New password for ${u.username} (min 8 chars):`)
    if (pw) { await apiPut(`/api/v1/users/${u.id}`, { password: pw }); reload() }
  }
  async function editRoles(u: { id: string; username: string; rolesJson: string }) {
    const current = JSON.parse(u.rolesJson || '[]').join(',')
    const next = window.prompt(`Roles for ${u.username} (comma separated):\n${allRoles.join(', ')}`, current)
    if (next !== null) {
      await apiPut(`/api/v1/users/${u.id}`, { roles: next.split(',').map((r) => r.trim()).filter(Boolean) })
      reload()
    }
  }
  /** §24.2: scope rules narrow a role to an environment, target group and adapter set. */
  async function editScopes(u: { id: string; username: string; scopesJson: string }) {
    const current = JSON.stringify(JSON.parse(u.scopesJson || '[]'), null, 2)
    const next = window.prompt(
      `Scope rules for ${u.username} — JSON array. Empty array = roles alone decide.\n`
      + `Example: [{"action":"certificate.deploy","environment":"PROD","targetGroup":"WEB","adapters":["nginx"]}]`,
      current)
    if (next === null) return
    try {
      const scopes = JSON.parse(next)
      const res = await apiPut(`/api/v1/users/${u.id}`, { scopes })
      if (!res.ok) alert(`Save failed (${res.status})`)
      reload()
    } catch {
      alert('That is not valid JSON.')
    }
  }

  /** Links a local account to an identity-provider subject for SSO (§4.3). */
  async function editFederation(u: { id: string; username: string; externalSubject: string | null }) {
    const next = window.prompt(
      `Identity provider subject (sub claim) for ${u.username}. Leave empty to unlink.`,
      u.externalSubject ?? '')
    if (next === null) return
    await apiPut(`/api/v1/users/${u.id}`,
      next ? { externalSubject: next } : { clearExternalSubject: true })
    reload()
  }

  async function removeUser(u: { id: string; username: string }) {
    if (!window.confirm(`Delete user ${u.username}?`)) return
    await apiDelete(`/api/v1/users/${u.id}`)
    reload()
  }

  return (
    <div className="page">
      <h1>Settings</h1>
      <h3>Session</h3>
      <p className="small">
        {getToken() ? <>Signed in. <button onClick={() => { setToken(null); window.location.href = '/login' }}>Sign out</button></>
          : 'Not signed in (server auth may be disabled — set Auth:Enabled=true in appsettings.json to enforce login).'}
      </p>

      <h3>Users</h3>
      <form className="inline-form" onSubmit={addUser} style={{ flexWrap: 'wrap' }}>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" required />
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password (min 8)" type="password" required />
        <select multiple value={roles} onChange={(e) => setRoles([...e.target.selectedOptions].map((o) => o.value))} style={{ height: 90 }}>
          {allRoles.map((r) => <option key={r}>{r}</option>)}
        </select>
        <button type="submit">Add user</button>
      </form>
      <table className="data-table">
        <thead><tr><th>Username</th><th>Roles</th><th>Scope</th><th>SSO subject</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          {(users ?? []).map((u) => (
            <tr key={u.id}>
              <td>{u.username}</td>
              <td className="small">{JSON.parse(u.rolesJson || '[]').join(', ')}</td>
              <td className="small muted">
                {(JSON.parse(u.scopesJson || '[]') as { action: string; environment?: string }[]).length === 0
                  ? 'unrestricted'
                  : (JSON.parse(u.scopesJson) as { action: string; environment?: string }[])
                      .map((r, i) => <div key={i}>{r.action}{r.environment ? ` @ ${r.environment}` : ''}</div>)}
              </td>
              <td className="small muted">{u.externalSubject ?? '—'}</td>
              <td>{u.enabled ? <span className="ok">yes</span> : <span className="bad">no</span>}</td>
              <td className="actions">
                <button onClick={() => editRoles(u)}>Roles</button>
                <button onClick={() => editScopes(u)}>Scopes</button>
                <button onClick={() => editFederation(u)}>SSO</button>
                <button onClick={() => resetPassword(u)}>Reset password</button>
                <button onClick={() => toggleUser(u)}>{u.enabled ? 'Disable' : 'Enable'}</button>
                <button className="danger" onClick={() => removeUser(u)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Notifications</h3>
      <p className="muted small">
        Configured server-side in appsettings.json: <code>Notifications:WebhookUrl</code> (generic webhook),{' '}
        <code>Notifications:TeamsWebhookUrl</code> (Microsoft Teams), <code>Notifications:Smtp:*</code> (e-mail).
        Events are also published to the RabbitMQ topic exchange <code>remotessl.events</code> for SIEM/downstream consumers.
      </p>
    </div>
  )
}

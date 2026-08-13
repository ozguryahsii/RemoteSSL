import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { API_BASE, apiGet, apiPost, apiPatch, apiDelete } from '../api/client'

interface CertificateListItem {
  id: string
  commonName: string
  displayName: string
  health: string
  issuerDn: string | null
  ca: string | null
  notAfter: string | null
  daysUntilExpiry: number | null
  managed: boolean
  deploymentCount: number
  autoRenew: boolean
  environment: string | null
  ownerId: string | null
  monitorCount: number
  versionCount: number
}

interface VersionDto {
  id: string; serialNumber: string; sha256Thumbprint: string; subjectDn: string; issuerDn: string
  notBefore: string; notAfter: string; daysUntilExpiry: number
  publicKeyAlgorithm: string; keySize: number; signatureAlgorithm: string; status: string; sans: string[]
}

interface CertificateDetail {
  id: string; commonName: string; displayName: string; health: string
  overview: {
    environment: string | null; ownerId: string | null; ca: string | null; issuerDn: string | null
    notAfter: string | null; daysUntilExpiry: number | null; managed: boolean; deploymentCount: number
    autoRenew: boolean; monitorCount: number; sans: string[]; createdAt: string; updatedAt: string
  }
  versions: VersionDto[]
  lifecycle: { at: string; stage: string; detail: string; actor: string | null }[]
  deployments: {
    jobId: string; status: string; strategy: string; requestedBy: string | null; approvedBy: string | null
    targetCount: number; failedTargets: number; createdAt: string; completedAt: string | null
  }[]
  stores: {
    bindingId: string; storeId: string; target: string; adapter: string
    storeType: string; storePath: string; alias: string | null; serviceBindingJson: string
  }[]
  monitors: { monitorId: string; host: string; port: number; sni: string | null; lastSeenAt: string }[]
  renewal: {
    policyId: string; name: string; enabled: boolean; triggerDays: number; rotateKey: boolean
    autoDeploy: boolean; approvalRequired: boolean; maintenanceWindowJson: string | null
    daysUntilTrigger: number | null; caConnector: string | null
  } | null
  artifacts: { versionId: string; kind: string; description: string; hasPrivateKey: boolean; createdAt: string }[]
  approvals: {
    id: string; deploymentJobId: string; status: string; requestedBy: string | null
    decidedBy: string | null; reason: string | null; createdAt: string; decidedAt: string | null
  }[]
  history: { id: number; timestamp: string; actor: string; action: string; result: string; detailsJson: string }[]
}

function healthClass(health: string): string {
  switch (health) {
    case 'Healthy': return 'ok'
    case 'ExpiringSoon': return 'warn'
    case 'Unknown': return 'muted'
    default: return 'bad'
  }
}

/** Certificate detail tabs per design doc §26.2. */
const TABS = ['Overview', 'Lifecycle', 'Deployments', 'Certificate Stores', 'Monitoring',
  'Renewal', 'Files / Artifacts', 'Approvals', 'History / Audit'] as const
type Tab = typeof TABS[number]

interface PlannedTarget {
  bindingId: string; target: string; adapter: string; environment: string | null; haRole: string | null
  store: string; alias: string | null; runnerName: string | null; runnerStatus: string
  currentThumbprint: string | null; currentCommonName: string | null; currentDaysLeft: number | null
}

interface DeploymentPlan {
  certificate: string; newThumbprint: string; newNotAfter: string
  strategy: string; maxConcurrency: number; stopOnFailure: boolean; manualContinuation: boolean
  approvalRequired: boolean; windowRequired: boolean; windowOpen: boolean; hasPrivateKey: boolean
  targets: PlannedTarget[]; environments: string[]; warnings: string[]; blockers: string[]
}

/** Impact preview before a deployment is committed (NFR-008). */
function DeploymentPlanView({ plan }: { plan: DeploymentPlan }) {
  return (
    <div className="plan-box">
      <h4>Impact preview</h4>
      <dl className="kv">
        <dt>Certificate</dt><dd>{plan.certificate}</dd>
        <dt>New thumbprint</dt><dd><code className="small">{plan.newThumbprint}</code></dd>
        <dt>Valid until</dt><dd>{new Date(plan.newNotAfter).toLocaleDateString()}</dd>
        <dt>Execution</dt>
        <dd>
          {plan.strategy}
          {plan.maxConcurrency > 0 ? ` · ${plan.maxConcurrency} at a time` : ' · all at once'}
          {plan.stopOnFailure ? ' · stops on first failure' : ' · continues past failures'}
          {plan.manualContinuation && ' · pauses between waves'}
        </dd>
        <dt>Environments</dt><dd>{plan.environments.join(', ') || '—'}</dd>
        <dt>Governance</dt>
        <dd>
          {plan.approvalRequired ? 'approval required' : 'no approval required'}
          {plan.windowRequired && (plan.windowOpen ? ' · maintenance window open' : ' · outside maintenance window')}
        </dd>
      </dl>

      {plan.blockers.length > 0 && (
        <div className="alert-list">
          {plan.blockers.map((b, i) => <div key={i} className="alert-row critical">{b}</div>)}
        </div>
      )}
      {plan.warnings.length > 0 && (
        <div className="alert-list">
          {plan.warnings.map((w, i) => <div key={i} className="alert-row warning">{w}</div>)}
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr><th>#</th><th>Target</th><th>Store</th><th>Runner</th><th>Serving today</th></tr>
        </thead>
        <tbody>
          {plan.targets.map((t, i) => (
            <tr key={t.bindingId}>
              <td className="small muted">{i + 1}</td>
              <td>
                {t.target} <span className="tag">{t.adapter}</span>
                <div className="muted small">
                  {t.environment ?? 'no environment'}{t.haRole && ` · HA ${t.haRole}`}
                </div>
              </td>
              <td className="small muted">{t.store}{t.alias && ` (${t.alias})`}</td>
              <td className="small">
                {t.runnerName ?? 'control plane'}
                <div className={t.runnerStatus === 'Online' ? 'ok' : 'bad'}>{t.runnerStatus}</div>
              </td>
              <td className="small muted">
                {t.currentThumbprint
                  ? <>{t.currentCommonName}<div><code>{t.currentThumbprint.slice(0, 16)}…</code> · {t.currentDaysLeft} days left</div></>
                  : 'unknown'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

interface StoredArtifact {
  id: string; kind: string; sensitivity: string; fileName: string; sizeBytes: number
  sha256: string; storageProvider: string; expiresAt: string | null
  createdBy: string | null; createdAt: string; purgedAt: string | null; purgeReason: string | null
}

const CONVERT_TARGETS = ['pem', 'der', 'p7b', 'pfx', 'jks', 'chain', 'fullchain'] as const

/**
 * Stored artifacts (§31) plus the format engine (§15.2): everything RemoteSSL keeps for this
 * certificate, and a converter that can hand the result back or store it as a classified,
 * envelope-encrypted artifact with a TTL.
 */
function ArtifactsPanel({ versionId }: { versionId: string | undefined }) {
  const [stored, setStored] = useState<StoredArtifact[]>([])
  const [to, setTo] = useState<string>('pfx')
  const [password, setPassword] = useState('')
  const [alias, setAlias] = useState('remotessl')
  const [keep, setKeep] = useState(true)
  const [message, setMessage] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    if (!versionId) return
    apiGet<StoredArtifact[]>(`/api/v1/artifacts/stored?certificateVersionId=${versionId}`)
      .then(setStored).catch(() => setStored([]))
  }, [versionId])
  useEffect(load, [load])

  const needsPassword = ['pfx', 'p12', 'jks'].includes(to)

  async function convert() {
    setBusy(true); setMessage(null)
    try {
      if (!versionId) { setMessage('No version to convert.'); return }
      // The API reads the stored PEM (and key, when it holds one) for this version, so no
      // certificate material needs to travel to the browser and back.
      const res = await apiPost('/api/v1/artifacts/convert', {
        to,
        certificateVersionId: versionId,
        password: needsPassword ? password : null,
        alias,
        store: keep,
      })
      const body = await res.json()
      if (!res.ok) { setMessage(body.title ?? `Conversion failed (${res.status})`); return }
      setMessage(keep
        ? `Stored as ${body.fileName} (${body.sensitivity}${body.expiresAt ? `, expires ${new Date(body.expiresAt).toLocaleString()}` : ''}).`
        : `Converted (${body.contentType}); ${Math.ceil((body.contentBase64.length * 3) / 4)} bytes returned inline.`)
      load()
    } finally { setBusy(false) }
  }

  return (
    <>
      <h3>Convert</h3>
      <div className="deploy-box">
        <div className="small">
          Format:{' '}
          <select value={to} onChange={(e) => setTo(e.target.value)}>
            {CONVERT_TARGETS.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          {needsPassword && (
            <> password: <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" style={{ width: 140 }} /></>
          )}
          {to === 'jks' && (
            <> alias: <input value={alias} onChange={(e) => setAlias(e.target.value)} style={{ width: 120 }} /></>
          )}
        </div>
        <label className="small">
          <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} />{' '}
          store the result (encrypted, with a TTL when it carries a key)
        </label>
        <button onClick={convert} disabled={busy || (needsPassword && !password)}>
          {busy ? 'Converting…' : 'Convert'}
        </button>
        {message && <span className="small">{message}</span>}
      </div>

      <h3>Stored artifacts</h3>
      <table className="data-table">
        <thead><tr><th>File</th><th>Kind</th><th>Class</th><th>Storage</th><th>Expires</th><th>Created</th><th></th></tr></thead>
        <tbody>
          {stored.map((a) => (
            <tr key={a.id}>
              <td>
                {a.fileName}
                <div className="muted small">{a.sizeBytes} bytes · <code>{a.sha256.slice(0, 16)}…</code></div>
              </td>
              <td className="small">{a.kind}</td>
              <td className="small">
                <span className={a.sensitivity === 'Public' ? 'muted' : 'warn'}>{a.sensitivity}</span>
              </td>
              <td className="small muted">{a.storageProvider}</td>
              <td className="small muted">{a.expiresAt ? new Date(a.expiresAt).toLocaleString() : '—'}</td>
              <td className="small muted">{new Date(a.createdAt).toLocaleString()}</td>
              <td className="actions">
                {a.purgedAt
                  ? <span className="muted small">purged — {a.purgeReason}</span>
                  : a.sensitivity === 'Public'
                    ? <a className="link-button" href={`${API_BASE}/api/v1/artifacts/stored/${a.id}/download`}>Download</a>
                    : <span className="muted small">key material — not downloadable</span>}
              </td>
            </tr>
          ))}
          {stored.length === 0 && <tr><td colSpan={7} className="muted">No stored artifacts for this version.</td></tr>}
        </tbody>
      </table>
    </>
  )
}

export default function Certificates() {
  const { t } = useTranslation()
  const [certs, setCerts] = useState<CertificateListItem[]>([])
  const [selected, setSelected] = useState<CertificateDetail | null>(null)
  const [tab, setTab] = useState<Tab>('Overview')

  const [bindings, setBindings] = useState<{ id: string; target: string; adapter: string; store: string }[]>([])
  const [selectedBindings, setSelectedBindings] = useState<string[]>([])
  const [deployVersion, setDeployVersion] = useState('')
  const [deployMsg, setDeployMsg] = useState<string | null>(null)
  const [needApproval, setNeedApproval] = useState(false)
  const [strategy, setStrategy] = useState('sequential')
  const [maxConcurrency, setMaxConcurrency] = useState('2')
  const [plan, setPlan] = useState<DeploymentPlan | null>(null)
  const [planning, setPlanning] = useState(false)

  function reload() {
    apiGet<CertificateListItem[]>('/api/v1/certificates').then(setCerts).catch(() => {})
  }
  useEffect(reload, [])

  function open(id: string) {
    setDeployMsg(null); setTab('Overview')
    apiGet<CertificateDetail>(`/api/v1/certificates/${id}`).then((d) => {
      setSelected(d)
      setDeployVersion(d.versions[0]?.id ?? '')
    }).catch(() => {})
    apiGet<{ id: string; target: string; adapter: string; store: string }[]>(`/api/v1/certificates/${id}/bindings`)
      .then((b) => { setBindings(b); setSelectedBindings(b.map((x) => x.id)) })
      .catch(() => setBindings([]))
  }

  /** NFR-008: show what the deployment would change before it is committed. */
  async function preview() {
    setPlanning(true); setDeployMsg(null); setPlan(null)
    try {
      const res = await apiPost('/api/v1/deployments/plan', {
        certificateVersionId: deployVersion,
        bindingIds: selectedBindings,
        strategy,
        maxConcurrency: concurrencyFor(strategy),
        approvalRequired: needApproval,
      })
      const body = await res.json()
      if (!res.ok) { setDeployMsg(`Plan failed: ${body.title ?? res.status}`); return }
      setPlan(body)
    } finally { setPlanning(false) }
  }

  const concurrencyFor = (s: string) =>
    ['wave', 'parallel', 'canary'].includes(s) ? Number(maxConcurrency) : 0

  async function deploy() {
    setDeployMsg('creating job…')
    const res = await apiPost('/api/v1/deployments', {
      certificateVersionId: deployVersion,
      bindingIds: selectedBindings,
      requestedBy: 'ui',
      strategy,
      maxConcurrency: concurrencyFor(strategy),
      approvalRequired: needApproval,
      autoExecute: !needApproval,
    })
    const body = await res.json()
    setDeployMsg(res.ok
      ? (needApproval ? 'Job created — waiting for approval (see Approvals screen).' : 'Job started — follow it on the Deployments screen.')
      : `Failed: ${body.title ?? res.status}`)
  }

  async function rename() {
    if (!selected) return
    const name = window.prompt('Display name:', selected.displayName)
    if (!name) return
    await apiPatch(`/api/v1/certificates/${selected.id}`, { displayName: name })
    open(selected.id); reload()
  }

  /** FR-009 / §19.2: revoke the version at its CA, then mark it revoked in the inventory. */
  async function revoke(versionId: string) {
    const reason = window.prompt(
      'Revocation reason: Unspecified | KeyCompromise | Superseded | CessationOfOperation', 'Unspecified')
    if (!reason) return
    let res = await apiPost(`/api/v1/certificates/versions/${versionId}/revoke`, { reason, revokedBy: 'ui' })
    if (!res.ok) {
      // Manual/offline CAs are revoked in their own interface; offer to record that here (§18.4).
      const problem = await res.json()
      if (!window.confirm(`${problem.title ?? `Revoke failed (${res.status})`}\n\nRecord it as revoked anyway?`)) return
      res = await apiPost(`/api/v1/certificates/versions/${versionId}/revoke`,
        { reason, revokedBy: 'ui', recordOnly: true })
      if (!res.ok) { alert((await res.json()).title ?? `Revoke failed (${res.status})`); return }
    }
    if (selected) open(selected.id)
    reload()
  }

  async function removeCert() {
    if (!selected || !window.confirm(`Delete certificate '${selected.commonName}' from the inventory?`)) return
    const res = await apiDelete(`/api/v1/certificates/${selected.id}`)
    if (!res.ok) { alert('Delete failed: ' + ((await res.json()).title ?? res.status)); return }
    setSelected(null); reload()
  }

  return (
    <div className="page">
      <h1>{t('nav.certificates')}</h1>
      {/* Inventory columns per design doc §26.1 */}
      <table className="data-table">
        <thead>
          <tr>
            <th>Certificate</th><th>Expiry</th><th>CA</th><th>Managed</th>
            <th>Deployments</th><th>Auto renew</th><th>Status</th><th>Monitors</th>
          </tr>
        </thead>
        <tbody>
          {certs.map((c) => (
            <tr key={c.id} className="clickable" onClick={() => open(c.id)}>
              <td>
                {c.commonName}
                {c.environment && <span className="tag muted">{c.environment}</span>}
              </td>
              <td>
                {c.daysUntilExpiry !== null
                  ? <span className={healthClass(c.health)}>{c.daysUntilExpiry} {t('monitors.days')}</span>
                  : '—'}
                {c.notAfter && <div className="muted small">{new Date(c.notAfter).toLocaleDateString()}</div>}
              </td>
              <td className="small">{c.ca ?? '—'}</td>
              <td>{c.managed ? <span className="ok">Yes</span> : <span className="muted">No</span>}</td>
              <td>{c.deploymentCount || '—'}</td>
              <td>{c.autoRenew ? <span className="ok">Yes</span> : <span className="muted">No</span>}</td>
              <td><span className={healthClass(c.health)}>{c.health}</span></td>
              <td>{c.monitorCount}</td>
            </tr>
          ))}
          {certs.length === 0 && <tr><td colSpan={8} className="muted">{t('certificates.empty')}</td></tr>}
        </tbody>
      </table>

      {selected && (
        <div className="detail-panel">
          <div className="detail-header">
            <h2>
              {selected.commonName}{' '}
              <span className={healthClass(selected.health)}>{selected.health}</span>
            </h2>
            <div className="actions">
              <button onClick={rename}>Rename</button>
              <button className="danger" onClick={removeCert}>Delete</button>
              <button onClick={() => setSelected(null)}>{t('common.close')}</button>
            </div>
          </div>

          <div className="tab-bar">
            {TABS.map((x) => (
              <button key={x} className={tab === x ? 'tab active' : 'tab'} onClick={() => setTab(x)}>{x}</button>
            ))}
          </div>

          {tab === 'Overview' && (
            <div className="tab-body">
              <dl className="kv">
                <dt>Common name</dt><dd>{selected.commonName}</dd>
                <dt>Display name</dt><dd>{selected.displayName}</dd>
                <dt>SAN</dt><dd>{selected.overview.sans.join(', ') || '—'}</dd>
                <dt>CA</dt><dd>{selected.overview.ca ?? '—'}</dd>
                <dt>Issuer DN</dt><dd className="small">{selected.overview.issuerDn ?? '—'}</dd>
                <dt>Expires</dt>
                <dd>
                  {selected.overview.notAfter ? new Date(selected.overview.notAfter).toLocaleDateString() : '—'}
                  {selected.overview.daysUntilExpiry !== null && ` (${selected.overview.daysUntilExpiry} days)`}
                </dd>
                <dt>Environment</dt><dd>{selected.overview.environment ?? '—'}</dd>
                <dt>Owner</dt><dd>{selected.overview.ownerId ?? '—'}</dd>
                <dt>Managed</dt><dd>{selected.overview.managed ? `Yes — ${selected.overview.deploymentCount} binding(s)` : 'No'}</dd>
                <dt>Auto renew</dt><dd>{selected.overview.autoRenew ? 'Yes' : 'No'}</dd>
                <dt>Monitors</dt><dd>{selected.overview.monitorCount}</dd>
                <dt>Versions</dt><dd>{selected.versions.length}</dd>
              </dl>

              <h3>Versions</h3>
              {selected.versions.map((v) => (
                <div key={v.id} className="version-card">
                  <div><strong>Serial:</strong> {v.serialNumber} <span className={`tag ${v.status === 'Superseded' ? 'muted' : 'ok'}`}>{v.status}</span></div>
                  <div><strong>SHA-256:</strong> <code className="small">{v.sha256Thumbprint}</code></div>
                  <div><strong>Validity:</strong> {new Date(v.notBefore).toLocaleDateString()} → {new Date(v.notAfter).toLocaleDateString()} ({v.daysUntilExpiry} days)</div>
                  <div><strong>Key:</strong> {v.publicKeyAlgorithm} {v.keySize} / {v.signatureAlgorithm}</div>
                  {v.sans.length > 0 && <div><strong>SAN:</strong> {v.sans.join(', ')}</div>}
                  {v.status !== 'Revoked' && (
                    <button className="danger" style={{ marginTop: 6 }} onClick={() => revoke(v.id)}>
                      Revoke at CA
                    </button>
                  )}
                </div>
              ))}

              <h3>Deploy</h3>
              {bindings.length === 0 ? (
                <p className="muted small">No deployment bindings. Create a store + binding under Managed Targets first.</p>
              ) : (
                <div className="deploy-box">
                  <select value={deployVersion} onChange={(e) => setDeployVersion(e.target.value)}>
                    {selected.versions.map((v) => (
                      <option key={v.id} value={v.id}>{v.serialNumber.slice(0, 16)}… ({v.status}, {v.daysUntilExpiry}d left)</option>
                    ))}
                  </select>
                  {bindings.map((b) => (
                    <label key={b.id} className="small" style={{ display: 'block' }}>
                      <input type="checkbox" checked={selectedBindings.includes(b.id)}
                        onChange={(e) => setSelectedBindings(e.target.checked
                          ? [...selectedBindings, b.id] : selectedBindings.filter((x) => x !== b.id))} />
                      {' '}{b.target} ({b.adapter}) — {b.store}
                    </label>
                  ))}
                  <div className="small">
                    Strategy:{' '}
                    <select value={strategy} onChange={(e) => { setStrategy(e.target.value); setPlan(null) }}>
                      <option value="sequential">Sequential (one at a time)</option>
                      <option value="wave">Wave (N at a time, stop on failure)</option>
                      <option value="parallel">Parallel (N at a time)</option>
                      <option value="all-at-once">All at once</option>
                      <option value="canary">Canary (N first, then continue manually)</option>
                      <option value="manual">Manual (continue every wave by hand)</option>
                      <option value="ha-pair">HA pair (standby member first)</option>
                    </select>
                    {['wave', 'parallel', 'canary'].includes(strategy) && (
                      <> concurrency: <input value={maxConcurrency} onChange={(e) => setMaxConcurrency(e.target.value)}
                        type="number" min={1} style={{ width: 60 }} /></>
                    )}
                  </div>
                  <label className="small"><input type="checkbox" checked={needApproval} onChange={(e) => setNeedApproval(e.target.checked)} /> require approval</label>
                  <div className="actions">
                    <button onClick={preview} disabled={planning || !deployVersion || selectedBindings.length === 0}>
                      {planning ? 'Planning…' : 'Preview impact'}
                    </button>
                    <button onClick={deploy}
                            disabled={!deployVersion || selectedBindings.length === 0 || (plan?.blockers.length ?? 0) > 0}>
                      Deploy
                    </button>
                  </div>
                  {deployMsg && <span className="small">{deployMsg}</span>}
                  {plan && <DeploymentPlanView plan={plan} />}
                </div>
              )}
            </div>
          )}

          {tab === 'Lifecycle' && (
            <div className="tab-body">
              <table className="data-table">
                <thead><tr><th>When</th><th>Stage</th><th>Detail</th><th>Actor</th></tr></thead>
                <tbody>
                  {selected.lifecycle.map((e, i) => (
                    <tr key={i}>
                      <td className="small muted">{new Date(e.at).toLocaleString()}</td>
                      <td>{e.stage}</td>
                      <td className="small">{e.detail}</td>
                      <td className="small">{e.actor ?? '—'}</td>
                    </tr>
                  ))}
                  {selected.lifecycle.length === 0 && <tr><td colSpan={4} className="muted">No lifecycle events yet.</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'Deployments' && (
            <div className="tab-body">
              <table className="data-table">
                <thead><tr><th>Status</th><th>Strategy</th><th>Targets</th><th>Requested</th><th>Approved</th><th>Created</th><th>Completed</th></tr></thead>
                <tbody>
                  {selected.deployments.map((d) => (
                    <tr key={d.jobId}>
                      <td><span className={d.status === 'Succeeded' ? 'ok' : d.status === 'Running' ? 'warn' : 'bad'}>{d.status}</span></td>
                      <td className="small">{d.strategy}</td>
                      <td>{d.failedTargets > 0 ? <span className="bad">{d.failedTargets}/{d.targetCount} failed</span> : `${d.targetCount}`}</td>
                      <td className="small">{d.requestedBy ?? '—'}</td>
                      <td className="small">{d.approvedBy ?? '—'}</td>
                      <td className="small muted">{new Date(d.createdAt).toLocaleString()}</td>
                      <td className="small muted">{d.completedAt ? new Date(d.completedAt).toLocaleString() : '—'}</td>
                    </tr>
                  ))}
                  {selected.deployments.length === 0 && <tr><td colSpan={7} className="muted">Never deployed.</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'Certificate Stores' && (
            <div className="tab-body">
              <table className="data-table">
                <thead><tr><th>Target</th><th>Adapter</th><th>Store</th><th>Alias</th><th>Service binding</th></tr></thead>
                <tbody>
                  {selected.stores.map((s) => (
                    <tr key={s.bindingId}>
                      <td>{s.target}</td><td>{s.adapter}</td>
                      <td className="small">{s.storeType} — {s.storePath}</td>
                      <td className="small">{s.alias ?? '—'}</td>
                      <td className="small muted">{s.serviceBindingJson}</td>
                    </tr>
                  ))}
                  {selected.stores.length === 0 && <tr><td colSpan={5} className="muted">Not bound to any certificate store.</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'Monitoring' && (
            <div className="tab-body">
              <table className="data-table">
                <thead><tr><th>Endpoint</th><th>SNI</th><th>Last seen</th></tr></thead>
                <tbody>
                  {selected.monitors.map((m) => (
                    <tr key={m.monitorId}>
                      <td>{m.host}:{m.port}</td>
                      <td className="small">{m.sni ?? '—'}</td>
                      <td className="small muted">{new Date(m.lastSeenAt).toLocaleString()}</td>
                    </tr>
                  ))}
                  {selected.monitors.length === 0 && <tr><td colSpan={3} className="muted">No monitor observes this certificate.</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'Renewal' && (
            <div className="tab-body">
              {selected.renewal ? (
                <dl className="kv">
                  <dt>Policy</dt><dd>{selected.renewal.name} {selected.renewal.enabled ? <span className="ok">(enabled)</span> : <span className="muted">(disabled)</span>}</dd>
                  <dt>Trigger</dt><dd>T-{selected.renewal.triggerDays} days</dd>
                  <dt>Next trigger in</dt>
                  <dd>{selected.renewal.daysUntilTrigger !== null
                    ? <span className={selected.renewal.daysUntilTrigger <= 0 ? 'warn' : ''}>{selected.renewal.daysUntilTrigger} days</span>
                    : '—'}</dd>
                  <dt>Key rotation</dt><dd>{selected.renewal.rotateKey ? 'Rotate key on renewal' : 'Reuse key'}</dd>
                  <dt>Auto deploy</dt><dd>{selected.renewal.autoDeploy ? 'Yes' : 'No'}</dd>
                  <dt>Approval</dt><dd>{selected.renewal.approvalRequired ? 'Required' : 'Not required'}</dd>
                  <dt>Maintenance window</dt><dd className="small">{selected.renewal.maintenanceWindowJson ?? 'anytime'}</dd>
                  <dt>CA connector</dt><dd>{selected.renewal.caConnector ?? '— (manual)'}</dd>
                </dl>
              ) : (
                <p className="muted">No renewal policy assigned. Attach one on the Policies screen to automate renewal.</p>
              )}
            </div>
          )}

          {tab === 'Files / Artifacts' && (
            <div className="tab-body">
              <p className="muted small">Private key material is never downloadable through the API (design doc §7.3 / §22.3).</p>
              <table className="data-table">
                <thead><tr><th>Kind</th><th>Description</th><th>Created</th><th></th></tr></thead>
                <tbody>
                  {selected.artifacts.map((a, i) => (
                    <tr key={i}>
                      <td>{a.kind}</td>
                      <td className="small">{a.description}</td>
                      <td className="small muted">{new Date(a.createdAt).toLocaleString()}</td>
                      <td className="actions">
                        {(a.kind === 'certificate' || a.kind === 'chain') && a.versionId && (
                          <>
                            <a className="link-button" href={`${API_BASE}/api/v1/certificates/versions/${a.versionId}/download?kind=${a.kind === 'chain' ? 'chain' : 'crt'}`}>Download</a>
                            {a.kind === 'certificate' && (
                              <a className="link-button" href={`${API_BASE}/api/v1/certificates/versions/${a.versionId}/download?kind=fullchain`}>Fullchain</a>
                            )}
                          </>
                        )}
                        {a.hasPrivateKey && <span className="muted small">held encrypted</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <ArtifactsPanel versionId={selected.versions[0]?.id} />
            </div>
          )}

          {tab === 'Approvals' && (
            <div className="tab-body">
              <table className="data-table">
                <thead><tr><th>Status</th><th>Requested by</th><th>Decided by</th><th>Reason</th><th>Created</th><th>Decided</th></tr></thead>
                <tbody>
                  {selected.approvals.map((a) => (
                    <tr key={a.id}>
                      <td><span className={a.status === 'Approved' ? 'ok' : a.status === 'Rejected' ? 'bad' : 'warn'}>{a.status}</span></td>
                      <td className="small">{a.requestedBy ?? '—'}</td>
                      <td className="small">{a.decidedBy ?? '—'}</td>
                      <td className="small">{a.reason ?? '—'}</td>
                      <td className="small muted">{new Date(a.createdAt).toLocaleString()}</td>
                      <td className="small muted">{a.decidedAt ? new Date(a.decidedAt).toLocaleString() : '—'}</td>
                    </tr>
                  ))}
                  {selected.approvals.length === 0 && <tr><td colSpan={6} className="muted">No approval ever requested for this certificate.</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'History / Audit' && (
            <div className="tab-body">
              <table className="data-table">
                <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Result</th><th>Details</th></tr></thead>
                <tbody>
                  {selected.history.map((e) => (
                    <tr key={e.id}>
                      <td className="small muted">{new Date(e.timestamp).toLocaleString()}</td>
                      <td className="small">{e.actor}</td>
                      <td>{e.action}</td>
                      <td><span className={/FAIL|MISMATCH|DRIFT/.test(e.result) ? 'bad' : 'ok'}>{e.result}</span></td>
                      <td className="small muted" style={{ maxWidth: 380, wordBreak: 'break-all' }}>{e.detailsJson}</td>
                    </tr>
                  ))}
                  {selected.history.length === 0 && <tr><td colSpan={5} className="muted">No audit events yet.</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

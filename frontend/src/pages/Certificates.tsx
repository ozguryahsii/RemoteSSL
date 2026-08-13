import { useEffect, useState } from 'react'
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

  async function deploy() {
    setDeployMsg('creating job…')
    const res = await apiPost('/api/v1/deployments', {
      certificateVersionId: deployVersion,
      bindingIds: selectedBindings,
      requestedBy: 'ui',
      strategy,
      maxConcurrency: strategy === 'wave' || strategy === 'parallel' ? Number(maxConcurrency) : 0,
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
                    <select value={strategy} onChange={(e) => setStrategy(e.target.value)}>
                      <option value="sequential">Sequential (one at a time)</option>
                      <option value="wave">Wave (N at a time, stop on failure)</option>
                      <option value="parallel">Parallel (N at a time)</option>
                      <option value="all-at-once">All at once</option>
                    </select>
                    {(strategy === 'wave' || strategy === 'parallel') && (
                      <> concurrency: <input value={maxConcurrency} onChange={(e) => setMaxConcurrency(e.target.value)}
                        type="number" min={1} style={{ width: 60 }} /></>
                    )}
                  </div>
                  <label className="small"><input type="checkbox" checked={needApproval} onChange={(e) => setNeedApproval(e.target.checked)} /> require approval</label>
                  <button onClick={deploy} disabled={!deployVersion || selectedBindings.length === 0}>Deploy</button>
                  {deployMsg && <span className="small" style={{ marginLeft: 8 }}>{deployMsg}</span>}
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

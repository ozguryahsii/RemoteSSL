import { useEffect, useState } from 'react'
import { apiGet, apiPost } from '../api/client'

/**
 * Installing a certificate on a machine touches four things — a server, a store on it, a binding
 * between that store and the certificate, and finally the installation job. Each had its own
 * screen, none of them said they were steps of one task, and nothing told you the order. Someone
 * who wanted to put a certificate on a server had to already know the model to find the path
 * through it.
 *
 * This walks the same four steps in order, creating whatever is missing as it goes, and finishes
 * on the impact preview so nobody installs into production without seeing what changes. It calls
 * exactly the endpoints the individual screens call — it is a route through the product, not a
 * second way to do it.
 */

interface CertificateOption {
  id: string
  commonName: string
  daysUntilExpiry: number | null
  health: string
  installedOn: string[]
}

interface StoreOption { id: string; storeType: string; storePath: string; alias: string | null }
interface TargetOption {
  id: string
  name: string
  adapterType: string
  environment: string | null
  stores: StoreOption[]
}

interface AdapterField {
  key: string
  label: string
  help: string | null
  required: boolean
  options: string[] | null
  default: string | null
}

interface Adapter {
  type: string
  displayName: string
  category: string
  channel: string
  requiresPrivateKey: boolean
  supportsAlias: boolean
  connectionFields: AdapterField[]
  serviceFields: AdapterField[]
  notes: string | null
}

interface CredentialOption { id: string; name: string; credentialType: string }

interface PlannedTarget {
  target: string
  adapter: string
  store: string
  runnerStatus: string
  currentCommonName: string | null
  currentDaysLeft: number | null
}

interface Plan {
  certificate: string
  newThumbprint: string
  strategy: string
  approvalRequired: boolean
  windowRequired: boolean
  windowOpen: boolean
  hasPrivateKey: boolean
  targets: PlannedTarget[]
  warnings: string[]
  blockers: string[]
}

const STEPS = ['Certificate', 'Server', 'Where on the server', 'Review & install'] as const

export default function InstallWizard({ onClose, onInstalled }: { onClose: () => void; onInstalled: () => void }) {
  const [step, setStep] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [certificates, setCertificates] = useState<CertificateOption[]>([])
  const [targets, setTargets] = useState<TargetOption[]>([])
  const [adapters, setAdapters] = useState<Adapter[]>([])
  const [credentials, setCredentials] = useState<CredentialOption[]>([])

  const [certificateId, setCertificateId] = useState('')

  // Step 2 — an existing server, or a new one described here.
  const [targetId, setTargetId] = useState('')
  const [newServer, setNewServer] = useState(false)
  const [name, setName] = useState('')
  const [adapterType, setAdapterType] = useState('nginx')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [environment, setEnvironment] = useState('')
  const [credentialId, setCredentialId] = useState('')

  // Step 3 — an existing store on that server, or a new path plus the adapter's service fields.
  const [storeId, setStoreId] = useState('')
  const [newStore, setNewStore] = useState(false)
  const [storePath, setStorePath] = useState('')
  const [alias, setAlias] = useState('')
  const [service, setService] = useState<Record<string, string>>({})

  const [plan, setPlan] = useState<Plan | null>(null)
  const [bindingId, setBindingId] = useState('')
  const [done, setDone] = useState<string | null>(null)

  useEffect(() => {
    apiGet<CertificateOption[]>('/api/v1/certificates?take=500').then(setCertificates).catch(() => {})
    apiGet<TargetOption[]>('/api/v1/targets?take=500').then(setTargets).catch(() => {})
    apiGet<Adapter[]>('/api/v1/adapters').then(setAdapters).catch(() => {})
    apiGet<CredentialOption[]>('/api/v1/credentials').then(setCredentials).catch(() => {})
  }, [])

  const adapter = adapters.find((a) => a.type === adapterType)
  const target = targets.find((t) => t.id === targetId)
  // A server that already exists brings its own adapter; only a new one is being chosen here.
  const effectiveAdapter = newServer ? adapter : adapters.find((a) => a.type === target?.adapterType)

  /** Service fields start from whatever defaults the adapter declares. */
  function adapterDefaults(a: Adapter | undefined): Record<string, string> {
    const next: Record<string, string> = {}
    for (const f of a?.serviceFields ?? []) if (f.default) next[f.key] = f.default
    return next
  }

  useEffect(() => { setService(adapterDefaults(effectiveAdapter)) }, [effectiveAdapter?.type])

  /**
   * Picking a location that is already in use prefills the paths and commands from a binding that
   * already lives there. Those are the values this adapter really uses on this machine — far
   * better than an empty form, and better than guessing a convention that may not be the one in
   * use here.
   */
  useEffect(() => {
    if (newStore || !storeId || !targetId) return
    let cancelled = false
    apiGet<{ storeId: string; serviceBindingJson: string }[]>(`/api/v1/targets/${targetId}/bindings`)
      .then((rows) => {
        if (cancelled) return
        const sibling = rows.find((b) => b.storeId === storeId)
        if (!sibling) return
        try {
          const existing = JSON.parse(sibling.serviceBindingJson || '{}') as Record<string, unknown>
          const next = { ...adapterDefaults(effectiveAdapter) }
          for (const [k, v] of Object.entries(existing)) {
            if (typeof v === 'string' || typeof v === 'number') next[k] = String(v)
          }
          setService(next)
        } catch { /* a malformed binding is not worth breaking the form over */ }
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [storeId, newStore, targetId, effectiveAdapter?.type])

  async function ensureServer(): Promise<string> {
    if (!newServer) return targetId
    const res = await apiPost('/api/v1/targets', {
      name,
      targetType: effectiveAdapter?.channel === 'winrm' ? 'WindowsServer'
        : effectiveAdapter?.channel === 'rest' ? 'NetworkDevice' : 'LinuxServer',
      adapterType,
      environment: environment || null,
      connectionConfig: { host, port: Number(port) },
      credentialRefId: credentialId || null,
      runnerId: null,
    })
    const body = await res.json()
    if (!res.ok) throw new Error(body.title ?? `The server could not be created (${res.status})`)
    return body.id as string
  }

  async function ensureStore(server: string): Promise<string> {
    if (!newStore) return storeId
    const res = await apiPost(`/api/v1/targets/${server}/stores`, {
      storeType: effectiveAdapter?.channel === 'winrm' ? 'windows-my' : 'pem-file',
      storePath,
      alias: alias || null,
      config: {},
    })
    const body = await res.json()
    if (!res.ok) throw new Error(body.title ?? `The store could not be created (${res.status})`)
    return body.id as string
  }

  /** Reuses the binding when this certificate is already bound to this store. */
  async function ensureBinding(server: string, store: string): Promise<string> {
    const existing = await apiGet<{ id: string; certificateId: string; storeId: string }[]>(
      `/api/v1/targets/${server}/bindings`).catch(() => [])
    const match = existing.find((b) => b.certificateId === certificateId && b.storeId === store)
    if (match) return match.id

    const res = await apiPost(`/api/v1/targets/stores/${store}/bindings`, {
      certificateId,
      serviceBinding: service,
      activationPolicy: {},
    })
    const body = await res.json()
    if (!res.ok) throw new Error(body.title ?? `The binding could not be created (${res.status})`)
    return body.id as string
  }

  /** Creates whatever is missing, then previews the impact — nothing is installed yet. */
  async function prepareReview() {
    setBusy(true); setError(null)
    try {
      const server = await ensureServer()
      const store = await ensureStore(server)
      const binding = await ensureBinding(server, store)
      setBindingId(binding)

      const versionId = await activeVersionOf(certificateId)
      const res = await apiPost('/api/v1/deployments/plan', {
        certificateVersionId: versionId,
        bindingIds: [binding],
        strategy: 'sequential',
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.title ?? `The plan could not be produced (${res.status})`)
      setPlan(body)
      setStep(3)
      // The lists are stale now that a server or store may have been created.
      apiGet<TargetOption[]>('/api/v1/targets?take=500').then(setTargets).catch(() => {})
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  async function activeVersionOf(id: string): Promise<string> {
    const detail = await apiGet<{ versions: { id: string; status: string; notAfter: string }[] }>(
      `/api/v1/certificates/${id}`)
    const usable = (detail.versions ?? [])
      .filter((v) => v.status === 'Active' || v.status === 'Issued')
      .sort((a, b) => new Date(b.notAfter).getTime() - new Date(a.notAfter).getTime())[0]
    if (!usable) throw new Error('This certificate has no active or issued version to install.')
    return usable.id
  }

  async function install() {
    setBusy(true); setError(null)
    try {
      const versionId = await activeVersionOf(certificateId)
      const res = await apiPost('/api/v1/deployments', {
        certificateVersionId: versionId,
        bindingIds: [bindingId],
        strategy: 'sequential',
        requestedBy: 'ui',
        approvalRequired: plan?.approvalRequired ?? false,
        autoExecute: !(plan?.approvalRequired ?? false),
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.title ?? `The installation could not be started (${res.status})`)
      setDone(plan?.approvalRequired
        ? `Job ${body.id} created and is waiting for approval.`
        : `Job ${body.id} started.`)
      onInstalled()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  const canContinue =
    step === 0 ? certificateId !== ''
      : step === 1 ? (newServer ? name !== '' && host !== '' : targetId !== '')
        : step === 2 ? (newStore ? storePath !== '' : storeId !== '')
          : false

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal wizard" onClick={(e) => e.stopPropagation()}>
        <div className="detail-header">
          <h2>Install a certificate on a server</h2>
          <button onClick={onClose}>Close</button>
        </div>

        <ol className="wizard-steps">
          {STEPS.map((label, i) => (
            <li key={label} className={i === step ? 'current' : i < step ? 'done' : ''}>
              <span className="wizard-step-no">{i + 1}</span> {label}
            </li>
          ))}
        </ol>

        {error && <p className="bad small">{error}</p>}

        {done ? (
          <>
            <p className="ok">{done}</p>
            <p className="muted small">Follow it on the Installations screen.</p>
            <div className="actions"><button onClick={onClose}>Done</button></div>
          </>
        ) : (
          <>
            {step === 0 && (
              <>
                <p className="muted small">Which certificate should end up on the server?</p>
                <select value={certificateId} onChange={(e) => setCertificateId(e.target.value)}>
                  <option value="">select a certificate…</option>
                  {certificates.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.commonName}
                      {c.daysUntilExpiry !== null ? ` — ${c.daysUntilExpiry} days left` : ''}
                      {c.installedOn.length > 0 ? ` — already on ${c.installedOn.join(', ')}` : ''}
                    </option>
                  ))}
                </select>
                {certificates.length === 0 && (
                  <p className="warn small">
                    There are no certificates yet. Request one under “Requests &amp; CSRs”, or add a
                    monitored endpoint so RemoteSSL discovers the one already in use.
                  </p>
                )}
              </>
            )}

            {step === 1 && (
              <>
                <p className="muted small">Which machine is it going on?</p>
                <div className="actions">
                  <button className={!newServer ? 'chosen' : ''} onClick={() => setNewServer(false)}>
                    A server I already added
                  </button>
                  <button className={newServer ? 'chosen' : ''} onClick={() => setNewServer(true)}>
                    A new server
                  </button>
                </div>

                {!newServer ? (
                  <>
                    <select value={targetId} onChange={(e) => { setTargetId(e.target.value); setStoreId('') }}>
                      <option value="">select a server…</option>
                      {targets.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.name} — {t.adapterType}{t.environment ? ` · ${t.environment}` : ''}
                        </option>
                      ))}
                    </select>
                    {targets.length === 0 && <p className="warn small">No servers added yet — choose “A new server”.</p>}
                  </>
                ) : (
                  <div className="wizard-fields">
                    <label>Name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" /></label>
                    <label>What runs on it
                      <select value={adapterType} onChange={(e) => setAdapterType(e.target.value)}>
                        {adapters.map((a) => <option key={a.type} value={a.type}>{a.displayName} ({a.category})</option>)}
                      </select>
                    </label>
                    <label>Host / IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.5" /></label>
                    <label>Port<input value={port} onChange={(e) => setPort(e.target.value)} /></label>
                    <label>Environment<input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="PROD" /></label>
                    <label>Credential
                      <select value={credentialId} onChange={(e) => setCredentialId(e.target.value)}>
                        <option value="">no credential</option>
                        {credentials.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.credentialType})</option>)}
                      </select>
                    </label>
                    {adapter?.notes && <p className="muted small">{adapter.notes}</p>}
                    {credentials.length === 0 && (
                      <p className="warn small">
                        No credentials stored yet. RemoteSSL cannot reach the server without one — add it
                        under Setup → Credentials, then come back.
                      </p>
                    )}
                  </div>
                )}
              </>
            )}

            {step === 2 && (
              <>
                <p className="muted small">
                  Where on the machine should the certificate live, and what has to happen after it is written?
                </p>
                {!newServer && (target?.stores.length ?? 0) > 0 && (
                  <div className="actions">
                    <button className={!newStore ? 'chosen' : ''} onClick={() => setNewStore(false)}>An existing location</button>
                    <button className={newStore ? 'chosen' : ''} onClick={() => setNewStore(true)}>A new location</button>
                  </div>
                )}

                {!newServer && !newStore && (target?.stores.length ?? 0) > 0 ? (
                  <select value={storeId} onChange={(e) => setStoreId(e.target.value)}>
                    <option value="">select a location…</option>
                    {(target?.stores ?? []).map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.storeType}: {s.storePath}{s.alias ? ` (${s.alias})` : ''}
                      </option>
                    ))}
                  </select>
                ) : (
                  <div className="wizard-fields">
                    <label>Path
                      <input value={storePath} onChange={(e) => setStorePath(e.target.value)}
                        placeholder={effectiveAdapter?.channel === 'winrm' ? 'LocalMachine/My' : '/etc/nginx/ssl'} />
                    </label>
                    {effectiveAdapter?.supportsAlias && (
                      <label>Alias<input value={alias} onChange={(e) => setAlias(e.target.value)} /></label>
                    )}
                  </div>
                )}

                {/* §9.3: the fields come from the adapter, so this screen never asks for
                    something the adapter has no use for. */}
                <div className="wizard-fields">
                  {(effectiveAdapter?.serviceFields ?? []).map((f) => (
                    <label key={f.key}>
                      {f.label}{f.required && <span className="bad"> *</span>}
                      <input
                        value={service[f.key] ?? ''}
                        onChange={(e) => setService({ ...service, [f.key]: e.target.value })}
                      />
                      {f.help && <span className="muted small">{f.help}</span>}
                    </label>
                  ))}
                </div>
              </>
            )}

            {step === 3 && plan && (
              <>
                <p className="small">
                  <strong>{plan.certificate}</strong>{' '}
                  <span className="muted">{plan.newThumbprint.slice(0, 16)}…</span>
                </p>
                <table className="data-table">
                  <thead><tr><th>Server</th><th>Adapter</th><th>Location</th><th>Serving today</th><th>Runner</th></tr></thead>
                  <tbody>
                    {plan.targets.map((t, i) => (
                      <tr key={i}>
                        <td>{t.target}</td>
                        <td className="small">{t.adapter}</td>
                        <td className="small muted">{t.store}</td>
                        <td className="small">
                          {t.currentCommonName
                            ? <>{t.currentCommonName} <span className="muted">({t.currentDaysLeft} days)</span></>
                            : <span className="muted">nothing yet</span>}
                        </td>
                        <td className="small">{t.runnerStatus}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {plan.approvalRequired && (
                  <p className="warn small">
                    Policy requires approval for this environment — the job will be created and wait for an approver.
                  </p>
                )}
                {plan.windowRequired && !plan.windowOpen && (
                  <p className="warn small">Policy requires a maintenance window, and it is not open right now.</p>
                )}
                {plan.warnings.map((w, i) => <p key={i} className="warn small">{w}</p>)}
                {plan.blockers.length > 0 && (
                  <>
                    <h3>This cannot run yet</h3>
                    <ul className="step-list">
                      {plan.blockers.map((b, i) => <li key={i} className="bad">{b}</li>)}
                    </ul>
                  </>
                )}
              </>
            )}

            <div className="actions" style={{ marginTop: 16 }}>
              {step > 0 && <button onClick={() => setStep(step - 1)} disabled={busy}>Back</button>}
              {step < 2 && <button onClick={() => setStep(step + 1)} disabled={!canContinue || busy}>Continue</button>}
              {step === 2 && (
                <button onClick={prepareReview} disabled={!canContinue || busy}>
                  {busy ? 'Preparing…' : 'Review'}
                </button>
              )}
              {step === 3 && (
                <button onClick={install} disabled={busy || (plan?.blockers.length ?? 1) > 0}>
                  {busy ? 'Starting…' : 'Install'}
                </button>
              )}
            </div>

            {step === 2 && (
              <p className="muted small">
                Nothing is installed by “Review” — it creates the server and location records if they are
                new, then shows what the installation would change.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  )
}

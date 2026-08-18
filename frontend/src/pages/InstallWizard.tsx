import { useEffect, useState } from 'react'
import { apiGet, apiPost } from '../api/client'

/**
 * Putting one certificate on many machines is the ordinary case, not the advanced one: a wildcard
 * covers a whole estate, and when it is renewed every machine serving it has to be updated in the
 * same pass or the ones left behind quietly expire.
 *
 * Installing touches four records — a server, a store on it, a binding between that store and the
 * certificate, and the job. Each had its own screen, none said it was a step of one task, and
 * nothing stated the order. This walks the steps for as many servers as are selected at once,
 * creates whatever is missing, and ends on the impact preview. It calls exactly the endpoints the
 * individual screens call: a route through the product, not a second way to do it.
 */

interface CertificateOption {
  id: string
  commonName: string
  daysUntilExpiry: number | null
  health: string
  installedOn: { server: string; state: string }[]
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

interface BindingRow { id: string; certificateId: string; storeId: string; serviceBindingJson: string }

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

const STEPS = ['Certificate', 'Servers', 'Where on each server', 'Review & install'] as const

/** Strategies the orchestrator implements (§21.4), described in terms of what they do to you. */
const STRATEGIES = [
  { value: 'sequential', label: 'One server at a time (safest)' },
  { value: 'wave', label: 'A few at a time, stop if one fails' },
  { value: 'parallel', label: 'A few at a time, keep going' },
  { value: 'canary', label: 'One first, then continue by hand' },
  { value: 'ha-pair', label: 'HA pairs — standby member first' },
  { value: 'all-at-once', label: 'All at once' },
]

export default function InstallWizard({ onClose, onInstalled }: { onClose: () => void; onInstalled: () => void }) {
  const [step, setStep] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [certificates, setCertificates] = useState<CertificateOption[]>([])
  const [targets, setTargets] = useState<TargetOption[]>([])
  const [adapters, setAdapters] = useState<Adapter[]>([])
  const [credentials, setCredentials] = useState<CredentialOption[]>([])

  const [certificateId, setCertificateId] = useState('')

  // Step 2 — any number of existing servers, and optionally one new one described here.
  const [targetIds, setTargetIds] = useState<string[]>([])
  const [filter, setFilter] = useState('')
  const [newServer, setNewServer] = useState(false)
  const [name, setName] = useState('')
  const [adapterType, setAdapterType] = useState('nginx')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [environment, setEnvironment] = useState('')
  const [credentialId, setCredentialId] = useState('')

  // Step 3 — per server: which store, or a new path. Service settings are shared, and only used
  // where a server has no existing binding to copy the real paths from.
  const [storeByTarget, setStoreByTarget] = useState<Record<string, string>>({})
  const [pathByTarget, setPathByTarget] = useState<Record<string, string>>({})
  const [service, setService] = useState<Record<string, string>>({})

  const [strategy, setStrategy] = useState('sequential')
  const [maxConcurrency, setMaxConcurrency] = useState('2')

  const [plan, setPlan] = useState<Plan | null>(null)
  const [bindingIds, setBindingIds] = useState<string[]>([])
  const [done, setDone] = useState<string | null>(null)

  useEffect(() => {
    apiGet<CertificateOption[]>('/api/v1/certificates?take=500').then(setCertificates).catch(() => {})
    apiGet<TargetOption[]>('/api/v1/targets?take=500').then(setTargets).catch(() => {})
    apiGet<Adapter[]>('/api/v1/adapters').then(setAdapters).catch(() => {})
    apiGet<CredentialOption[]>('/api/v1/credentials').then(setCredentials).catch(() => {})
  }, [])

  const newAdapter = adapters.find((a) => a.type === adapterType)
  const chosen = targets.filter((t) => targetIds.includes(t.id))
  /** The adapter the shared service form is drawn from: the new server's, or the first chosen. */
  const formAdapter = newServer && chosen.length === 0
    ? newAdapter
    : adapters.find((a) => a.type === chosen[0]?.adapterType) ?? newAdapter
  const mixedAdapters = new Set(chosen.map((t) => t.adapterType)).size > 1

  function adapterDefaults(a: Adapter | undefined): Record<string, string> {
    const next: Record<string, string> = {}
    for (const f of a?.serviceFields ?? []) if (f.default) next[f.key] = f.default
    return next
  }

  useEffect(() => { setService(adapterDefaults(formAdapter)) }, [formAdapter?.type])

  const visible = targets.filter((t) =>
    filter === '' || `${t.name} ${t.adapterType} ${t.environment ?? ''}`.toLowerCase().includes(filter.toLowerCase()))

  function toggle(id: string) {
    setTargetIds(targetIds.includes(id) ? targetIds.filter((x) => x !== id) : [...targetIds, id])
  }

  async function createServer(): Promise<string> {
    const res = await apiPost('/api/v1/targets', {
      name,
      targetType: newAdapter?.channel === 'winrm' ? 'WindowsServer'
        : newAdapter?.channel === 'rest' ? 'NetworkDevice' : 'LinuxServer',
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
    const existing = storeByTarget[server]
    if (existing) return existing

    const path = pathByTarget[server]
    if (!path) throw new Error(`No location chosen for ${targets.find((t) => t.id === server)?.name ?? server}.`)
    const adapter = adapters.find((a) => a.type === targets.find((t) => t.id === server)?.adapterType) ?? formAdapter
    const res = await apiPost(`/api/v1/targets/${server}/stores`, {
      storeType: adapter?.channel === 'winrm' ? 'windows-my' : 'pem-file',
      storePath: path,
      alias: null,
      config: {},
    })
    const body = await res.json()
    if (!res.ok) throw new Error(body.title ?? `The store could not be created (${res.status})`)
    return body.id as string
  }

  /**
   * One binding per server. Reuses the binding when this certificate already lives in that store;
   * otherwise copies the service settings from whatever binding is already there, because those
   * are the paths and commands this machine really uses. The shared form is the last resort.
   */
  async function ensureBinding(server: string, store: string): Promise<string> {
    const rows = await apiGet<BindingRow[]>(`/api/v1/targets/${server}/bindings`).catch(() => [])
    const mine = rows.find((b) => b.certificateId === certificateId && b.storeId === store)
    if (mine) return mine.id

    const sibling = rows.find((b) => b.storeId === store)
    let serviceBinding: Record<string, string> = service
    if (sibling) {
      try {
        const parsed = JSON.parse(sibling.serviceBindingJson || '{}') as Record<string, unknown>
        const copied: Record<string, string> = {}
        for (const [k, v] of Object.entries(parsed)) {
          if (typeof v === 'string' || typeof v === 'number') copied[k] = String(v)
        }
        if (Object.keys(copied).length > 0) serviceBinding = copied
      } catch { /* a malformed binding is not worth failing the install over */ }
    }

    const res = await apiPost(`/api/v1/targets/stores/${store}/bindings`, {
      certificateId, serviceBinding, activationPolicy: {},
    })
    const body = await res.json()
    if (!res.ok) throw new Error(body.title ?? `The binding could not be created (${res.status})`)
    return body.id as string
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

  /** Creates whatever is missing for every chosen server, then previews the impact. */
  async function prepareReview() {
    setBusy(true); setError(null)
    try {
      const servers = [...targetIds]
      const created = await Promise.all(servers.map(async (s) => ensureBinding(s, await ensureStore(s))))
      setBindingIds(created)

      const versionId = await activeVersionOf(certificateId)
      const res = await apiPost('/api/v1/deployments/plan', {
        certificateVersionId: versionId,
        bindingIds: created,
        strategy,
        maxConcurrency: Number(maxConcurrency) || 0,
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.title ?? `The plan could not be produced (${res.status})`)
      setPlan(body)
      setStep(3)
      apiGet<TargetOption[]>('/api/v1/targets?take=500').then(setTargets).catch(() => {})
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  async function install() {
    setBusy(true); setError(null)
    try {
      const versionId = await activeVersionOf(certificateId)
      const res = await apiPost('/api/v1/deployments', {
        certificateVersionId: versionId,
        bindingIds,
        strategy,
        maxConcurrency: Number(maxConcurrency) || 0,
        requestedBy: 'ui',
        approvalRequired: plan?.approvalRequired ?? false,
        autoExecute: !(plan?.approvalRequired ?? false),
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.title ?? `The installation could not be started (${res.status})`)
      setDone(plan?.approvalRequired
        ? `Job ${body.id} created for ${bindingIds.length} server(s) and is waiting for approval.`
        : `Job ${body.id} started on ${bindingIds.length} server(s).`)
      onInstalled()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  /** Step 2 also creates the new server, so the next step can list it like any other. */
  async function leaveServerStep() {
    if (!newServer) { setStep(2); return }
    setBusy(true); setError(null)
    try {
      const id = await createServer()
      const refreshed = await apiGet<TargetOption[]>('/api/v1/targets?take=500')
      setTargets(refreshed)
      setTargetIds([...targetIds, id])
      setNewServer(false); setName(''); setHost('')
      setStep(2)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  const everyServerHasALocation = targetIds.every((id) => storeByTarget[id] || pathByTarget[id])
  const canContinue =
    step === 0 ? certificateId !== ''
      : step === 1 ? (targetIds.length > 0 || (newServer && name !== '' && host !== ''))
        : step === 2 ? targetIds.length > 0 && everyServerHasALocation
          : false

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal wizard" onClick={(e) => e.stopPropagation()}>
        <div className="detail-header">
          <h2>Install a certificate on servers</h2>
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
            <p className="muted small">Follow it under Activity → Installations.</p>
            <div className="actions"><button onClick={onClose}>Done</button></div>
          </>
        ) : (
          <>
            {step === 0 && (
              <>
                <p className="muted small">Which certificate should end up on the servers?</p>
                <select value={certificateId} onChange={(e) => setCertificateId(e.target.value)}>
                  <option value="">select a certificate…</option>
                  {certificates.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.commonName}
                      {c.daysUntilExpiry !== null ? ` — ${c.daysUntilExpiry} days left` : ''}
                      {c.installedOn.length > 0 ? ` — on ${c.installedOn.map((s) => s.server).join(', ')}` : ''}
                    </option>
                  ))}
                </select>
                {certificates.length === 0 && (
                  <p className="warn small">
                    There are no certificates yet. Request one under Certificates → Requests &amp; CSRs, or
                    watch an endpoint so RemoteSSL discovers the one already in use.
                  </p>
                )}
              </>
            )}

            {step === 1 && (
              <>
                <p className="muted small">
                  Tick every machine it should go on. One certificate can cover a whole estate —
                  a wildcard usually does — and they are all updated in one run.
                </p>

                <div className="actions">
                  <button className={!newServer ? 'chosen' : ''} onClick={() => setNewServer(false)}>
                    Servers I already added
                  </button>
                  <button className={newServer ? 'chosen' : ''} onClick={() => setNewServer(true)}>
                    Add a new server
                  </button>
                </div>

                {!newServer ? (
                  <>
                    {targets.length > 6 && (
                      <input value={filter} onChange={(e) => setFilter(e.target.value)}
                        placeholder="filter by name, adapter or environment" />
                    )}
                    <div className="server-picker">
                      {visible.map((t) => (
                        <label key={t.id} className={targetIds.includes(t.id) ? 'picked' : ''}>
                          <input type="checkbox" checked={targetIds.includes(t.id)} onChange={() => toggle(t.id)} />
                          <span>
                            <strong>{t.name}</strong>
                            <span className="muted small"> · {t.adapterType}{t.environment ? ` · ${t.environment}` : ''}</span>
                          </span>
                        </label>
                      ))}
                      {visible.length === 0 && (
                        <p className="muted small">
                          {targets.length === 0
                            ? 'No servers added yet — choose “Add a new server”.'
                            : 'Nothing matches that filter.'}
                        </p>
                      )}
                    </div>
                    <div className="actions">
                      <button onClick={() => setTargetIds(visible.map((t) => t.id))}
                        disabled={visible.length === 0}>Select all shown</button>
                      <button onClick={() => setTargetIds([])} disabled={targetIds.length === 0}>Clear</button>
                      <span className="muted small" style={{ alignSelf: 'center' }}>
                        {targetIds.length} selected
                      </span>
                    </div>
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
                    {newAdapter?.notes && <p className="muted small">{newAdapter.notes}</p>}
                    {credentials.length === 0 && (
                      <p className="warn small">
                        No credentials stored yet. RemoteSSL cannot reach the server without one — add it
                        under Setup → Credentials, then come back.
                      </p>
                    )}
                    <p className="muted small">
                      Continuing adds this server and ticks it; you can then add more or move on.
                    </p>
                  </div>
                )}
              </>
            )}

            {step === 2 && (
              <>
                <p className="muted small">Where on each machine should the certificate live?</p>
                <table className="data-table">
                  <thead><tr><th>Server</th><th>Location</th></tr></thead>
                  <tbody>
                    {chosen.map((t) => (
                      <tr key={t.id}>
                        <td>
                          {t.name}
                          <div className="muted small">{t.adapterType}{t.environment ? ` · ${t.environment}` : ''}</div>
                        </td>
                        <td>
                          {t.stores.length > 0 ? (
                            <select
                              value={storeByTarget[t.id] ?? ''}
                              onChange={(e) => setStoreByTarget({ ...storeByTarget, [t.id]: e.target.value })}
                            >
                              <option value="">a new location…</option>
                              {t.stores.map((s) => (
                                <option key={s.id} value={s.id}>
                                  {s.storeType}: {s.storePath}{s.alias ? ` (${s.alias})` : ''}
                                </option>
                              ))}
                            </select>
                          ) : <span className="muted small">no location yet</span>}
                          {!storeByTarget[t.id] && (
                            <input
                              value={pathByTarget[t.id] ?? ''}
                              onChange={(e) => setPathByTarget({ ...pathByTarget, [t.id]: e.target.value })}
                              placeholder={t.adapterType === 'iis' || t.adapterType === 'windows-cert-store'
                                ? 'LocalMachine/My' : '/etc/nginx/ssl'}
                              style={{ marginTop: 4, width: '100%' }}
                            />
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {/* §9.3: the fields come from the adapter, so this never asks for something the
                    adapter has no use for. */}
                <h3>Service settings</h3>
                <p className="muted small">
                  Used only where a server has no certificate installed yet. Where one is already
                  there, its own paths and commands are kept.
                  {mixedAdapters && ' The selected servers do not all run the same thing, so these '
                    + `follow ${formAdapter?.displayName ?? 'the first one'}.`}
                </p>
                <div className="wizard-fields">
                  {(formAdapter?.serviceFields ?? []).map((f) => (
                    <label key={f.key}>
                      {f.label}{f.required && <span className="bad"> *</span>}
                      <input value={service[f.key] ?? ''}
                        onChange={(e) => setService({ ...service, [f.key]: e.target.value })} />
                      {f.help && <span className="muted small">{f.help}</span>}
                    </label>
                  ))}
                </div>

                {targetIds.length > 1 && (
                  <>
                    <h3>How to roll it out</h3>
                    <div className="wizard-fields">
                      <label>Order
                        <select value={strategy} onChange={(e) => setStrategy(e.target.value)}>
                          {STRATEGIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                        </select>
                      </label>
                      {['wave', 'parallel', 'canary'].includes(strategy) && (
                        <label>How many at a time
                          <input value={maxConcurrency} onChange={(e) => setMaxConcurrency(e.target.value)}
                            type="number" min={1} />
                        </label>
                      )}
                    </div>
                  </>
                )}
              </>
            )}

            {step === 3 && plan && (
              <>
                <p className="small">
                  <strong>{plan.certificate}</strong>{' '}
                  <span className="muted">{plan.newThumbprint.slice(0, 16)}…</span> — going to{' '}
                  <strong>{plan.targets.length}</strong> server(s), {plan.strategy}
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
                    Policy requires approval for this environment — the job is created and waits for an approver.
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
              {step === 0 && <button onClick={() => setStep(1)} disabled={!canContinue || busy}>Continue</button>}
              {step === 1 && (
                <button onClick={leaveServerStep} disabled={!canContinue || busy}>
                  {busy ? 'Adding…' : newServer ? 'Add and continue' : 'Continue'}
                </button>
              )}
              {step === 2 && (
                <button onClick={prepareReview} disabled={!canContinue || busy}>
                  {busy ? 'Preparing…' : 'Review'}
                </button>
              )}
              {step === 3 && (
                <button onClick={install} disabled={busy || (plan?.blockers.length ?? 1) > 0}>
                  {busy ? 'Starting…' : `Install on ${bindingIds.length} server(s)`}
                </button>
              )}
            </div>

            {step === 2 && (
              <p className="muted small">
                Nothing is installed by “Review” — it records the locations, then shows what the
                installation would change on each server.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  )
}

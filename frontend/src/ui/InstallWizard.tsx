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
  /** The site, file or alias this binding installs to — what tells two rows on one server apart. */
  site: string | null
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

/**
 * One place a certificate is actually served from, as discovery found it: an IIS site, an nginx
 * server block, a keystore alias. This is the unit a replacement really works on — three IIS sites
 * on one machine are three bindings, not one — so when the wizard is opened from a discovery it is
 * driven by these rather than by a list of servers.
 */
export interface PresetLocation {
  targetId: string
  targetName: string
  adapterType: string
  /** What the operator calls the place: the site name, the server_name, the alias. */
  siteName: string
  /** The store discovery already knows about, when it does; otherwise the path to find or create. */
  storeId?: string | null
  storePath: string | null
  /** Service settings read off the running configuration — the paths this site really uses. */
  service: Record<string, string>
  /** What it is serving today, shown so the operator can see what is being replaced. */
  currently?: string | null
}

const STEPS = ['Certificate', 'Servers', 'Where on each server', 'Review & install'] as const
const PRESET_STEPS = ['Certificate', 'Sites to replace on', 'Review & install'] as const

/** Strategies the orchestrator implements (§21.4), described in terms of what they do to you. */
const STRATEGIES = [
  { value: 'sequential', label: 'One server at a time (safest)' },
  { value: 'wave', label: 'A few at a time, stop if one fails' },
  { value: 'parallel', label: 'A few at a time, keep going' },
  { value: 'canary', label: 'One first, then continue by hand' },
  { value: 'ha-pair', label: 'HA pairs — standby member first' },
  { value: 'all-at-once', label: 'All at once' },
]

export default function InstallWizard({ onClose, onInstalled, preset }: {
  onClose: () => void
  onInstalled: () => void
  /** Set when opened from a discovery: the exact sites whose certificate is being replaced. */
  preset?: PresetLocation[]
}) {
  const replacing = (preset?.length ?? 0) > 0
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

  // Replacement mode — one row per discovered site, each with the paths that site really uses.
  const [locations, setLocations] = useState<PresetLocation[]>(preset ?? [])

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

  /**
   * The list of places this run installs to. In the ordinary flow that is one per chosen server;
   * when replacing, it is one per discovered site, which may be several on the same machine.
   */
  interface Unit {
    key: string
    targetId: string
    label: string
    storeId: string
    path: string
    service: Record<string, string>
    /** Preset units carry the site's own settings, which must not be overwritten by a sibling. */
    exact: boolean
  }

  const units: Unit[] = replacing
    ? locations.map((l, i) => ({
      key: `${l.targetId}:${l.siteName}:${i}`,
      targetId: l.targetId,
      label: `${l.siteName} on ${l.targetName}`,
      storeId: l.storeId ?? '',
      path: l.storePath ?? '',
      service: l.service,
      exact: true,
    }))
    : targetIds.map((id) => ({
      key: id,
      targetId: id,
      label: targets.find((t) => t.id === id)?.name ?? id,
      storeId: storeByTarget[id] ?? '',
      path: pathByTarget[id] ?? '',
      service,
      exact: false,
    }))

  function updateLocation(i: number, patch: Partial<PresetLocation>) {
    setLocations(locations.map((l, j) => (j === i ? { ...l, ...patch } : l)))
  }

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

  async function ensureStore(unit: Unit): Promise<string> {
    const server = unit.targetId
    if (unit.storeId) return unit.storeId

    const path = unit.path
    if (!path) throw new Error(`No location chosen for ${unit.label}.`)

    // A location this server already has is that location, not a second one with the same name.
    // Creating a duplicate would leave two stores pointing at one directory and, worse, two
    // bindings that both claim to own it.
    const already = targets.find((t) => t.id === server)?.stores
      .find((st) => st.storePath.replace(/\/+$/, '') === path.replace(/\/+$/, ''))
    if (already) return already.id

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
  async function ensureBinding(unit: Unit, store: string): Promise<string> {
    const rows = await apiGet<BindingRow[]>(`/api/v1/targets/${unit.targetId}/bindings`).catch(() => [])

    // A store can hold several sites — three IIS sites all live in LocalMachine\My — so "this
    // certificate is already in this store" is not enough to say the binding is the same one.
    // When the site's own settings are known, they are part of its identity.
    const mine = rows.find((b) => b.certificateId === certificateId && b.storeId === store
      && (!unit.exact || sameService(b.serviceBindingJson, unit.service)))
    if (mine) return mine.id

    // Settings read off the running configuration describe this site; a sibling's describe another.
    const sibling = unit.exact ? undefined : rows.find((b) => b.storeId === store)
    let serviceBinding: Record<string, string> = unit.service
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

  /** True when every setting we know about this site matches what the stored binding says. */
  function sameService(json: string, want: Record<string, string>): boolean {
    let parsed: Record<string, unknown>
    try { parsed = JSON.parse(json || '{}') as Record<string, unknown> } catch { return false }
    return Object.entries(want).every(([k, v]) => v === '' || String(parsed[k] ?? '') === v)
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
      // Sequential, and with a cache per (server, path): several sites on one machine share one
      // store, and creating them in parallel would create the same store several times over.
      const stores = new Map<string, string>()
      const created: string[] = []
      for (const unit of units) {
        const cacheKey = `${unit.targetId}|${unit.storeId || unit.path.replace(/\/+$/, '')}`
        let storeId = stores.get(cacheKey)
        if (!storeId) {
          storeId = await ensureStore(unit)
          stores.set(cacheKey, storeId)
        }
        created.push(await ensureBinding(unit, storeId))
      }
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
      const places = `${bindingIds.length} ${replacing ? 'site(s)' : 'server(s)'}`
      setDone(plan?.approvalRequired
        ? `Job ${body.id} created for ${places} and is waiting for approval.`
        : `Job ${body.id} started on ${places}.`)
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

  const everyPlaceHasALocation = units.every((u) => u.storeId || u.path)
  /**
   * A replacement carries each site's own settings, so a missing required one is a real gap —
   * nginx without a key path, for instance, has nowhere to put the private key.
   */
  const missingRequired = replacing
    ? locations.flatMap((l) => (adapters.find((a) => a.type === l.adapterType)?.serviceFields ?? [])
      .filter((f) => f.required && !l.service[f.key])
      .map((f) => `${l.siteName}: ${f.label} is required`))
    : []
  const canContinue =
    step === 0 ? certificateId !== ''
      : step === 1 ? (targetIds.length > 0 || (newServer && name !== '' && host !== ''))
        : step === 2 ? units.length > 0 && everyPlaceHasALocation && missingRequired.length === 0
          : false

  return (
    <div className="overlay" onClick={onClose}>
      <div className="sheet wide" onClick={(e) => e.stopPropagation()}>
        <div className="sheet-head">
          <h2>{replacing
            ? `Replace the certificate on ${locations.length} site(s)`
            : 'Install a certificate on servers'}</h2>
          <button onClick={onClose}>Close</button>
        </div>

        <div className="sheet-body">
        <ol className="steps">
          {(replacing ? PRESET_STEPS : STEPS).map((label, i) => {
            // Replacement skips the server step: discovery already said which machines are involved.
            const at = replacing ? (i === 0 ? 0 : i + 1) : i
            return (
              <li key={label} className={at === step ? 'current' : at < step ? 'done' : ''}>
                <span className="step-no">{i + 1}</span> {label}
              </li>
            )
          })}
        </ol>

        {error && <p className="notice bad small">{error}</p>}

        {done ? (
          <>
            <p className="ok">{done}</p>
            <p className="muted small">Follow it under Activity → Installations.</p>
            <div className="row-actions"><button onClick={onClose}>Done</button></div>
          </>
        ) : (
          <>
            {step === 0 && (
              <>
                {replacing && (
                  <>
                    <p className="muted small">Replacing what these sites serve today:</p>
                    <table className="grid">
                      <thead><tr><th>Site</th><th>Server</th><th>Serving now</th></tr></thead>
                      <tbody>
                        {locations.map((l, i) => (
                          <tr key={i}>
                            <td>{l.siteName}</td>
                            <td className="small">{l.targetName} <span className="muted">· {l.adapterType}</span></td>
                            <td className="small">{l.currently ?? <span className="muted">nothing bound</span>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
                <p className="muted small">
                  {replacing ? 'Which certificate should replace it?' : 'Which certificate should end up on the servers?'}
                </p>
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
                  <p className="notice warn small">
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

                <div className="row-actions">
                  <button className={!newServer ? 'primary' : ''} onClick={() => setNewServer(false)}>
                    Servers I already added
                  </button>
                  <button className={newServer ? 'primary' : ''} onClick={() => setNewServer(true)}>
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
                    <div className="row-actions">
                      <button onClick={() => setTargetIds(visible.map((t) => t.id))}
                        disabled={visible.length === 0}>Select all shown</button>
                      <button onClick={() => setTargetIds([])} disabled={targetIds.length === 0}>Clear</button>
                      <span className="muted small" style={{ alignSelf: 'center' }}>
                        {targetIds.length} selected
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="form-grid">
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
                      <p className="notice warn small">
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

            {step === 2 && replacing && (
              <>
                <p className="muted small">
                  These are the paths and settings each site is using right now, read from its own
                  configuration. Change one only if you want the replacement to go somewhere else.
                </p>
                {locations.map((l, i) => {
                  const a = adapters.find((x) => x.type === l.adapterType)
                  return (
                    <div key={i} className="card">
                      <h3>{l.siteName} <span className="muted small">on {l.targetName} · {l.adapterType}</span></h3>
                      <div className="form-grid">
                        <label>Where it lives
                          <input value={l.storePath ?? ''} disabled={!!l.storeId}
                            onChange={(e) => updateLocation(i, { storePath: e.target.value })} />
                        </label>
                        {/* §9.3: the adapter says which settings this kind of place has. */}
                        {(a?.serviceFields ?? []).map((f) => (
                          <label key={f.key}>
                            {f.label}{f.required && <span className="bad"> *</span>}
                            <input value={l.service[f.key] ?? ''}
                              onChange={(e) => updateLocation(i, {
                                service: { ...l.service, [f.key]: e.target.value },
                              })} />
                            {f.help && <span className="muted small">{f.help}</span>}
                          </label>
                        ))}
                      </div>
                    </div>
                  )
                })}

                {missingRequired.map((m, i) => <p key={i} className="notice warn small">{m}</p>)}

                {locations.length > 1 && (
                  <>
                    <h3>How to roll it out</h3>
                    <div className="form-grid">
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

            {step === 2 && !replacing && (
              <>
                <p className="muted small">Where on each machine should the certificate live?</p>
                <table className="grid">
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
                <div className="form-grid">
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
                    <div className="form-grid">
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
                  <strong>{plan.targets.length}</strong> {replacing ? 'site(s)' : 'server(s)'}, {plan.strategy}
                </p>
                <table className="grid">
                  <thead><tr><th>Server</th><th>Site</th><th>Adapter</th><th>Location</th><th>Serving today</th><th>Runner</th></tr></thead>
                  <tbody>
                    {plan.targets.map((t, i) => (
                      <tr key={i}>
                        <td>{t.target}</td>
                        <td className="small">{t.site ?? <span className="muted">—</span>}</td>
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
                  <p className="notice warn small">
                    Policy requires approval for this environment — the job is created and waits for an approver.
                  </p>
                )}
                {plan.windowRequired && !plan.windowOpen && (
                  <p className="notice warn small">Policy requires a maintenance window, and it is not open right now.</p>
                )}
                {plan.warnings.map((w, i) => <p key={i} className="notice warn small">{w}</p>)}
                {plan.blockers.length > 0 && (
                  <>
                    <h3>This cannot run yet</h3>
                    <ul className="work-list">
                      {plan.blockers.map((b, i) => <li key={i} className="bad">{b}</li>)}
                    </ul>
                  </>
                )}
              </>
            )}

            <div className="row-actions" style={{ marginTop: 16 }}>
              {step > 0 && (
                <button onClick={() => setStep(replacing && step === 2 ? 0 : step - 1)} disabled={busy}>Back</button>
              )}
              {step === 0 && (
                <button onClick={() => setStep(replacing ? 2 : 1)} disabled={!canContinue || busy}>Continue</button>
              )}
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
                  {busy ? 'Starting…'
                    : replacing ? `Replace on ${bindingIds.length} site(s)`
                      : `Install on ${bindingIds.length} server(s)`}
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
    </div>
  )
}

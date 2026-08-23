import { useState } from 'react'
import { apiGet, apiPost, apiDelete } from '../api/client'
import { Page, Card, Loading, Problem, Empty, useApi, Expiry, Pill, Modal, Field, daysUntil } from './kit'
import InstallWizard, { type PresetLocation } from './InstallWizard'

/**
 * The estate: every machine and device RemoteSSL can reach, and — when you ask it — what each one
 * is actually serving right now.
 *
 * "What's on it?" is the question this screen exists for. A list of servers with paths on them
 * tells you where somebody once decided to write a file; asking the machine tells you which IIS
 * site or nginx server block is on the certificate that expires next week.
 */

interface Store { id: string; storeType: string; storePath: string; alias: string | null }
interface Target {
  id: string
  name: string
  targetType: string
  adapterType: string
  environment: string | null
  connectionConfigJson: string
  credentialRefId: string | null
  stores: Store[]
}

interface DiscoveredSite {
  kind: string
  name: string
  detail: string | null
  thumbprint: string | null
  subject: string | null
  notAfter: string | null
  storePath: string | null
  alias: string | null
  certificatePath: string | null
  keyPath: string | null
}

interface Discovery {
  success: boolean
  sites: DiscoveredSite[]
  error?: string | null
  notSupportedReason?: string | null
  pending?: boolean
}

interface Adapter {
  type: string
  displayName: string
  category: string
  channel: string
  notes: string | null
}

interface Credential { id: string; name: string; credentialType: string }

/** The port each channel speaks on, so nobody has to remember 5985. */
const DEFAULT_PORT: Record<string, string> = { ssh: '22', winrm: '5985', rest: '443' }

export default function Servers() {
  const { data, error, loading, reload } = useApi<Target[]>('/api/v1/targets?take=500')
  const { data: adapters } = useApi<Adapter[]>('/api/v1/adapters')
  const { data: credentials } = useApi<Credential[]>('/api/v1/credentials')

  const [adding, setAdding] = useState(false)
  const [discovery, setDiscovery] = useState<Discovery | null>(null)
  const [discoveredOn, setDiscoveredOn] = useState<Target | null>(null)
  const [picked, setPicked] = useState<number[]>([])
  const [replacing, setReplacing] = useState<PresetLocation[] | null>(null)
  const [filter, setFilter] = useState('')

  const rows = (data ?? []).filter((t) =>
    filter === '' || `${t.name} ${t.adapterType} ${t.environment ?? ''}`.toLowerCase()
      .includes(filter.toLowerCase()))

  /** Asks the machine what it is serving. The runner does the work, so this polls the job. */
  async function askWhatIsOnIt(target: Target) {
    setDiscoveredOn(target)
    setPicked([])
    setDiscovery({ success: true, sites: [], pending: true })

    const res = await apiPost(`/api/v1/targets/${target.id}/stores/discover`)
    if (!res.ok) {
      setDiscovery({ success: false, sites: [], error: `The request was refused (${res.status}).` })
      return
    }
    const { jobId } = await res.json() as { jobId: string }

    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 2000))
      const job = await apiGet<{ status: string; resultJson: string | null; error?: string }>(
        `/api/v1/targets/jobs/${jobId}`).catch(() => null)
      if (!job) continue
      if (job.status === 'Queued' || job.status === 'Running') continue

      if (job.resultJson) {
        try {
          setDiscovery(JSON.parse(job.resultJson) as Discovery)
          return
        } catch { /* fall through to the generic message */ }
      }
      setDiscovery({
        success: false, sites: [],
        error: job.error ?? 'The runner finished without saying what it found.',
      })
      return
    }
    setDiscovery({
      success: false, sites: [],
      error: 'No answer from the runner. Is one online under Settings → Runners?',
    })
  }

  async function removeTarget(t: Target) {
    if (!confirm(`Remove ${t.name}? Nothing is changed on the machine itself.`)) return
    const res = await apiDelete(`/api/v1/targets/${t.id}`)
    if (res.ok) reload()
    else alert(`It could not be removed (${res.status}). Certificates may still be bound to it.`)
  }

  /** A discovered site becomes a place to install to, carrying the paths it really uses. */
  function toLocation(site: DiscoveredSite, on: Target): PresetLocation {
    const service: Record<string, string> = {}
    if (site.kind === 'iis-site') {
      service.iisSiteName = site.name
      // IIS reports a binding as "ip:port:hostheader" — e.g. "*:443:www.example.com".
      const parts = (site.detail ?? '').split(':')
      if (parts.length >= 2 && parts[1]) service.iisPort = parts[1]
      if (parts.length >= 3 && parts[2]) service.iisHostHeader = parts[2]
    } else if (site.certificatePath) {
      service.certPath = site.certificatePath
      if (site.keyPath) service.keyPath = site.keyPath
    }
    if (site.alias) service.alias = site.alias

    return {
      targetId: on.id,
      targetName: on.name,
      adapterType: on.adapterType,
      siteName: site.name,
      storeId: site.kind === 'keystore-alias' ? on.stores[0]?.id ?? null : null,
      storePath: site.storePath ?? (site.kind === 'iis-site' ? 'LocalMachine/My' : null),
      service,
      currently: site.subject
        ? `${site.subject}${site.notAfter ? ` — ${daysUntil(site.notAfter)} days left` : ''}`
        : null,
    }
  }

  return (
    <Page
      title="Servers"
      lead="Everything RemoteSSL can reach. Ask a machine what it is serving, then replace what needs replacing."
      actions={<button className="primary" onClick={() => setAdding(true)}>Add a server</button>}
    >
      {error && <Problem error={error} />}
      {loading && !data && <Loading what="your servers" />}

      {data && data.length === 0 && (
        <Empty title="No servers yet.">
          Add the machines and devices that serve your certificates — IIS, nginx, F5, a Java
          keystore. RemoteSSL reaches Windows over WinRM and everything else over SSH.
        </Empty>
      )}

      {data && data.length > 0 && (
        <Card aside={<input className="search" value={filter} placeholder="filter by name, kind or environment"
          onChange={(e) => setFilter(e.target.value)} />}>
          <table className="grid">
            <thead>
              <tr><th>Server</th><th>Runs</th><th>Address</th><th>Known places</th><th></th></tr>
            </thead>
            <tbody>
              {rows.map((t) => {
                let host = ''
                try {
                  const c = JSON.parse(t.connectionConfigJson || '{}') as { host?: string; port?: number }
                  host = c.host ? `${c.host}${c.port ? `:${c.port}` : ''}` : ''
                } catch { host = '' }
                return (
                  <tr key={t.id}>
                    <td>
                      <strong>{t.name}</strong>
                      {t.environment && <span className="tag">{t.environment}</span>}
                    </td>
                    <td className="small"><Pill tone="plain">{t.adapterType}</Pill></td>
                    <td className="small muted mono">{host || '—'}</td>
                    <td className="small muted">
                      {t.stores.length === 0
                        ? 'none yet'
                        : t.stores.map((s) => s.alias ?? s.storePath).join(', ')}
                    </td>
                    <td className="row-actions">
                      <button className="primary" onClick={() => askWhatIsOnIt(t)}>What's on it?</button>
                      <button className="danger ghost" onClick={() => removeTarget(t)}>Remove</button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </Card>
      )}

      {discovery && discoveredOn && (
        <Modal title={`What ${discoveredOn.name} is serving`} onClose={() => { setDiscovery(null); setPicked([]) }} wide>
          {discovery.pending && <Loading what={`an answer from ${discoveredOn.name}`} />}
          {discovery.error && <Problem error={discovery.error} />}
          {discovery.notSupportedReason && (
            <p className="notice warn small">{discovery.notSupportedReason}</p>
          )}

          {!discovery.pending && !discovery.error && discovery.sites.length === 0 && (
            <Empty title="Nothing is serving TLS here.">
              The machine answered, but no site or store on it is using a certificate.
            </Empty>
          )}

          {discovery.sites.length > 0 && (
            <>
              <p className="muted small">
                Tick the sites that should move to a different certificate — a wildcard renewal
                usually means several at once.
              </p>
              <table className="grid">
                <thead>
                  <tr><th></th><th>Site</th><th>Where</th><th>Serving now</th><th>Runs out</th></tr>
                </thead>
                <tbody>
                  {discovery.sites.map((site, i) => (
                    <tr key={i} className={picked.includes(i) ? 'picked' : ''}>
                      <td>
                        <input type="checkbox" checked={picked.includes(i)}
                          onChange={() => setPicked(picked.includes(i)
                            ? picked.filter((x) => x !== i)
                            : [...picked, i])} />
                      </td>
                      <td>
                        <strong>{site.name}</strong>
                        <div className="muted small">{site.kind.replace('-', ' ')}</div>
                      </td>
                      <td className="small muted">{site.detail ?? site.storePath ?? '—'}</td>
                      <td className="small">
                        {site.subject ?? <span className="muted">nothing recognised</span>}
                      </td>
                      <td><Expiry days={daysUntil(site.notAfter)} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="row-actions">
                <button className="primary" disabled={picked.length === 0}
                  onClick={() => setReplacing([...picked].sort((a, b) => a - b)
                    .map((i) => toLocation(discovery.sites[i], discoveredOn)))}>
                  Replace certificate on {picked.length} site(s)
                </button>
                <button onClick={() => setPicked(discovery.sites.map((_, i) => i))}>Select all</button>
                <button className="ghost" onClick={() => setPicked([])} disabled={picked.length === 0}>Clear</button>
              </div>
            </>
          )}
        </Modal>
      )}

      {adding && (
        <AddServer
          adapters={adapters ?? []}
          credentials={credentials ?? []}
          onClose={() => setAdding(false)}
          onAdded={() => { setAdding(false); reload() }}
        />
      )}

      {replacing && (
        <InstallWizard
          preset={replacing}
          onClose={() => setReplacing(null)}
          onInstalled={() => { setReplacing(null); reload() }}
        />
      )}
    </Page>
  )
}

function AddServer({ adapters, credentials, onClose, onAdded }: {
  adapters: Adapter[]
  credentials: Credential[]
  onClose: () => void
  onAdded: () => void
}) {
  const [name, setName] = useState('')
  const [adapterType, setAdapterType] = useState('nginx')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [environment, setEnvironment] = useState('')
  const [credentialId, setCredentialId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const adapter = adapters.find((a) => a.type === adapterType)

  function chooseAdapter(type: string) {
    setAdapterType(type)
    const channel = adapters.find((a) => a.type === type)?.channel ?? 'ssh'
    setPort(DEFAULT_PORT[channel] ?? '22')
  }

  async function save() {
    setBusy(true); setError(null)
    try {
      const res = await apiPost('/api/v1/targets', {
        name,
        targetType: adapter?.channel === 'winrm' ? 'WindowsServer'
          : adapter?.channel === 'rest' ? 'NetworkDevice' : 'LinuxServer',
        adapterType,
        environment: environment || null,
        connectionConfig: { host, port: Number(port) },
        credentialRefId: credentialId || null,
        runnerId: null,
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.title ?? `It could not be added (${res.status})`)
      onAdded()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  // Grouped by what they are, because "iis" and "f5-bigip" are not the same kind of decision.
  const groups = [...new Set(adapters.map((a) => a.category))]

  return (
    <Modal title="Add a server" onClose={onClose}>
      {error && <Problem error={error} />}
      <div className="form-grid">
        <Field label="Name" hint="What you call it — this is what you will look for later.">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" />
        </Field>
        <Field label="What runs on it">
          <select value={adapterType} onChange={(e) => chooseAdapter(e.target.value)}>
            {groups.map((g) => (
              <optgroup key={g} label={g}>
                {adapters.filter((a) => a.category === g).map((a) => (
                  <option key={a.type} value={a.type}>{a.displayName}</option>
                ))}
              </optgroup>
            ))}
          </select>
        </Field>
        <Field label="Address"><input value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.5" /></Field>
        <Field label="Port" hint={adapter?.channel === 'winrm' ? '5985 plain, 5986 over TLS' : undefined}>
          <input value={port} onChange={(e) => setPort(e.target.value)} />
        </Field>
        <Field label="Environment"><input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="PROD" /></Field>
        <Field label="Sign in with">
          <select value={credentialId} onChange={(e) => setCredentialId(e.target.value)}>
            <option value="">no credential</option>
            {credentials.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.credentialType})</option>)}
          </select>
        </Field>
      </div>

      {adapter?.notes && <p className="muted small">{adapter.notes}</p>}
      {credentials.length === 0 && (
        <p className="notice warn small">
          No credentials stored yet — RemoteSSL cannot sign in to the machine without one.
          Add it under Settings → Credentials, then come back.
        </p>
      )}

      <div className="row-actions">
        <button className="primary" onClick={save} disabled={busy || name === '' || host === ''}>
          {busy ? 'Adding…' : 'Add it'}
        </button>
        <button className="ghost" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  )
}

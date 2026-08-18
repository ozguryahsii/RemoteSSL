import { useState } from 'react'
import { apiGet, apiDelete } from '../api/client'
import { useData, post, MAX_PAGE, TruncationNotice } from './SimplePages'
import InstallWizard, { type PresetLocation } from './InstallWizard'

interface DiscoveredSite {
  kind: string
  name: string
  detail: string | null
  thumbprint: string | null
  subject: string | null
  notAfter: string | null
  storePath: string | null
  alias: string | null
  /** The files this site actually uses, where the adapter can see them. */
  certificatePath: string | null
  keyPath: string | null
}

interface Discovery {
  success: boolean
  sites: DiscoveredSite[]
  error?: string | null
  notSupportedReason?: string | null
  /** Set locally while the runner job is still in flight. */
  pending?: boolean
}

function daysLeft(iso: string): number {
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86400000)
}

/** Which server the open discovery panel belongs to, so a replacement can be aimed at it. */
interface DiscoverySubject { id: string; name: string; adapterType: string; storeId?: string }

/**
 * Turns a site discovery found into the place a replacement should install to, carrying the
 * settings the site is really using. This is the whole point of asking the server what it serves:
 * the operator picks the site, and the paths come from the machine rather than from a convention.
 */
function siteToLocation(site: DiscoveredSite, on: DiscoverySubject): PresetLocation {
  const service: Record<string, string> = {}
  if (site.kind === 'iis-site') {
    service.iisSiteName = site.name
    // IIS reports a binding as "ip:port:hostheader" — e.g. "*:443:www.ozgur.com".
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
    // A keystore inventory is read from a store we already have; everything else comes back as a path.
    storeId: site.kind === 'keystore-alias' ? on.storeId ?? null : null,
    storePath: site.storePath ?? (site.kind === 'iis-site' ? 'LocalMachine/My' : null),
    service,
    currently: site.subject
      ? `${site.subject}${site.notAfter ? ` — ${daysLeft(site.notAfter)} days left` : ''}`
      : null,
  }
}

interface TargetRow {
  id: string; name: string; targetType: string; adapterType: string
  environment: string | null; haRole: string | null; targetGroup: string | null
  credentialRefId: string | null; connectionConfigJson: string
  stores: { id: string; storeType: string; storePath: string; alias: string | null }[]
}

/**
 * What an adapter can do, as the server describes it (design doc §9.3). The screen reads this
 * instead of hard-coding per-adapter behaviour, so a new adapter appears here without a UI change
 * and no action is ever offered that the platform would refuse.
 */
export interface AdapterDescriptor {
  type: string; displayName: string; category: string; channel: string
  requiresPrivateKey: boolean; supportsChain: boolean; supportsRollback: boolean
  supportsAlias: boolean; supportsRemoteVerify: boolean; supportsStoreDiscovery: boolean
  requiresCommit: boolean
  connectionFields: AdapterField[]; serviceFields: AdapterField[]
  notes: string | null
}

export interface AdapterField {
  key: string; label: string; help: string | null; required: boolean
  options: string[] | null; default: string | null
}

/// Default management port per adapter — auto-filled on selection, always hand-editable.
const DEFAULT_PORTS: Record<string, number> = {
  nginx: 22, apache: 22, haproxy: 22, 'generic-file': 22, 'generic-ssh': 22,
  'windows-cert-store': 22, iis: 22, 'windows-ccs': 22, // Windows OpenSSH
  'java-keystore': 22, 'java-truststore': 22, 'oracle-wallet': 22,
  'f5-bigip': 443, fortigate: 443, paloalto: 443, 'citrix-adc': 443, 'cisco-ise': 443,
}

async function patchTarget(id: string, body: unknown): Promise<Response> {
  const { API_BASE, getToken } = await import('../api/client')
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = getToken()
  if (token) h['Authorization'] = `Bearer ${token}`
  return fetch(`${API_BASE}/api/v1/targets/${id}`, { method: 'PATCH', headers: h, body: JSON.stringify(body) })
}

export default function Targets() {
  const [targets, reload, , targetTotal] = useData<TargetRow[]>(`/api/v1/targets?take=${MAX_PAGE}`)
  const [creds] = useData<{ id: string; name: string }[]>('/api/v1/credentials')
  const [adapters] = useData<AdapterDescriptor[]>('/api/v1/adapters', 600000)
  const [name, setName] = useState(''); const [adapter, setAdapter] = useState('nginx')
  const [host, setHost] = useState(''); const [port, setPort] = useState('22'); const [credId, setCredId] = useState('')
  const [portTouched, setPortTouched] = useState(false)
  const [winMethod, setWinMethod] = useState('winrm') // winrm | ssh, for windows adapters
  const [testResult, setTestResult] = useState<string | null>(null)
  const [discovery, setDiscovery] = useState<Discovery | null>(null)
  const [discoveryFor, setDiscoveryFor] = useState<DiscoverySubject | null>(null)
  const [picked, setPicked] = useState<number[]>([])
  const [replaceOn, setReplaceOn] = useState<PresetLocation[] | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const [eHaRole, setEHaRole] = useState(''); const [eGroup, setEGroup] = useState('')
  const [eName, setEName] = useState(''); const [eAdapter, setEAdapter] = useState('nginx')
  const [eHost, setEHost] = useState(''); const [ePort, setEPort] = useState('22'); const [eCred, setECred] = useState('')
  const [eMethod, setEMethod] = useState('winrm')

  const isWindows = (a: string) => a === 'windows-cert-store' || a === 'iis'
  const isVendor = (a: string) => ['f5-bigip', 'fortigate', 'paloalto', 'citrix-adc', 'cisco-ise'].includes(a)

  function pickAdapter(value: string) {
    setAdapter(value)
    // Auto-fill the default port unless the user already typed one manually.
    if (!portTouched) {
      const p = isWindows(value) ? (winMethod === 'winrm' ? 5985 : 22) : DEFAULT_PORTS[value] ?? 22
      setPort(String(p))
    }
  }

  function pickWinMethod(value: string) {
    setWinMethod(value)
    if (!portTouched && isWindows(adapter)) setPort(value === 'winrm' ? '5985' : '22')
  }

  async function add(e: React.FormEvent) {
    e.preventDefault()
    const connectionConfig = isVendor(adapter)
      ? { managementUrl: `https://${host}:${port}` }
      : isWindows(adapter)
        ? { host, port: Number(port), method: winMethod, winRmUseSsl: winMethod === 'winrm' && Number(port) === 5986 }
        : { host, port: Number(port) }
    const res = await post('/api/v1/targets', {
      name, adapterType: adapter,
      targetType: isWindows(adapter) ? 'WindowsServer' : isVendor(adapter) ? 'NetworkDevice' : 'LinuxServer',
      connectionConfig,
      credentialRefId: credId || null,
    })
    if (!res.ok) { alert('Create failed: ' + ((await res.json()).title ?? res.status)); return }
    setName(''); setHost(''); setPortTouched(false); setPort(String(DEFAULT_PORTS[adapter] ?? 22)); reload()
  }

  function startEdit(t: TargetRow) {
    setEditing(t.id); setEName(t.name); setEAdapter(t.adapterType); setECred(t.credentialRefId ?? '')
    setEHaRole(t.haRole ?? ''); setEGroup(t.targetGroup ?? '')
    try {
      const c = JSON.parse(t.connectionConfigJson)
      if (c.managementUrl) {
        const u = new URL(c.managementUrl)
        setEHost(u.hostname); setEPort(u.port || '443')
      } else {
        setEHost(c.host ?? ''); setEPort(String(c.port ?? 22)); setEMethod(c.method ?? 'winrm')
      }
    } catch { setEHost(''); setEPort('22') }
  }

  async function saveEdit(id: string) {
    const connectionConfig = isVendor(eAdapter)
      ? { managementUrl: `https://${eHost}:${ePort}` }
      : isWindows(eAdapter)
        ? { host: eHost, port: Number(ePort), method: eMethod, winRmUseSsl: eMethod === 'winrm' && Number(ePort) === 5986 }
        : { host: eHost, port: Number(ePort) }
    const res = await patchTarget(id, {
      name: eName, adapterType: eAdapter, connectionConfig,
      haRole: eHaRole || null, clearHaRole: !eHaRole,
      targetGroup: eGroup || null, clearTargetGroup: !eGroup,
      credentialRefId: eCred || null, clearCredential: !eCred,
    })
    if (!res.ok) { alert('Update failed: ' + ((await res.json()).title ?? res.status)); return }
    setEditing(null); reload()
  }

  async function remove(t: TargetRow) {
    if (!window.confirm(`Delete target '${t.name}'? Its stores will be removed too.`)) return
    const res = await apiDelete(`/api/v1/targets/${t.id}`)
    if (!res.ok) alert('Delete failed: ' + ((await res.json()).title ?? res.status))
    reload()
  }

  async function removeStore(storeId: string) {
    const res = await apiDelete(`/api/v1/targets/stores/${storeId}`)
    if (!res.ok) alert('Delete failed: ' + ((await res.json()).title ?? res.status))
    reload()
  }

  async function addStore(targetId: string) {
    const path = window.prompt('Store path (e.g. /etc/nginx/ssl, LocalMachine\\My, /opt/app/truststore.jks):')
    if (!path) return
    await post(`/api/v1/targets/${targetId}/stores`, { storeType: 'auto', storePath: path, alias: null })
    reload()
  }

  const capability = (type: string) => (adapters ?? []).find((a) => a.type === type)

  /**
   * Asks the target what it is actually serving: which IIS sites or nginx server blocks exist and
   * which certificate each one uses today. "Where do I write the file" is the wrong question to
   * start from — the operator knows the site, not the path.
   */
  async function discoverStores(t: TargetRow) {
    const targetId = t.id
    setDiscoveryFor({ id: t.id, name: t.name, adapterType: t.adapterType })
    setPicked([])
    setDiscovery({ success: true, sites: [], pending: true })
    const res = await post(`/api/v1/targets/${targetId}/stores/discover`)
    const { jobId } = await res.json()
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 2000))
      const job = await apiGet<{ status: string; resultJson: string | null }>(`/api/v1/targets/jobs/${jobId}`)
      if (job.status === 'Succeeded' || job.status === 'Failed') {
        try { setDiscovery(JSON.parse(job.resultJson ?? '{}') as Discovery) }
        catch { setDiscovery({ success: false, sites: [], error: 'the runner returned something unreadable' }) }
        return
      }
    }
    setDiscovery({ success: false, sites: [], error: 'timed out — is a runner online for this server?' })
  }

  /** §12.3: list everything in a Java keystore, not just the alias we deploy to. */
  async function inventoryKeystore(t: TargetRow, storeId: string) {
    const targetId = t.id
    setDiscoveryFor({ id: t.id, name: t.name, adapterType: t.adapterType, storeId })
    setPicked([])
    setDiscovery({ success: true, sites: [], pending: true })
    const res = await post(`/api/v1/targets/${targetId}/stores/${storeId}/inventory`)
    if (!res.ok) {
      setDiscovery({ success: false, sites: [],
        error: (await res.json()).detail ?? `The keystore could not be read (${res.status})` })
      return
    }
    const { jobId } = await res.json()
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 2000))
      const job = await apiGet<{ status: string; resultJson: string | null }>(`/api/v1/targets/jobs/${jobId}`)
      if (job.status === 'Succeeded') {
        const result = JSON.parse(job.resultJson ?? '{}')
        // A keystore alias is a place a certificate lives, so it is reported like any other site.
        setDiscovery({
          success: true,
          sites: (result.entries ?? []).map((e: {
            alias: string; entryType: string; subject: string | null
            notAfter: string | null; sha256Thumbprint: string | null
          }) => ({
            kind: 'keystore-alias',
            name: e.alias,
            detail: e.entryType,
            thumbprint: e.sha256Thumbprint,
            subject: e.subject,
            notAfter: e.notAfter,
            storePath: null,
            alias: e.alias,
            certificatePath: null,
            keyPath: null,
          })),
        })
        return
      }
      if (job.status === 'Failed') {
        setDiscovery({ success: false, sites: [],
          error: JSON.parse(job.resultJson ?? '{}').error ?? 'the keystore could not be read' })
        return
      }
    }
    setDiscovery({ success: false, sites: [], error: 'timed out — is a runner online for this server?' })
  }

  async function testConnection(targetId: string) {
    setTestResult('testing…')
    const res = await post(`/api/v1/targets/${targetId}/test-connection`)
    const { jobId } = await res.json()
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 2000))
      const job = await apiGet<{ status: string; resultJson: string | null }>(`/api/v1/targets/jobs/${jobId}`)
      if (job.status === 'Succeeded') { setTestResult(`OK: ${JSON.parse(job.resultJson ?? '{}').output ?? ''}`); return }
      if (job.status === 'Failed') { setTestResult('FAILED'); return }
    }
    setTestResult('timeout — is a runner online?')
  }

  return (
    <div className="page">
      <h1>Servers</h1>
      <TruncationNotice shown={(targets ?? []).length} total={targetTotal} />
      <form className="inline-form" onSubmit={add}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="target name" required />
        <select value={adapter} onChange={(e) => pickAdapter(e.target.value)}>
          {(adapters ?? []).map((a) => <option key={a.type} value={a.type}>{a.displayName}</option>)}
        </select>
        {isWindows(adapter) && (
          <select value={winMethod} onChange={(e) => pickWinMethod(e.target.value)} title="Windows management channel">
            <option value="winrm">WinRM (PowerShell Remoting)</option>
            <option value="ssh">SSH (OpenSSH)</option>
          </select>
        )}
        <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="host" required />
        <input value={port} onChange={(e) => { setPort(e.target.value); setPortTouched(true) }}
               type="number" min={1} max={65535} style={{ width: 80 }} title="port (auto-filled per adapter, editable)" />
        <select value={credId} onChange={(e) => setCredId(e.target.value)}>
          <option value="">no credential</option>
          {(creds ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <button type="submit">Add target</button>
      </form>
      {capability(adapter) && (
        <p className="small muted">
          {capability(adapter)!.displayName} · {capability(adapter)!.channel} ·{' '}
          {capability(adapter)!.requiresPrivateKey ? 'needs the private key' : 'certificate only'}
          {capability(adapter)!.supportsRollback ? ' · can roll back' : ' · no rollback'}
          {capability(adapter)!.requiresCommit ? ' · needs a commit to persist' : ''}
          {capability(adapter)!.notes ? <><br />{capability(adapter)!.notes}</> : null}
        </p>
      )}
      {testResult && <p className="small">{testResult}</p>}
      {discovery && (
        <div className="detail-panel">
          <div className="detail-header">
            <h3>What {discoveryFor?.name} is serving</h3>
            <button onClick={() => { setDiscovery(null); setDiscoveryFor(null); setPicked([]) }}>Close</button>
          </div>
          {discovery.pending && <p className="muted small">Asking the server…</p>}
          {discovery.error && <p className="bad small">{discovery.error}</p>}
          {discovery.notSupportedReason && <p className="warn small">{discovery.notSupportedReason}</p>}
          {!discovery.pending && !discovery.error && (discovery.sites ?? []).length === 0
            && !discovery.notSupportedReason && (
              <p className="muted small">Nothing on this server is serving a certificate yet.</p>
            )}
          {(discovery.sites ?? []).length > 0 && (
            <table className="data-table">
              <thead>
                <tr><th></th><th>Site</th><th>Where</th><th>Certificate it serves now</th><th>Expires</th></tr>
              </thead>
              <tbody>
                {discovery.sites.map((site, i) => (
                  <tr key={i} className={picked.includes(i) ? 'picked' : ''}>
                    <td>
                      <input type="checkbox" checked={picked.includes(i)}
                        title="Replace the certificate on this site"
                        onChange={() => setPicked(picked.includes(i)
                          ? picked.filter((x) => x !== i)
                          : [...picked, i])} />
                    </td>
                    <td>
                      {site.name}
                      <div className="muted small">{site.kind}</div>
                    </td>
                    <td className="small muted">{site.detail ?? '—'}</td>
                    <td className="small">
                      {site.subject
                        ? <>{site.subject}<div className="muted">{site.thumbprint?.slice(0, 16)}…</div></>
                        : site.thumbprint
                          ? <span className="muted">{site.thumbprint.slice(0, 16)}… (not in this store)</span>
                          : <span className="warn">nothing bound</span>}
                    </td>
                    <td className="small">
                      {site.notAfter
                        ? <span className={daysLeft(site.notAfter) < 30 ? 'bad' : 'ok'}>
                            {daysLeft(site.notAfter)} days
                          </span>
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {(discovery.sites ?? []).length > 0 && (
            <div className="actions">
              <button
                disabled={picked.length === 0 || !discoveryFor}
                onClick={() => setReplaceOn([...picked]
                  .sort((a, b) => a - b)
                  .map((i) => siteToLocation(discovery.sites[i], discoveryFor!)))}
              >
                Replace certificate on {picked.length} site(s)
              </button>
              <button onClick={() => setPicked(discovery.sites.map((_, i) => i))}>Select all</button>
              <button onClick={() => setPicked([])} disabled={picked.length === 0}>Clear</button>
              <span className="muted small" style={{ alignSelf: 'center' }}>
                Tick the sites that should move to a different certificate — a wildcard renewal
                usually means several of them at once.
              </span>
            </div>
          )}
        </div>
      )}
      {replaceOn && (
        <InstallWizard
          preset={replaceOn}
          onClose={() => setReplaceOn(null)}
          onInstalled={reload}
        />
      )}
      <table className="data-table">
        <thead><tr><th>Name</th><th>Adapter</th><th>Connection</th><th>HA role</th><th>Group</th><th>Stores</th><th></th></tr></thead>
        <tbody>
          {(targets ?? []).map((t) => editing === t.id ? (
            <tr key={t.id} className="editing-row">
              <td><input value={eName} onChange={(e) => setEName(e.target.value)} /></td>
              <td>
                <select value={eAdapter} onChange={(e) => { setEAdapter(e.target.value); setEPort(String(DEFAULT_PORTS[e.target.value] ?? 22)) }}>
                  {(adapters ?? []).map((a) => <option key={a.type} value={a.type}>{a.displayName}</option>)}
                </select>
              </td>
              <td>
                <input value={eHost} onChange={(e) => setEHost(e.target.value)} placeholder="host" style={{ width: 160 }} />{' '}
                <input value={ePort} onChange={(e) => setEPort(e.target.value)} type="number" style={{ width: 80 }} />
                {isWindows(eAdapter) && (
                  <select value={eMethod} onChange={(e) => setEMethod(e.target.value)}>
                    <option value="winrm">WinRM</option><option value="ssh">SSH</option>
                  </select>
                )}
              </td>
              <td>
                <select value={eHaRole} onChange={(e) => setEHaRole(e.target.value)}
                        title="Standby members deploy first under the HA-pair strategy">
                  <option value="">not in an HA pair</option>
                  <option value="standby">standby</option>
                  <option value="active">active</option>
                </select>
              </td>
              <td>
                <input value={eGroup} onChange={(e) => setEGroup(e.target.value)} placeholder="group"
                       title="Used by scope rules (§24.2)" style={{ width: 90 }} />
              </td>
              <td>
                <select value={eCred} onChange={(e) => setECred(e.target.value)}>
                  <option value="">no credential</option>
                  {(creds ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </td>
              <td className="actions">
                <button onClick={() => saveEdit(t.id)}>Save</button>
                <button onClick={() => setEditing(null)}>Cancel</button>
              </td>
            </tr>
          ) : (
            <tr key={t.id}>
              <td>{t.name}</td><td>{t.adapterType}</td>
              <td className="small muted">{t.connectionConfigJson}</td>
              <td className="small">{t.haRole ?? <span className="muted">—</span>}</td>
              <td className="small">{t.targetGroup ?? <span className="muted">—</span>}</td>
              <td className="small">
                {t.stores.length === 0 ? '—' : t.stores.map((s) => (
                  <span key={s.id} className="store-chip">
                    {s.storePath}{s.alias ? ` (${s.alias})` : ''}
                    <button className="chip-x" title="Remove store" onClick={() => removeStore(s.id)}>×</button>
                  </span>
                ))}
              </td>
              <td className="actions">
                <button onClick={() => testConnection(t.id)}>Test connection</button>
                <button onClick={() => discoverStores(t)}>What's on it?</button>
                {/* §9.3: only offered where the adapter can actually read the store back. */}
                {capability(t.adapterType)?.supportsStoreDiscovery && t.stores.length > 0 && (
                  <button onClick={() => inventoryKeystore(t, t.stores[0].id)}>Inventory</button>
                )}
                <button onClick={() => addStore(t.id)}>Add store</button>
                <button onClick={() => startEdit(t)}>Edit</button>
                <button className="danger" onClick={() => remove(t)}>Delete</button>
              </td>
            </tr>
          ))}
          {(targets ?? []).length === 0 && <tr><td colSpan={7} className="muted">No targets yet.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

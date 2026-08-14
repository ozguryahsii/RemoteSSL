import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiGet, apiPost, apiPatch, apiDelete } from '../api/client'
import { useData, post } from './SimplePages'

interface ObservedCert {
  certificateId: string
  commonName: string
  issuerDn: string
  sha256Thumbprint: string
  notAfter: string
  daysUntilExpiry: number
  health: string
}

interface Vantage {
  probeStatus: string
  probeError: string | null
  probeAt: string | null
  tlsProtocol: string | null
  chainValid: boolean | null
  chainError: string | null
  certificate: ObservedCert | null
  cipherSuite: string | null
}

interface Expected {
  certificateId: string
  versionId: string
  commonName: string
  sha256Thumbprint: string
  notAfter: string
  status: string
}

interface BindingLink {
  bindingId: string
  targetId: string
  targetName: string
  adapter: string
  storeType: string
  storePath: string
  alias: string | null
  credentialName: string | null
  credentialStatus: string
  serviceBindingJson: string
}

interface Monitor {
  id: string
  host: string
  port: number
  sni: string | null
  enabled: boolean
  probeIntervalMinutes: number | null
  runnerId: string | null
  externalProbeEnabled: boolean
  external: Vantage
  internal: Vantage
  verdict: string
  verdictDetail: string
  expected: Expected | null
  driftStatus: string
  bindings: BindingLink[]
  timeoutSeconds: number | null
  retryCount: number
  protocol: string
  healthCheckUrl: string | null
  healthCheckExpectedStatus: number | null
  healthCheckStatus: string
  healthCheckDetail: string | null
  healthCheckAt: string | null
  healthCheckLatencyMs: number | null
}

function healthClass(health: string | undefined): string {
  switch (health) {
    case 'Healthy': return 'ok'
    case 'ExpiringSoon': return 'warn'
    default: return health ? 'bad' : ''
  }
}

function verdictClass(v: string): string {
  switch (v) {
    case 'Match': return 'ok'
    case 'Mismatch': return 'bad'
    case 'NotConfigured': return 'muted'
    default: return 'warn'
  }
}

function healthClassFor(status: string): string {
  switch (status) {
    case 'Healthy': return 'ok'
    case 'Unhealthy': return 'bad'
    case 'Unreachable': return 'bad'
    default: return 'muted'
  }
}

function driftClass(d: string): string {
  switch (d) {
    case 'InSync': return 'ok'
    case 'Drift': return 'bad'
    case 'NotObserved': return 'warn'
    default: return 'muted'
  }
}

/** §26.3: expected certificate, drift verdict, managed target / credential / binding links. */
function ExpectedCell({ m }: { m: Monitor }) {
  return (
    <div className="small">
      <span className={driftClass(m.driftStatus)}>{m.driftStatus}</span>
      {m.expected ? (
        <>
          <div>{m.expected.commonName}</div>
          <div className="muted">
            {m.expected.sha256Thumbprint.slice(0, 12)}… · {m.expected.status} ·{' '}
            {new Date(m.expected.notAfter).toLocaleDateString()}
          </div>
        </>
      ) : (
        <div className="muted">No certificate linked to this endpoint.</div>
      )}
      {m.bindings.map((b) => (
        <div key={b.bindingId} className="muted" style={{ marginTop: 4 }}>
          → {b.targetName} <span className="tag">{b.adapter}</span>
          <div>{b.storeType}: {b.storePath}{b.alias ? ` (${b.alias})` : ''}</div>
          <div>credential: {b.credentialName ?? '—'} ({b.credentialStatus})</div>
        </div>
      ))}
      {m.bindings.length === 0 && <div className="muted">No managed target bound.</div>}
    </div>
  )
}

/** One vantage cell: probe status, the certificate it serves and its expiry. */
function VantageCell({ v, enabled, label }: { v: Vantage; enabled: boolean; label: string }) {
  if (!enabled) return <span className="muted small">{label}</span>
  const c = v.certificate
  return (
    <div className="small">
      <span className={v.probeStatus === 'Success' ? 'ok' : v.probeStatus === 'NeverProbed' ? 'muted' : 'bad'}>
        {v.probeStatus}
      </span>
      {v.probeError && <div className="muted">{v.probeError}</div>}
      {c && (
        <>
          <div>{c.commonName}</div>
          <div>
            <span className={healthClass(c.health)}>{c.daysUntilExpiry} days</span>
            <span className="muted"> · {c.sha256Thumbprint.slice(0, 12)}…</span>
          </div>
          {v.chainValid === false && <div className="warn">chain: {v.chainError}</div>}
        </>
      )}
      {(v.tlsProtocol || v.cipherSuite) && (
        <div className="muted">{[v.tlsProtocol, v.cipherSuite].filter(Boolean).join(' · ')}</div>
      )}
      {v.probeAt && <div className="muted">{new Date(v.probeAt).toLocaleString()}</div>}
    </div>
  )
}

export default function Monitors() {
  const { t } = useTranslation()
  const [monitors, setMonitors] = useState<Monitor[]>([])
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const [sni, setSni] = useState('')
  const [runnerId, setRunnerId] = useState('')
  const [externalEnabled, setExternalEnabled] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const [eHost, setEHost] = useState(''); const [ePort, setEPort] = useState('443')
  const [eSni, setESni] = useState(''); const [eInterval, setEInterval] = useState('')
  const [eRunner, setERunner] = useState('')
  const [eExternal, setEExternal] = useState(true)
  const [eTimeout, setETimeout] = useState(''); const [eRetries, setERetries] = useState('0')
  const [eHealthUrl, setEHealthUrl] = useState(''); const [eHealthStatus, setEHealthStatus] = useState('')

  const [runners] = useData<{ id: string; name: string }[]>('/api/v1/runners')

  const reload = useCallback(() => {
    apiGet<Monitor[]>('/api/v1/monitors').then(setMonitors).catch((e) => setError(String(e)))
  }, [])

  useEffect(() => {
    reload()
    const id = setInterval(reload, 30_000)
    return () => clearInterval(id)
  }, [reload])

  async function addMonitor(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    const res = await apiPost('/api/v1/monitors', { host, port: Number(port), sni: sni || null, runnerId: runnerId || null, externalProbeEnabled: externalEnabled })
    if (!res.ok) {
      setError(`${t('monitors.addFailed')} (${res.status})`)
      return
    }
    setHost('')
    setPort('443')
    setSni('')
    reload()
  }

  async function probe(id: string) {
    setBusy(id)
    try {
      await apiPost(`/api/v1/monitors/${id}/probe`)
      reload()
    } finally {
      setBusy(null)
    }
  }

  async function remove(id: string) {
    if (!window.confirm('Delete this monitor?')) return
    await apiDelete(`/api/v1/monitors/${id}`)
    reload()
  }

  function startEdit(m: Monitor) {
    setEditing(m.id); setEHost(m.host); setEPort(String(m.port))
    setESni(m.sni ?? ''); setEInterval(m.probeIntervalMinutes ? String(m.probeIntervalMinutes) : '')
    setERunner(m.runnerId ?? ''); setEExternal(m.externalProbeEnabled)
    setETimeout(m.timeoutSeconds ? String(m.timeoutSeconds) : ''); setERetries(String(m.retryCount))
    setEHealthUrl(m.healthCheckUrl ?? '')
    setEHealthStatus(m.healthCheckExpectedStatus ? String(m.healthCheckExpectedStatus) : '')
  }

  async function saveEdit(id: string) {
    const res = await apiPatch(`/api/v1/monitors/${id}`, {
      host: eHost, port: Number(ePort), sni: eSni || null, clearSni: !eSni,
      probeIntervalMinutes: eInterval ? Number(eInterval) : null,
      runnerId: eRunner || null, clearRunner: !eRunner, externalProbeEnabled: eExternal,
      timeoutSeconds: eTimeout ? Number(eTimeout) : null, clearTimeout: !eTimeout,
      retryCount: Number(eRetries) || 0,
      healthCheckUrl: eHealthUrl || null, clearHealthCheck: !eHealthUrl,
      healthCheckExpectedStatus: eHealthStatus ? Number(eHealthStatus) : null,
    })
    if (!res.ok) { setError(`Update failed (${res.status})`); return }
    setEditing(null); reload()
  }

  async function toggleEnabled(m: Monitor) {
    await apiPatch(`/api/v1/monitors/${m.id}`, { enabled: !m.enabled })
    reload()
  }

  return (
    <div className="page">
      <h1>{t('nav.monitors')}</h1>

      <form className="inline-form" onSubmit={addMonitor}>
        <input value={host} onChange={(e) => setHost(e.target.value)}
               placeholder={t('monitors.hostPlaceholder')} required />
        <input value={port} onChange={(e) => setPort(e.target.value)}
               placeholder="443" type="number" min={1} max={65535} style={{ width: 90 }} />
        <input value={sni} onChange={(e) => setSni(e.target.value)}
               placeholder={t('monitors.sniPlaceholder')} />
        <select value={runnerId} onChange={(e) => setRunnerId(e.target.value)}
                title="Internal-DNS endpoints must be probed by a runner inside the segment">
          <option value="">probe from control plane</option>
          {(runners ?? []).map((r) => <option key={r.id} value={r.id}>via runner: {r.name}</option>)}
        </select>
        <label className="small" title="Turn off for services that exist only on internal DNS">
          <input type="checkbox" checked={externalEnabled} onChange={(e) => setExternalEnabled(e.target.checked)} /> probe externally
        </label>
        <button type="submit">{t('monitors.add')}</button>
      </form>
      {error && <p className="error">{error}</p>}
      <p className="muted small" style={{ marginTop: -12 }}>
        <strong>Outside</strong> is probed by the control plane over public DNS. <strong>Inside</strong> is probed by a
        runner that lives in the same network as the application — pick one under <em>Edit → via runner</em>. Only then
        can RemoteSSL compare the two and tell you whether the certificate was replaced outside, inside, or both.
        Endpoints that exist only on internal DNS (external probe says DnsResolutionFailed) need a runner to be
        monitored at all; you can also untick <em>probe externally</em> for them.
      </p>

      <table className="data-table">
        <thead>
          <tr>
            <th>{t('monitors.endpoint')}</th>
            <th>Outside (control plane)</th>
            <th>Inside (runner)</th>
            <th>Comparison</th>
            <th>App health</th>
            <th>Expected / target</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {monitors.map((m) => editing === m.id ? (
            <tr key={m.id} className="editing-row">
              <td>
                <input value={eHost} onChange={(e) => setEHost(e.target.value)} style={{ width: 150 }} />:
                <input value={ePort} onChange={(e) => setEPort(e.target.value)} type="number" style={{ width: 70 }} />
                <br /><input value={eSni} onChange={(e) => setESni(e.target.value)} placeholder="SNI" style={{ width: 150 }} />
                <select value={eRunner} onChange={(e) => setERunner(e.target.value)}>
                  <option value="">control plane</option>
                  {(runners ?? []).map((r) => <option key={r.id} value={r.id}>via {r.name}</option>)}
                </select>
              </td>
              <td colSpan={4} className="small muted">
                <div>
                  Interval (min): <input value={eInterval} onChange={(e) => setEInterval(e.target.value)}
                    placeholder="default" type="number" style={{ width: 80 }} />
                  {' '}timeout (s): <input value={eTimeout} onChange={(e) => setETimeout(e.target.value)}
                    placeholder="default" type="number" min={1} max={120} style={{ width: 80 }} />
                  {' '}retries: <input value={eRetries} onChange={(e) => setERetries(e.target.value)}
                    type="number" min={0} max={5} style={{ width: 60 }} />
                  <label style={{ marginLeft: 10 }}>
                    <input type="checkbox" checked={eExternal} onChange={(e) => setEExternal(e.target.checked)} /> probe externally
                  </label>
                </div>
                <div style={{ marginTop: 4 }}>
                  Health check URL: <input value={eHealthUrl} onChange={(e) => setEHealthUrl(e.target.value)}
                    placeholder="https://app.example/health" style={{ width: 240 }} />
                  {' '}expect: <input value={eHealthStatus} onChange={(e) => setEHealthStatus(e.target.value)}
                    placeholder="any 2xx/3xx" type="number" style={{ width: 90 }} />
                </div>
              </td>
              <td className="actions">
                <button onClick={() => saveEdit(m.id)}>Save</button>
                <button onClick={() => setEditing(null)}>Cancel</button>
              </td>
            </tr>
          ) : (
            <tr key={m.id}>
              <td>
                {m.host}:{m.port}
                {m.sni && <div className="muted small">SNI: {m.sni}</div>}
                {!m.enabled && <span className="tag muted">disabled</span>}
              </td>
              <td><VantageCell v={m.external} enabled={m.externalProbeEnabled}
                               label="external probe turned off for this endpoint" /></td>
              <td><VantageCell v={m.internal} enabled={!!m.runnerId}
                               label="not probed from inside — pick a runner under Edit" /></td>
              <td>
                <span className={verdictClass(m.verdict)}>{m.verdict}</span>
                <div className="muted small" style={{ maxWidth: 320 }}>{m.verdictDetail}</div>
              </td>
              <td className="small">
                {m.healthCheckUrl ? (
                  <>
                    <span className={healthClassFor(m.healthCheckStatus)}>{m.healthCheckStatus}</span>
                    <div className="muted">{m.healthCheckDetail ?? m.healthCheckUrl}</div>
                    {m.healthCheckLatencyMs !== null && <div className="muted">{m.healthCheckLatencyMs} ms</div>}
                  </>
                ) : <span className="muted">not configured</span>}
              </td>
              <td><ExpectedCell m={m} /></td>
              <td className="actions">
                <button onClick={() => probe(m.id)} disabled={busy === m.id}>
                  {busy === m.id ? t('monitors.probing') : t('monitors.probeNow')}
                </button>
                <button onClick={() => startEdit(m)}>Edit</button>
                <button onClick={() => toggleEnabled(m)}>{m.enabled ? 'Disable' : 'Enable'}</button>
                <button className="danger" onClick={() => remove(m.id)}>{t('common.delete')}</button>
              </td>
            </tr>
          ))}
          {monitors.length === 0 && (
            <tr><td colSpan={7} className="muted">{t('monitors.empty')}</td></tr>
          )}
        </tbody>
      </table>

      <ServicePaths monitors={monitors} />
    </div>
  )
}

interface PathRow { id: string; name: string; monitorIdsJson: string }
interface Analysis {
  verdict: string
  hops: { order: number; endpoint: string; probedVia: string; status: string; detail: string; notAfter: string | null }[]
}

/** Multi-hop TLS analysis: F5 -> nginx -> IIS style layered paths (finds the layer skipped during renewal). */
function ServicePaths({ monitors }: { monitors: Monitor[] }) {
  const [paths, reloadPaths] = useData<PathRow[]>('/api/v1/paths')
  const [name, setName] = useState('')
  const [hops, setHops] = useState<string[]>([])
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [busy, setBusy] = useState(false)

  const [pick, setPick] = useState('')

  async function addPath(e: React.FormEvent) {
    e.preventDefault()
    const res = await post('/api/v1/paths', { name, monitorIds: hops })
    if (!res.ok) { alert('Create failed: ' + ((await res.json()).title ?? res.status)); return }
    setName(''); setHops([]); reloadPaths()
  }

  function addHop() {
    if (pick && !hops.includes(pick)) setHops([...hops, pick])
    setPick('')
  }

  function moveHop(i: number, delta: number) {
    const next = [...hops]
    const j = i + delta
    if (j < 0 || j >= next.length) return
    ;[next[i], next[j]] = [next[j], next[i]]
    setHops(next)
  }

  const label = (id: string) => {
    const m = monitors.find((x) => x.id === id)
    return m ? `${m.host}:${m.port}${m.sni ? ` (SNI ${m.sni})` : ''}` : '?'
  }

  async function analyze(id: string) {
    setBusy(true); setAnalysis(null)
    try {
      const res = await post(`/api/v1/paths/${id}/analyze`)
      let a: Analysis = await res.json()
      // Runner-probed hops complete asynchronously — re-fetch once for their results.
      if (a.hops.some((h) => h.probedVia === 'runner')) {
        await new Promise((r) => setTimeout(r, 8000))
        a = await apiGet<Analysis>(`/api/v1/paths/${id}/analysis`)
      }
      setAnalysis(a)
    } finally { setBusy(false) }
  }

  const hopStatus = (s: string) =>
    s === 'Healthy' ? 'ok' : ['ExpiringSoon'].includes(s) ? 'warn' : 'bad'

  return (
    <div style={{ marginTop: 32 }}>
      <h2>Service Paths</h2>
      <p className="muted small">
        Model the TLS layers in front of one application — add a monitor per layer first (each pointing at that
        layer's own address, with the application hostname as SNI), then chain them here from the outermost hop
        (F5 VIP) to the innermost (IIS backend). Analysis probes every hop and pinpoints the layer whose
        certificate was skipped during a renewal.
      </p>

      <div className="path-builder">
        <input value={name} onChange={(e) => setName(e.target.value)}
               placeholder="path name (e.g. emakin prod)" style={{ minWidth: 220 }} />
        <select value={pick} onChange={(e) => setPick(e.target.value)} style={{ minWidth: 280 }}>
          <option value="">select a monitor to add as the next hop…</option>
          {monitors.filter((m) => !hops.includes(m.id)).map((m) => (
            <option key={m.id} value={m.id}>{m.host}:{m.port}{m.sni ? ` (SNI ${m.sni})` : ''}</option>
          ))}
        </select>
        <button type="button" onClick={addHop} disabled={!pick}>Add hop</button>
      </div>

      {hops.length > 0 && (
        <ol className="hop-list">
          {hops.map((h, i) => (
            <li key={h}>
              <span className="hop-index">{i + 1}.</span> {label(h)}
              <span className="muted small">{i === 0 ? ' — outermost' : i === hops.length - 1 ? ' — innermost' : ''}</span>
              <button type="button" onClick={() => moveHop(i, -1)} disabled={i === 0}>↑</button>
              <button type="button" onClick={() => moveHop(i, 1)} disabled={i === hops.length - 1}>↓</button>
              <button type="button" className="danger" onClick={() => setHops(hops.filter((x) => x !== h))}>×</button>
            </li>
          ))}
        </ol>
      )}

      <div className="path-builder">
        <button type="button" onClick={addPath} disabled={!name || hops.length < 2}>Save path</button>
        {hops.length < 2 && <span className="muted small">Add at least two hops (outermost first) and a name.</span>}
      </div>

      <table className="data-table">
        <thead><tr><th>Name</th><th>Hops</th><th></th></tr></thead>
        <tbody>
          {(paths ?? []).map((p) => (
            <tr key={p.id}>
              <td>{p.name}</td>
              <td className="small muted">
                {(JSON.parse(p.monitorIdsJson) as string[]).map((mid) => {
                  const m = monitors.find((x) => x.id === mid); return m ? `${m.host}:${m.port}` : '?'
                }).join(' → ')}
              </td>
              <td className="actions">
                <button onClick={() => analyze(p.id)} disabled={busy}>{busy ? 'Analyzing…' : 'Analyze'}</button>
                <button className="danger" onClick={async () => {
                  if (window.confirm('Delete this path?')) { await apiDelete(`/api/v1/paths/${p.id}`); reloadPaths() }
                }}>Delete</button>
              </td>
            </tr>
          ))}
          {(paths ?? []).length === 0 && <tr><td colSpan={3} className="muted">No service paths yet.</td></tr>}
        </tbody>
      </table>

      {analysis && (
        <div className="detail-panel">
          <div className="detail-header">
            <h3 className={analysis.verdict.startsWith('OK') ? 'ok' : 'bad'}>{analysis.verdict}</h3>
            <button onClick={() => setAnalysis(null)}>Close</button>
          </div>
          <table className="data-table">
            <thead><tr><th>#</th><th>Hop</th><th>Probed via</th><th>Status</th><th>Detail</th><th>Expiry</th></tr></thead>
            <tbody>
              {analysis.hops.map((h) => (
                <tr key={h.order}>
                  <td>{h.order}</td><td>{h.endpoint}</td><td className="small">{h.probedVia}</td>
                  <td><span className={hopStatus(h.status)}>{h.status}</span></td>
                  <td className="small">{h.detail}</td>
                  <td className="small muted">{h.notAfter ? new Date(h.notAfter).toLocaleDateString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

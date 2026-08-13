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

interface Monitor {
  id: string
  host: string
  port: number
  sni: string | null
  enabled: boolean
  probeIntervalMinutes: number | null
  runnerId: string | null
  lastProbeStatus: string
  lastProbeError: string | null
  lastProbeAt: string | null
  lastTlsProtocol: string | null
  lastHostnameValid: boolean | null
  lastChainValid: boolean | null
  lastChainError: string | null
  observedCertificate: ObservedCert | null
}

function healthClass(health: string | undefined): string {
  switch (health) {
    case 'Healthy': return 'ok'
    case 'ExpiringSoon': return 'warn'
    default: return health ? 'bad' : ''
  }
}

export default function Monitors() {
  const { t } = useTranslation()
  const [monitors, setMonitors] = useState<Monitor[]>([])
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const [sni, setSni] = useState('')
  const [runnerId, setRunnerId] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const [eHost, setEHost] = useState(''); const [ePort, setEPort] = useState('443')
  const [eSni, setESni] = useState(''); const [eInterval, setEInterval] = useState('')
  const [eRunner, setERunner] = useState('')

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
    const res = await apiPost('/api/v1/monitors', { host, port: Number(port), sni: sni || null, runnerId: runnerId || null })
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
    setERunner(m.runnerId ?? '')
  }

  async function saveEdit(id: string) {
    const res = await apiPatch(`/api/v1/monitors/${id}`, {
      host: eHost, port: Number(ePort), sni: eSni || null, clearSni: !eSni,
      probeIntervalMinutes: eInterval ? Number(eInterval) : null,
      runnerId: eRunner || null, clearRunner: !eRunner,
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
        <button type="submit">{t('monitors.add')}</button>
      </form>
      {error && <p className="error">{error}</p>}

      <table className="data-table">
        <thead>
          <tr>
            <th>{t('monitors.endpoint')}</th>
            <th>{t('monitors.status')}</th>
            <th>{t('monitors.certificate')}</th>
            <th>{t('monitors.expiry')}</th>
            <th>{t('monitors.tls')}</th>
            <th>{t('monitors.lastProbe')}</th>
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
                Probe interval (min): <input value={eInterval} onChange={(e) => setEInterval(e.target.value)}
                  placeholder="default" type="number" style={{ width: 90 }} />
              </td>
              <td></td>
              <td className="actions">
                <button onClick={() => saveEdit(m.id)}>Save</button>
                <button onClick={() => setEditing(null)}>Cancel</button>
              </td>
            </tr>
          ) : (
            <tr key={m.id}>
              <td>
                {m.host}:{m.port}
                {m.sni && <span className="muted"> (SNI: {m.sni})</span>}
                {m.runnerId && <span className="tag ok" style={{ marginLeft: 6 }}>via runner</span>}
                {!m.enabled && <span className="tag muted" style={{ marginLeft: 6 }}>disabled</span>}
              </td>
              <td>
                <span className={m.lastProbeStatus === 'Success' ? 'ok' : m.lastProbeStatus === 'NeverProbed' ? 'muted' : 'bad'}>
                  {m.lastProbeStatus}
                </span>
                {m.lastProbeError && <div className="muted small">{m.lastProbeError}</div>}
              </td>
              <td>
                {m.observedCertificate ? (
                  <>
                    {m.observedCertificate.commonName}
                    {m.lastChainValid === false && (
                      <div className="warn small">{t('monitors.chainInvalid')}: {m.lastChainError}</div>
                    )}
                  </>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              <td>
                {m.observedCertificate && (
                  <span className={healthClass(m.observedCertificate.health)}>
                    {m.observedCertificate.daysUntilExpiry} {t('monitors.days')}
                  </span>
                )}
              </td>
              <td>{m.lastTlsProtocol ?? <span className="muted">—</span>}</td>
              <td className="muted small">{m.lastProbeAt ? new Date(m.lastProbeAt).toLocaleString() : '—'}</td>
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

  async function addPath(e: React.FormEvent) {
    e.preventDefault()
    const res = await post('/api/v1/paths', { name, monitorIds: hops })
    if (!res.ok) { alert('Create failed: ' + ((await res.json()).title ?? res.status)); return }
    setName(''); setHops([]); reloadPaths()
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
        Model the TLS layers in front of an application (e.g. F5 VIP → nginx → IIS backend, outermost first).
        Analysis probes every hop and pinpoints the layer whose certificate was skipped during a renewal.
      </p>
      <form className="inline-form" onSubmit={addPath} style={{ flexWrap: 'wrap' }}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="path name (e.g. emakin prod)" required />
        <select multiple value={hops} onChange={(e) => setHops([...e.target.selectedOptions].map((o) => o.value))}
                style={{ height: 90, minWidth: 260 }} title="Cmd-click to select hops in order (outermost first)">
          {monitors.map((m) => <option key={m.id} value={m.id}>{m.host}:{m.port}{m.sni ? ` (${m.sni})` : ''}</option>)}
        </select>
        <span className="muted small">selected order: {hops.map((h) => {
          const m = monitors.find((x) => x.id === h); return m ? `${m.host}:${m.port}` : ''
        }).join(' → ') || '—'}</span>
        <button type="submit" disabled={hops.length < 2}>Add path</button>
      </form>

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

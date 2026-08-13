import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { API_BASE, apiGet } from '../api/client'

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
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

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
    const res = await fetch(`${API_BASE}/api/v1/monitors`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port: Number(port), sni: sni || null }),
    })
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
      await fetch(`${API_BASE}/api/v1/monitors/${id}/probe`, { method: 'POST' })
      reload()
    } finally {
      setBusy(null)
    }
  }

  async function remove(id: string) {
    await fetch(`${API_BASE}/api/v1/monitors/${id}`, { method: 'DELETE' })
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
          {monitors.map((m) => (
            <tr key={m.id}>
              <td>
                {m.host}:{m.port}
                {m.sni && <span className="muted"> (SNI: {m.sni})</span>}
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
                <button className="danger" onClick={() => remove(m.id)}>{t('common.delete')}</button>
              </td>
            </tr>
          ))}
          {monitors.length === 0 && (
            <tr><td colSpan={7} className="muted">{t('monitors.empty')}</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

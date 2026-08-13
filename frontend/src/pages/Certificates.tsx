import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiGet } from '../api/client'

interface CertificateListItem {
  id: string
  commonName: string
  displayName: string
  health: string
  issuerDn: string | null
  notAfter: string | null
  daysUntilExpiry: number | null
  monitorCount: number
  versionCount: number
}

interface CertificateDetail {
  id: string
  commonName: string
  health: string
  versions: {
    id: string
    serialNumber: string
    sha256Thumbprint: string
    issuerDn: string
    notBefore: string
    notAfter: string
    daysUntilExpiry: number
    publicKeyAlgorithm: string
    keySize: number
    signatureAlgorithm: string
    status: string
    sans: string[]
  }[]
  monitors: { monitorId: string; host: string; port: number; sni: string | null; lastSeenAt: string }[]
}

function healthClass(health: string): string {
  switch (health) {
    case 'Healthy': return 'ok'
    case 'ExpiringSoon': return 'warn'
    case 'Unknown': return 'muted'
    default: return 'bad'
  }
}

export default function Certificates() {
  const { t } = useTranslation()
  const [certs, setCerts] = useState<CertificateListItem[]>([])
  const [selected, setSelected] = useState<CertificateDetail | null>(null)

  useEffect(() => {
    apiGet<CertificateListItem[]>('/api/v1/certificates').then(setCerts).catch(() => {})
  }, [])

  function open(id: string) {
    apiGet<CertificateDetail>(`/api/v1/certificates/${id}`).then(setSelected).catch(() => {})
  }

  return (
    <div className="page">
      <h1>{t('nav.certificates')}</h1>
      <table className="data-table">
        <thead>
          <tr>
            <th>{t('certificates.name')}</th>
            <th>{t('certificates.status')}</th>
            <th>{t('certificates.expiry')}</th>
            <th>{t('certificates.issuer')}</th>
            <th>{t('certificates.monitors')}</th>
            <th>{t('certificates.versions')}</th>
          </tr>
        </thead>
        <tbody>
          {certs.map((c) => (
            <tr key={c.id} className="clickable" onClick={() => open(c.id)}>
              <td>{c.commonName}</td>
              <td><span className={healthClass(c.health)}>{c.health}</span></td>
              <td>{c.daysUntilExpiry !== null ? `${c.daysUntilExpiry} ${t('monitors.days')}` : '—'}</td>
              <td className="muted small">{c.issuerDn ?? '—'}</td>
              <td>{c.monitorCount}</td>
              <td>{c.versionCount}</td>
            </tr>
          ))}
          {certs.length === 0 && (
            <tr><td colSpan={6} className="muted">{t('certificates.empty')}</td></tr>
          )}
        </tbody>
      </table>

      {selected && (
        <div className="detail-panel">
          <div className="detail-header">
            <h2>{selected.commonName}</h2>
            <button onClick={() => setSelected(null)}>{t('common.close')}</button>
          </div>

          <h3>{t('certificates.versions')}</h3>
          {selected.versions.map((v) => (
            <div key={v.id} className="version-card">
              <div><strong>{t('certificates.serial')}:</strong> {v.serialNumber} <span className={`tag ${v.status === 'Superseded' ? 'muted' : 'ok'}`}>{v.status}</span></div>
              <div><strong>SHA-256:</strong> <code className="small">{v.sha256Thumbprint}</code></div>
              <div><strong>{t('certificates.validity')}:</strong> {new Date(v.notBefore).toLocaleDateString()} → {new Date(v.notAfter).toLocaleDateString()} ({v.daysUntilExpiry} {t('monitors.days')})</div>
              <div><strong>{t('certificates.key')}:</strong> {v.publicKeyAlgorithm} {v.keySize} / {v.signatureAlgorithm}</div>
              {v.sans.length > 0 && <div><strong>SAN:</strong> {v.sans.join(', ')}</div>}
            </div>
          ))}

          <h3>{t('nav.monitors')}</h3>
          <ul>
            {selected.monitors.map((m) => (
              <li key={m.monitorId}>
                {m.host}:{m.port}
                {m.sni && <span className="muted"> (SNI: {m.sni})</span>}
                <span className="muted small"> — {t('certificates.lastSeen')}: {new Date(m.lastSeenAt).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

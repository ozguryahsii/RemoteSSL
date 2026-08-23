import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Page, Card, Loading, Problem, Empty, useApi, Expiry, Pill } from './kit'
import UploadCertificate from './UploadCertificate'

/**
 * Every certificate the estate has, with the two facts that decide what happens next: when it
 * runs out, and where it is actually serving. Everything else is on the detail screen.
 */

interface Site { server: string; state: string }
interface Row {
  id: string
  commonName: string
  displayName: string
  health: string
  ca: string | null
  notAfter: string | null
  daysUntilExpiry: number | null
  environment: string | null
  installedOn: Site[]
}

export default function Certificates() {
  const { data, error, loading, reload } = useApi<Row[]>('/api/v1/certificates?take=500')
  const [filter, setFilter] = useState('')
  const [uploading, setUploading] = useState(false)
  const navigate = useNavigate()

  const rows = (data ?? []).filter((r) =>
    filter === '' || `${r.commonName} ${r.displayName} ${r.environment ?? ''}`.toLowerCase()
      .includes(filter.toLowerCase()))

  const sorted = [...rows].sort((a, b) =>
    (a.daysUntilExpiry ?? 99999) - (b.daysUntilExpiry ?? 99999))

  return (
    <Page
      title="Certificates"
      lead="What you have, when each runs out, and which machines are serving it."
      actions={<button className="primary" onClick={() => setUploading(true)}>Add a certificate</button>}
    >
      {error && <Problem error={error} />}
      {loading && !data && <Loading what="the inventory" />}

      {data && data.length === 0 && (
        <Empty title="No certificates yet.">
          Add one you already have as a file, or watch an address under Servers so RemoteSSL picks
          up what is being served there.
        </Empty>
      )}

      {data && data.length > 0 && (
        <Card
          aside={<input className="search" value={filter} placeholder="filter by name or environment"
            onChange={(e) => setFilter(e.target.value)} />}
        >
          <table className="grid">
            <thead>
              <tr>
                <th>Certificate</th>
                <th>Runs out</th>
                <th>Where it is serving</th>
                <th>Issued by</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((r) => {
                const installed = r.installedOn.filter((s) => s.state === 'installed')
                const failed = r.installedOn.filter((s) => s.state === 'failed')
                return (
                  <tr key={r.id} className="clickable" onClick={() => navigate(`/certificates/${r.id}`)}>
                    <td>
                      <strong>{r.commonName}</strong>
                      {r.environment && <span className="tag">{r.environment}</span>}
                      {r.displayName && r.displayName !== r.commonName && (
                        <div className="muted small">{r.displayName}</div>
                      )}
                    </td>
                    <td><Expiry days={r.daysUntilExpiry} /></td>
                    <td className="small">
                      {r.installedOn.length === 0
                        ? <span className="muted">nowhere yet</span>
                        : (
                          <>
                            {installed.length > 0 && (
                              <div>{installed.slice(0, 3).map((s) => s.server).join(', ')}
                                {installed.length > 3 && ` +${installed.length - 3} more`}</div>
                            )}
                            {failed.length > 0 && (
                              <Pill tone="critical">{failed.length} did not take it</Pill>
                            )}
                          </>
                        )}
                    </td>
                    <td className="small muted">{r.ca ?? '—'}</td>
                    <td>
                      <button onClick={(e) => { e.stopPropagation(); navigate(`/certificates/${r.id}?renew=1`) }}>
                        Renew
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </Card>
      )}

      {uploading && (
        <UploadCertificate
          onClose={() => setUploading(false)}
          onDone={() => { setUploading(false); reload() }}
        />
      )}
    </Page>
  )
}

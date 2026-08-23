import { useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { apiDelete, apiPost, API_BASE } from '../api/client'
import { Page, Card, Loading, Problem, useApi, Expiry, Pill, shortDate, shortDateTime } from './kit'
import StartRenewal from './StartRenewal'
import InstallWizard, { type PresetLocation } from './InstallWizard'

/**
 * One certificate, answering the three questions people open it with: how long have I got, where
 * is it serving, and what happened to it. The nine-tab version of this screen had every fact the
 * database holds and no answer to any of those.
 */

interface Detail {
  id: string
  commonName: string
  displayName: string
  health: string
  overview: {
    environment: string | null
    ca: string | null
    issuerDn: string | null
    notAfter: string | null
    daysUntilExpiry: number | null
    sans: string[]
    deploymentCount: number
    monitorCount: number
  }
  versions: {
    id: string; sha256Thumbprint: string; notBefore: string; notAfter: string
    daysUntilExpiry: number; status: string; keySize: number; publicKeyAlgorithm: string
  }[]
  deployments: {
    jobId: string; status: string; targetCount: number; failedTargets: number
    createdAt: string; completedAt: string | null
  }[]
  stores: {
    bindingId: string; storeId: string; targetId: string; target: string; adapter: string
    storePath: string; alias: string | null; serviceBindingJson: string
  }[]
  monitors: { monitorId: string; host: string; port: number; lastSeenAt: string }[]
  history: { id: number; timestamp: string; actor: string; action: string; result: string }[]
}

export default function CertificateDetail() {
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const { data, error, loading, reload } = useApi<Detail>(id ? `/api/v1/certificates/${id}` : null)
  const [installing, setInstalling] = useState<PresetLocation[] | null>(null)
  const [busy, setBusy] = useState(false)

  const renewing = params.get('renew') === '1'

  async function remove() {
    if (!id || !confirm('Remove this certificate from the inventory? Nothing is uninstalled from any server.')) return
    setBusy(true)
    const res = await apiDelete(`/api/v1/certificates/${id}`)
    setBusy(false)
    if (res.ok) navigate('/certificates')
    else alert(`It could not be removed (${res.status}). It may still be bound to a server.`)
  }

  /**
   * Withdraws a version at the CA (FR-009). When the CA cannot be reached the operator is offered
   * the record-only path, because a revocation done by hand in the CA's portal still has to be
   * visible here — an inventory that disagrees with reality is worse than no inventory.
   */
  async function revoke(versionId: string) {
    const reason = window.prompt('Why is this being revoked? (keyCompromise, superseded, cessationOfOperation…)',
      'superseded')
    if (!reason) return
    setBusy(true)
    let res = await apiPost(`/api/v1/certificates/versions/${versionId}/revoke`,
      { reason, revokedBy: 'ui', recordOnly: false })
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      const recordOnly = confirm(
        `The CA did not accept the revocation: ${body.title ?? res.status}\n\n`
        + 'Record it here anyway, as revoked outside RemoteSSL?')
      if (recordOnly) {
        res = await apiPost(`/api/v1/certificates/versions/${versionId}/revoke`,
          { reason, revokedBy: 'ui', recordOnly: true })
      }
    }
    setBusy(false)
    if (res.ok) reload()
  }

  if (loading && !data) return <Page title="Certificate"><Loading what="this certificate" /></Page>
  if (error) return <Page title="Certificate"><Problem error={error} /></Page>
  if (!data) return null

  const o = data.overview
  const current = data.versions.find((v) => v.status === 'Active') ?? data.versions[0]

  /** Reinstall exactly where it already lives — the usual move after a renewal. */
  function installEverywhere() {
    if (!data) return
    setInstalling(data.stores.map((s) => {
      let service: Record<string, string> = {}
      try {
        const parsed = JSON.parse(s.serviceBindingJson || '{}') as Record<string, unknown>
        for (const [k, v] of Object.entries(parsed)) {
          if (typeof v === 'string' || typeof v === 'number') service[k] = String(v)
        }
      } catch { service = {} }
      return {
        targetId: s.targetId,
        targetName: s.target,
        adapterType: s.adapter,
        siteName: service.iisSiteName ?? service.certPath ?? s.alias ?? s.storePath,
        storeId: s.storeId,
        storePath: s.storePath,
        service,
        currently: null,
      }
    }))
  }

  return (
    <Page
      title={data.commonName}
      lead={[o.environment, o.ca ? `issued by ${o.ca}` : o.issuerDn ?? undefined]
        .filter(Boolean).join(' · ') || undefined}
      actions={
        <>
          <button className="primary" onClick={() => setParams({ renew: '1' })}>Renew</button>
          <button onClick={() => navigate('/certificates')}>Back to list</button>
          <button className="danger" onClick={remove} disabled={busy}>Remove</button>
        </>
      }
    >
      <div className="split">
        <Card title="How long is left">
          <p className="headline"><Expiry days={o.daysUntilExpiry} /></p>
          <dl className="facts">
            <dt>Expires</dt><dd>{shortDate(o.notAfter)}</dd>
            <dt>Key</dt><dd>{current ? `${current.publicKeyAlgorithm} ${current.keySize}` : '—'}</dd>
            <dt>Also covers</dt>
            <dd>{o.sans.length > 0 ? o.sans.join(', ') : <span className="muted">no additional names</span>}</dd>
            <dt>Fingerprint</dt>
            <dd className="mono small">{current ? `${current.sha256Thumbprint.slice(0, 24)}…` : '—'}</dd>
          </dl>
        </Card>

        <Card
          title={`Where it is serving (${data.stores.length})`}
          aside={data.stores.length > 0
            ? <button onClick={installEverywhere}>Install current version everywhere</button>
            : undefined}
        >
          {data.stores.length === 0 ? (
            <p className="muted small">
              Not installed anywhere yet. Open a server under <strong>Servers</strong>, ask what it
              is serving, and put this certificate on the sites that need it.
            </p>
          ) : (
            <table className="grid">
              <thead><tr><th>Server</th><th>Place</th><th>Runs</th></tr></thead>
              <tbody>
                {data.stores.map((s) => (
                  <tr key={s.bindingId}>
                    <td>{s.target}</td>
                    <td className="small muted">{s.alias ?? s.storePath}</td>
                    <td className="small">{s.adapter}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {data.monitors.length > 0 && (
        <Card title="Seen in the wild">
          <table className="grid">
            <thead><tr><th>Address</th><th>Last seen serving this</th></tr></thead>
            <tbody>
              {data.monitors.map((m) => (
                <tr key={m.monitorId}>
                  <td>{m.host}:{m.port}</td>
                  <td className="small muted">{shortDateTime(m.lastSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Card title="The files, and older versions">
        <p className="muted small">
          Download what the CA issued, or withdraw a version that must no longer be trusted.
          The private key is never downloadable — it is what makes the certificate yours.
        </p>
        <table className="grid">
          <thead><tr><th>Valid from</th><th>Until</th><th>Status</th><th>Files</th><th></th></tr></thead>
          <tbody>
            {data.versions.map((v) => (
              <tr key={v.id}>
                <td>{shortDate(v.notBefore)}</td>
                <td>{shortDate(v.notAfter)}</td>
                <td><Pill tone={v.status === 'Active' ? 'calm' : v.status === 'Revoked' ? 'critical' : 'plain'}>
                  {v.status}
                </Pill></td>
                <td className="small">
                  <a href={`${API_BASE}/api/v1/certificates/versions/${v.id}/download?kind=cert`}>certificate</a>
                  {' · '}
                  <a href={`${API_BASE}/api/v1/certificates/versions/${v.id}/download?kind=fullchain`}>with chain</a>
                </td>
                <td>
                  {v.status !== 'Revoked' && (
                    <button className="danger ghost" onClick={() => revoke(v.id)} disabled={busy}>Revoke</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      {data.deployments.length > 0 && (
        <Card title="Installation history">
          <table className="grid">
            <thead><tr><th>When</th><th>Result</th><th>Places</th><th></th></tr></thead>
            <tbody>
              {data.deployments.slice(0, 8).map((d) => (
                <tr key={d.jobId}>
                  <td className="small">{shortDateTime(d.createdAt)}</td>
                  <td>
                    <Pill tone={d.status === 'Succeeded' ? 'calm' : d.status === 'Running' ? 'plain' : 'critical'}>
                      {d.status}
                    </Pill>
                  </td>
                  <td className="small">
                    {d.targetCount}{d.failedTargets > 0 && <span className="bad"> · {d.failedTargets} failed</span>}
                  </td>
                  <td><button onClick={() => navigate(`/activity/${d.jobId}`)}>Open</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {renewing && (
        <StartRenewal
          certificateId={data.id}
          commonName={data.commonName}
          sans={o.sans}
          keySize={current?.keySize ?? 2048}
          keyAlgorithm={current?.publicKeyAlgorithm ?? 'RSA'}
          environment={o.environment}
          onClose={() => setParams({})}
          onStarted={(requestId) => navigate(`/renewals/${requestId}`)}
        />
      )}

      {installing && (
        <InstallWizard
          preset={installing}
          onClose={() => setInstalling(null)}
          onInstalled={() => { setInstalling(null); reload() }}
        />
      )}
    </Page>
  )
}

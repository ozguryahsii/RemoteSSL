import { useState } from 'react'
import { useData, post } from './SimplePages'

interface RequestRow {
  id: string; commonName: string; state: string; keyAlgorithm: string; keySizeOrCurve: number
  caConnectorId: string | null; errorMessage: string | null; issuedVersionId: string | null
  requestedBy: string; createdAt: string
}

export default function Requests() {
  const [requests, reload] = useData<RequestRow[]>('/api/v1/certificates/requests', 15000)
  const [connectors] = useData<{ id: string; name: string; connectorType: string }[]>('/api/v1/ca-connectors')
  const [cn, setCn] = useState(''); const [sans, setSans] = useState('')
  const [alg, setAlg] = useState('RSA'); const [size, setSize] = useState('2048'); const [caId, setCaId] = useState('')
  const [csr, setCsr] = useState<string | null>(null)

  async function create(e: React.FormEvent) {
    e.preventDefault()
    const res = await post('/api/v1/certificates/requests', {
      commonName: cn, sans: sans.split(',').map((s) => s.trim()).filter(Boolean),
      keyAlgorithm: alg, keySizeOrCurve: Number(size), caConnectorId: caId || null, requestedBy: 'ui',
    })
    const body = await res.json()
    setCsr(body.csrPem ?? null)
    setCn(''); setSans(''); reload()
  }

  async function uploadIssued(id: string) {
    const certPem = window.prompt('Paste the signed certificate PEM:')
    if (!certPem) return
    const chainPem = window.prompt('Paste the chain PEM (optional):') || null
    const res = await post(`/api/v1/certificates/requests/${id}/certificate`, { certPem, chainPem })
    if (!res.ok) alert('Upload failed: ' + (await res.json()).title)
    reload()
  }

  const stateClass = (s: string) =>
    s === 'Issued' || s === 'ReadyForDeployment' ? 'ok'
      : s.startsWith('Failed') || s === 'Rejected' ? 'bad' : 'warn'

  return (
    <div className="page">
      <h1>Certificate Requests</h1>
      <form className="inline-form" onSubmit={create}>
        <input value={cn} onChange={(e) => setCn(e.target.value)} placeholder="common name" required />
        <input value={sans} onChange={(e) => setSans(e.target.value)} placeholder="SANs (comma separated)" />
        <select value={alg} onChange={(e) => setAlg(e.target.value)}><option>RSA</option><option>EC</option></select>
        <select value={size} onChange={(e) => setSize(e.target.value)}>
          {alg === 'RSA' ? ['2048', '3072', '4096'].map((s) => <option key={s}>{s}</option>)
            : ['256', '384'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={caId} onChange={(e) => setCaId(e.target.value)}>
          <option value="">CSR only (no CA)</option>
          {(connectors ?? []).map((c) => <option key={c.id} value={c.id}>{c.name} ({c.connectorType})</option>)}
        </select>
        <button type="submit">Create request</button>
      </form>

      {csr && (
        <div className="detail-panel">
          <div className="detail-header"><h3>Generated CSR</h3><button onClick={() => setCsr(null)}>Close</button></div>
          <pre className="small" style={{ overflowX: 'auto' }}>{csr}</pre>
        </div>
      )}

      <table className="data-table">
        <thead><tr><th>Common name</th><th>State</th><th>Key</th><th>Requested by</th><th>Created</th><th></th></tr></thead>
        <tbody>
          {(requests ?? []).map((r) => (
            <tr key={r.id}>
              <td>{r.commonName}</td>
              <td>
                <span className={stateClass(r.state)}>{r.state}</span>
                {r.errorMessage && <div className="bad small">{r.errorMessage}</div>}
              </td>
              <td>{r.keyAlgorithm} {r.keySizeOrCurve}</td>
              <td>{r.requestedBy}</td>
              <td className="small muted">{new Date(r.createdAt).toLocaleString()}</td>
              <td className="actions">
                {['WaitingForCertificate', 'CsrGenerated', 'PendingIssuance'].includes(r.state) && (
                  <button onClick={() => uploadIssued(r.id)}>Upload issued cert</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

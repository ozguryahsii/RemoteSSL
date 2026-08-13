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
  const [org, setOrg] = useState(''); const [ou, setOu] = useState('')
  const [city, setCity] = useState(''); const [state, setState] = useState(''); const [country, setCountry] = useState('')
  const [csr, setCsr] = useState<string | null>(null)
  // In-app upload modal state
  const [uploadFor, setUploadFor] = useState<RequestRow | null>(null)
  const [certPem, setCertPem] = useState(''); const [chainPem, setChainPem] = useState('')
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)

  async function create(e: React.FormEvent) {
    e.preventDefault()
    const res = await post('/api/v1/certificates/requests', {
      commonName: cn, sans: sans.split(',').map((s) => s.trim()).filter(Boolean),
      keyAlgorithm: alg, keySizeOrCurve: Number(size), caConnectorId: caId || null, requestedBy: 'ui',
      organization: org || null, organizationalUnit: ou || null,
      locality: city || null, state: state || null, country: country || null,
    })
    const body = await res.json()
    setCsr(body.csrPem ?? null)
    setCn(''); setSans(''); reload()
  }

  function openUpload(r: RequestRow) {
    setUploadFor(r); setCertPem(''); setChainPem(''); setUploadError(null)
  }

  function readFileInto(setter: (v: string) => void) {
    return (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (!file) return
      const reader = new FileReader()
      reader.onload = () => setter(String(reader.result ?? ''))
      reader.readAsText(file)
    }
  }

  async function submitUpload() {
    if (!uploadFor) return
    setUploading(true); setUploadError(null)
    try {
      const res = await post(`/api/v1/certificates/requests/${uploadFor.id}/certificate`, {
        certPem, chainPem: chainPem || null,
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setUploadError(body.title ?? `Upload failed (${res.status})`)
        return
      }
      setUploadFor(null); reload()
    } finally { setUploading(false) }
  }

  const stateClass = (s: string) =>
    s === 'Issued' || s === 'ReadyForDeployment' ? 'ok'
      : s.startsWith('Failed') || s === 'Rejected' ? 'bad' : 'warn'

  return (
    <div className="page">
      <h1>Certificate Requests</h1>
      <form onSubmit={create}>
        <div className="inline-form">
          <input value={cn} onChange={(e) => setCn(e.target.value)} placeholder="common name *" required />
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
        </div>
        <div className="inline-form">
          <input value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Organization (O)" />
          <input value={ou} onChange={(e) => setOu(e.target.value)} placeholder="Org. Unit (OU)" />
          <input value={city} onChange={(e) => setCity(e.target.value)} placeholder="City / Locality (L)" />
          <input value={state} onChange={(e) => setState(e.target.value)} placeholder="State (ST)" />
          <input value={country} onChange={(e) => setCountry(e.target.value)} placeholder="Country (C, e.g. TR)"
                 maxLength={2} style={{ width: 140 }} />
          <button type="submit">Create request</button>
        </div>
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
                  <button onClick={() => openUpload(r)}>Upload issued cert</button>
                )}
              </td>
            </tr>
          ))}
          {(requests ?? []).length === 0 && (
            <tr><td colSpan={6} className="muted">No requests yet. Fill the form above to generate a CSR (and optionally submit it to a CA).</td></tr>
          )}
        </tbody>
      </table>

      {uploadFor && (
        <div className="modal-overlay" onClick={() => !uploading && setUploadFor(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="detail-header">
              <h3>Upload issued certificate — {uploadFor.commonName}</h3>
              <button onClick={() => setUploadFor(null)} disabled={uploading}>Close</button>
            </div>
            <p className="muted small">
              This is the CA's response to your CSR: the signed certificate (PEM/.crt/.cer) and optionally its
              chain. Paste the PEM content or pick a file — the request then moves to <b>Issued</b> and the
              certificate lands in the inventory, ready for deployment.
            </p>
            <label className="small"><b>Certificate (leaf) *</b> — paste PEM or choose file</label>
            <input type="file" accept=".pem,.crt,.cer,.txt" onChange={readFileInto(setCertPem)} />
            <textarea value={certPem} onChange={(e) => setCertPem(e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE-----" rows={7} />
            <label className="small"><b>Chain (intermediates)</b> — optional</label>
            <input type="file" accept=".pem,.crt,.cer,.txt" onChange={readFileInto(setChainPem)} />
            <textarea value={chainPem} onChange={(e) => setChainPem(e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE----- (optional)" rows={4} />
            {uploadError && <p className="error small">{uploadError}</p>}
            <div className="actions" style={{ justifyContent: 'flex-end' }}>
              <button onClick={submitUpload} disabled={uploading || !certPem.includes('BEGIN CERTIFICATE')}>
                {uploading ? 'Uploading…' : 'Upload'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

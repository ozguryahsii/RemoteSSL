import { useState } from 'react'
import { apiDelete, apiGet, apiPost } from '../api/client'
import { useData, post, MAX_PAGE, TruncationNotice } from './SimplePages'

interface RequestRow {
  id: string; commonName: string; state: string; keyAlgorithm: string; keySizeOrCurve: number
  caConnectorId: string | null; errorMessage: string | null; issuedVersionId: string | null
  requestedBy: string; environment: string | null; ownerId: string | null; createdAt: string
}

interface PolicyFinding { rule: string; message: string }

/** One outstanding proof of domain control (design doc §18.1). */
interface DomainValidationRow {
  id: string; domain: string; method: string; state: string
  expectedDnsRecord: string | null; expectedHttpResponse: string | null
  detail: string | null; expiresAt: string | null
}

export default function Requests() {
  const [requests, reload, , requestTotal] = useData<RequestRow[]>(`/api/v1/certificates/requests?take=${MAX_PAGE}`, 15000)
  const [connectors] = useData<{ id: string; name: string; connectorType: string }[]>('/api/v1/ca-connectors')
  const [cn, setCn] = useState(''); const [sans, setSans] = useState('')
  const [alg, setAlg] = useState('RSA'); const [size, setSize] = useState('2048'); const [caId, setCaId] = useState('')
  const [org, setOrg] = useState(''); const [ou, setOu] = useState('')
  const [city, setCity] = useState(''); const [state, setState] = useState(''); const [country, setCountry] = useState('')
  const [environment, setEnvironment] = useState(''); const [owner, setOwner] = useState('')
  const [validityDays, setValidityDays] = useState('')
  const [csr, setCsr] = useState<string | null>(null)
  const [policyError, setPolicyError] = useState<PolicyFinding[] | null>(null)
  const [warnings, setWarnings] = useState<PolicyFinding[]>([])
  const [notice, setNotice] = useState<string | null>(null)
  // In-app upload modal state
  const [uploadFor, setUploadFor] = useState<RequestRow | null>(null)
  const [certPem, setCertPem] = useState(''); const [chainPem, setChainPem] = useState('')
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  // §18.1 domain validation: what the CA wants published, for which name.
  const [validationFor, setValidationFor] = useState<RequestRow | null>(null)
  const [validations, setValidations] = useState<DomainValidationRow[] | null>(null)
  const [validationBusy, setValidationBusy] = useState(false)

  async function create(e: React.FormEvent) {
    e.preventDefault()
    setPolicyError(null); setWarnings([]); setNotice(null)
    const res = await post('/api/v1/certificates/requests', {
      commonName: cn, sans: sans.split(',').map((s) => s.trim()).filter(Boolean),
      keyAlgorithm: alg, keySizeOrCurve: Number(size), caConnectorId: caId || null, requestedBy: 'ui',
      organization: org || null, organizationalUnit: ou || null,
      locality: city || null, state: state || null, country: country || null,
      environment: environment || null, ownerId: owner || null,
      requestedValidityDays: validityDays ? Number(validityDays) : null,
    })
    const body = await res.json()
    if (!res.ok) {
      // Blocking policy violations come back as problem details with the offending rules (§17.2).
      setPolicyError(body.findings ?? [{ rule: 'request', message: body.title ?? `Failed (${res.status})` }])
      return
    }
    setCsr(body.csrPem ?? null)
    setWarnings(body.warnings ?? [])
    if (body.state === 'PendingApproval')
      setNotice(`Request created and is awaiting approval — policy requires approval in ${environment}.`)
    setCn(''); setSans(''); reload()
  }

  async function decide(r: RequestRow, approve: boolean) {
    const approver = window.prompt(approve ? 'Approver username:' : 'Rejecting — your username:')
    if (!approver) return
    const reason = window.prompt('Reason (optional):') ?? undefined
    const res = await post(`/api/v1/certificates/requests/${r.id}/approve`,
      { approver, approve, reason })
    if (!res.ok) alert((await res.json()).title ?? `Decision failed (${res.status})`)
    reload()
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

  async function openValidations(r: RequestRow) {
    setValidationFor(r); setValidations(null)
    try {
      setValidations(await apiGet<DomainValidationRow[]>(`/api/v1/requests/${r.id}/validations`))
    } catch (e: unknown) {
      setNotice(e instanceof Error ? e.message : String(e))
      setValidationFor(null)
    }
  }

  /** Tells the CA the proof is published; the CA verifies asynchronously. */
  async function submitValidation(v: DomainValidationRow) {
    if (!validationFor) return
    setValidationBusy(true)
    try {
      const res = await apiPost(`/api/v1/requests/${validationFor.id}/validations/${v.id}/submit`)
      if (!res.ok) setNotice((await res.json()).title ?? `Submit failed (${res.status})`)
      await openValidations(validationFor)
    } finally { setValidationBusy(false) }
  }

  return (
    <div className="page">
      <h1>Certificate Requests</h1>
      <TruncationNotice shown={(requests ?? []).length} total={requestTotal} />
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
          <input value={environment} onChange={(e) => setEnvironment(e.target.value)}
                 placeholder="Environment (e.g. PROD)" style={{ width: 170 }}
                 title="Drives approval and maintenance-window policy" />
          <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Owner" style={{ width: 130 }} />
          <input value={validityDays} onChange={(e) => setValidityDays(e.target.value)} type="number"
                 placeholder="Validity (days)" style={{ width: 140 }} />
          <button type="submit">Create request</button>
        </div>
      </form>

      {policyError && (
        <div className="alert-list">
          {policyError.map((f, i) => (
            <div key={i} className="alert-row critical"><strong>{f.rule}</strong> — {f.message}</div>
          ))}
        </div>
      )}
      {warnings.length > 0 && (
        <div className="alert-list">
          {warnings.map((f, i) => (
            <div key={i} className="alert-row warning"><strong>{f.rule}</strong> — {f.message}</div>
          ))}
        </div>
      )}
      {notice && <p className="warn">{notice}</p>}

      {csr && (
        <div className="detail-panel">
          <div className="detail-header"><h3>Generated CSR</h3><button onClick={() => setCsr(null)}>Close</button></div>
          <pre className="small" style={{ overflowX: 'auto' }}>{csr}</pre>
        </div>
      )}

      <table className="data-table">
        <thead><tr><th>Common name</th><th>State</th><th>Key</th><th>Environment</th><th>Requested by</th><th>Created</th><th></th></tr></thead>
        <tbody>
          {(requests ?? []).map((r) => (
            <tr key={r.id}>
              <td>{r.commonName}</td>
              <td>
                <span className={stateClass(r.state)}>{r.state}</span>
                {r.errorMessage && <div className="bad small">{r.errorMessage}</div>}
              </td>
              <td>{r.keyAlgorithm} {r.keySizeOrCurve}</td>
              <td className="small">{r.environment ?? '—'}{r.ownerId && <div className="muted">owner: {r.ownerId}</div>}</td>
              <td>{r.requestedBy}</td>
              <td className="small muted">{new Date(r.createdAt).toLocaleString()}</td>
              <td className="actions">
                {r.state === 'PendingApproval' && (
                  <>
                    <button onClick={() => decide(r, true)}>Approve</button>
                    <button className="danger" onClick={() => decide(r, false)}>Reject</button>
                  </>
                )}
                {['WaitingForCertificate', 'CsrGenerated', 'PendingIssuance'].includes(r.state) && (
                  <button onClick={() => openUpload(r)}>Upload issued cert</button>
                )}
                {['PendingIssuance', 'SubmittedToCa', 'CsrGenerated'].includes(r.state) && (
                  <button onClick={() => openValidations(r)}>Domain validation</button>
                )}
                {r.state !== 'Issued' && (
                  <button className="danger" onClick={async () => {
                    if (window.confirm('Delete this request?')) { await apiDelete(`/api/v1/certificates/requests/${r.id}`); reload() }
                  }}>Delete</button>
                )}
              </td>
            </tr>
          ))}
          {(requests ?? []).length === 0 && (
            <tr><td colSpan={7} className="muted">No requests yet. Fill the form above to generate a CSR (and optionally submit it to a CA).</td></tr>
          )}
        </tbody>
      </table>

      {validationFor && (
        <div className="detail-panel">
          <div className="detail-header">
            <h3>Domain validation — {validationFor.commonName}</h3>
            <button onClick={() => { setValidationFor(null); setValidations(null) }}>Close</button>
          </div>
          <p className="muted small">
            The CA needs proof that you control each name. Publish what it asks for, then press
            Verify — the CA checks asynchronously, so the state moves to Valid on its own.
          </p>
          {validations === null && <p className="small">Loading…</p>}
          {validations?.length === 0 && (
            <p className="small ok">Nothing outstanding: every name on this request is already authorized.</p>
          )}
          {(validations ?? []).map((v) => (
            <div key={v.id} className="plan-box">
              <h4>{v.domain} <span className="tag">{v.method}</span></h4>
              <dl className="kv">
                <dt>State</dt>
                <dd>
                  <span className={v.state === 'Valid' ? 'ok' : v.state === 'Failed' ? 'bad' : ''}>{v.state}</span>
                  {v.detail ? ` — ${v.detail}` : ''}
                </dd>
                {v.expectedDnsRecord && <><dt>Publish this DNS record</dt>
                  <dd><pre className="pem-block">{v.expectedDnsRecord}</pre></dd></>}
                {v.expectedHttpResponse && <><dt>Serve this over HTTP</dt>
                  <dd><pre className="pem-block">{v.expectedHttpResponse}</pre></dd></>}
                {v.expiresAt && <><dt>Expires</dt><dd>{new Date(v.expiresAt).toLocaleString()}</dd></>}
              </dl>
              {v.state !== 'Valid' && (
                <button onClick={() => submitValidation(v)} disabled={validationBusy}>
                  {validationBusy ? 'Asking the CA…' : 'I have published it — verify'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}

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

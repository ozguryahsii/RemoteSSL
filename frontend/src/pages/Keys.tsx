import { useState } from 'react'
import { apiDelete, apiPost } from '../api/client'
import { useData, post } from './SimplePages'

type KeyRow = {
  id: string; label: string; provider: string; reference: string; algorithm: string
  sizeOrCurve: number; exportable: boolean; ownerId: string | null; ownerTeam: string | null
  environment: string | null; purpose: string | null; createdBy: string; createdAt: string
  lastUsedAt: string | null; destroyedAt: string | null
}

const ALGORITHMS = ['RSA', 'EC'] as const

/**
 * Managed private keys (design doc §16.3). Software keys live encrypted in the control plane;
 * PKCS#11 and cloud HSM keys never leave their token, which is why their export column always
 * reads "no" and the export button is absent.
 */
export default function Keys() {
  const [keys, reload, error] = useData<KeyRow[]>('/api/v1/keys')
  const [providers] = useData<{ provider: string; enabled: boolean }[]>('/api/v1/keys/providers', 300000)

  const [label, setLabel] = useState('')
  const [provider, setProvider] = useState('Software')
  const [algorithm, setAlgorithm] = useState<string>('RSA')
  const [size, setSize] = useState('3072')
  const [exportable, setExportable] = useState(false)
  const [ownerId, setOwnerId] = useState('')
  const [ownerTeam, setOwnerTeam] = useState('')
  const [environment, setEnvironment] = useState('')
  const [purpose, setPurpose] = useState('')
  const [message, setMessage] = useState<string | null>(null)

  const [csrFor, setCsrFor] = useState<KeyRow | null>(null)
  const [subject, setSubject] = useState('CN=')
  const [sans, setSans] = useState('')
  const [csrPem, setCsrPem] = useState<string | null>(null)

  async function create(e: React.FormEvent) {
    e.preventDefault()
    setMessage(null)
    const res = await post('/api/v1/keys', {
      label, provider, algorithm, sizeOrCurve: Number(size),
      exportable, ownerId: ownerId || null, ownerTeam: ownerTeam || null,
      environment: environment || null, purpose: purpose || null,
    }).catch((err: unknown) => { setMessage(err instanceof Error ? err.message : String(err)); return null })
    if (!res) return
    setLabel(''); setOwnerId(''); setOwnerTeam(''); setEnvironment(''); setPurpose(''); reload()
  }

  async function makeCsr() {
    if (!csrFor) return
    setMessage(null); setCsrPem(null)
    try {
      const res = await apiPost(`/api/v1/keys/${csrFor.id}/csr`, {
        subject, sans: sans.split(',').map((s) => s.trim()).filter(Boolean),
      })
      const body = await res.json()
      setCsrPem(body.csrPem)
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : String(err))
    }
  }

  async function exportKey(k: KeyRow) {
    setMessage(null)
    try {
      const res = await apiPost(`/api/v1/keys/${k.id}/export`)
      const body = await res.json()
      setCsrFor(null); setCsrPem(body.privateKeyPem)
    } catch (err: unknown) {
      setMessage(err instanceof Error ? err.message : String(err))
    }
  }

  async function destroy(k: KeyRow) {
    if (!window.confirm(`Destroy key “${k.label}”? This cannot be undone.`)) return
    const res = await apiDelete(`/api/v1/keys/${k.id}`)
    if (!res.ok) setMessage(`Destroy failed: ${res.status}`)
    reload()
  }

  return (
    <div className="page">
      <p className="muted small">
        Private keys under management. A key created non-exportable can never be read back — that
        is enforced by the platform for software keys and by the device itself for HSM keys.
      </p>
      {error && <p className="bad small">{error}</p>}
      {message && <p className="bad small">{message}</p>}

      <form className="inline-form" onSubmit={create}>
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="label" required />
        <select value={provider} onChange={(e) => setProvider(e.target.value)}>
          {(providers ?? [{ provider: 'Software', enabled: true }]).map((p) => (
            <option key={p.provider} value={p.provider} disabled={!p.enabled}>
              {p.provider}{p.enabled ? '' : ' (not configured)'}
            </option>
          ))}
        </select>
        <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
          {ALGORITHMS.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <input value={size} onChange={(e) => setSize(e.target.value)} type="number" style={{ width: 90 }}
          title={algorithm === 'EC' ? 'Curve size: 256, 384 or 521' : 'RSA modulus size'} />
        <label className="small">
          <input type="checkbox" checked={exportable} disabled={provider !== 'Software'}
            onChange={(e) => setExportable(e.target.checked)} /> exportable
        </label>
        <input value={ownerId} onChange={(e) => setOwnerId(e.target.value)} placeholder="owner" />
        <input value={ownerTeam} onChange={(e) => setOwnerTeam(e.target.value)} placeholder="team" />
        <input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="environment" />
        <input value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="purpose" />
        <button type="submit">Create key</button>
      </form>

      {csrFor && (
        <div className="inline-form" style={{ marginTop: 8 }}>
          <strong>CSR for “{csrFor.label}”</strong>
          <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="CN=example.com" style={{ width: 220 }} />
          <input value={sans} onChange={(e) => setSans(e.target.value)} placeholder="SANs, comma separated" style={{ width: 220 }} />
          <button onClick={makeCsr}>Generate CSR</button>
          <button onClick={() => { setCsrFor(null); setCsrPem(null) }}>Close</button>
        </div>
      )}
      {csrPem && <pre className="pem-block">{csrPem}</pre>}

      <table className="data-table">
        <thead><tr>
          <th>Label</th><th>Provider</th><th>Algorithm</th><th>Exportable</th><th>Owner</th>
          <th>Environment</th><th>Purpose</th><th>Created</th><th>Last used</th><th></th>
        </tr></thead>
        <tbody>
          {(keys ?? []).map((k) => (
            <tr key={k.id}>
              <td title={k.reference}>{k.label}</td>
              <td className="small">{k.provider}</td>
              <td className="small">{k.algorithm}-{k.sizeOrCurve}</td>
              <td className="small">{k.exportable ? <span className="bad">yes</span> : <span className="ok">no</span>}</td>
              <td className="small">{k.ownerId ?? '—'}{k.ownerTeam ? ` / ${k.ownerTeam}` : ''}</td>
              <td className="small">{k.environment ?? '—'}</td>
              <td className="small">{k.purpose ?? '—'}</td>
              <td className="small muted">{new Date(k.createdAt).toLocaleDateString()} — {k.createdBy}</td>
              <td className="small muted">{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : 'never'}</td>
              <td className="actions">
                <button onClick={() => { setCsrFor(k); setCsrPem(null); setSubject('CN=') }}>CSR</button>
                {k.exportable && <button onClick={() => exportKey(k)}>Export</button>}
                <button className="danger" onClick={() => destroy(k)}>Destroy</button>
              </td>
            </tr>
          ))}
          {(keys ?? []).length === 0 && <tr><td colSpan={10} className="muted">No managed keys yet.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

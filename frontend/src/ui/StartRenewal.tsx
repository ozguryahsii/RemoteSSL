import { useState } from 'react'
import { apiPost } from '../api/client'
import { Modal, Field, Problem } from './kit'

/**
 * Begins a renewal: RemoteSSL keeps the private key and produces the CSR.
 *
 * Everything is pre-filled from the certificate being replaced, because a renewal is by
 * definition the same names again — retyping them is only an opportunity to get one wrong and
 * find out months later, from a browser warning.
 */
export default function StartRenewal({
  certificateId, commonName, sans, keySize, keyAlgorithm, environment, onClose, onStarted,
}: {
  /** Null when this is a first certificate rather than a replacement for an existing one. */
  certificateId: string | null
  commonName: string
  sans: string[]
  keySize: number
  keyAlgorithm: string
  environment: string | null
  onClose: () => void
  onStarted: (requestId: string) => void
}) {
  const [cn, setCn] = useState(commonName)
  const [names, setNames] = useState(sans.join(', '))
  const [algorithm, setAlgorithm] = useState(keyAlgorithm.includes('EC') ? 'ECDSA' : 'RSA')
  const [size, setSize] = useState(String(keySize >= 2048 ? keySize : 2048))
  const [organization, setOrganization] = useState('')
  const [organizationalUnit, setOrganizationalUnit] = useState('')
  const [locality, setLocality] = useState('')
  const [state, setState] = useState('')
  const [country, setCountry] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [warnings, setWarnings] = useState<string[]>([])

  async function start() {
    setBusy(true); setError(null)
    try {
      const res = await apiPost('/api/v1/certificates/requests', {
        commonName: cn.trim(),
        sans: names.split(',').map((s) => s.trim()).filter(Boolean),
        keyAlgorithm: algorithm,
        keySizeOrCurve: Number(size) || 2048,
        keyOrigin: 'central',
        requestedBy: 'ui',
        certificateId,
        environment,
        organization: organization.trim() || null,
        organizationalUnit: organizationalUnit.trim() || null,
        locality: locality.trim() || null,
        state: state.trim() || null,
        country: country.trim() || null,
      })
      const body = await res.json()
      if (!res.ok) {
        const findings = (body.findings as { message: string }[] | undefined)?.map((f) => f.message)
        throw new Error([body.title, ...(findings ?? [])].filter(Boolean).join(' — '))
      }
      setWarnings((body.warnings as { message: string }[] | undefined)?.map((w) => w.message) ?? [])
      onStarted(body.id as string)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  return (
    <Modal title={certificateId ? `Renew ${commonName}` : 'Request a certificate'} onClose={onClose} wide>
      {error && <Problem error={error} />}
      {warnings.map((w, i) => <p key={i} className="notice warn small">{w}</p>)}

      <p className="muted small">
        RemoteSSL generates a new private key and a CSR from these details. You send the CSR to
        your CA; when the signed certificate comes back you upload it here and install it where
        the old one is serving. The private key never leaves this server until then.
      </p>

      <div className="form-grid">
        <Field label="Common name"><input value={cn} onChange={(e) => setCn(e.target.value)} /></Field>
        <Field label="Also covers (SAN)" hint="Comma separated. Keep the same names unless something changed.">
          <input value={names} onChange={(e) => setNames(e.target.value)} placeholder="www.example.com, api.example.com" />
        </Field>
        <Field label="Key type">
          <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
            <option value="RSA">RSA</option>
            <option value="ECDSA">ECDSA</option>
          </select>
        </Field>
        <Field label={algorithm === 'RSA' ? 'Key size' : 'Curve'}>
          <select value={size} onChange={(e) => setSize(e.target.value)}>
            {algorithm === 'RSA'
              ? <>
                <option value="2048">2048</option>
                <option value="3072">3072</option>
                <option value="4096">4096</option>
              </>
              : <>
                <option value="256">P-256</option>
                <option value="384">P-384</option>
              </>}
          </select>
        </Field>
      </div>

      <details>
        <summary>Organisation details (most commercial CAs ask for these)</summary>
        <div className="form-grid">
          <Field label="Organisation (O)"><input value={organization} onChange={(e) => setOrganization(e.target.value)} /></Field>
          <Field label="Unit (OU)"><input value={organizationalUnit} onChange={(e) => setOrganizationalUnit(e.target.value)} /></Field>
          <Field label="City (L)"><input value={locality} onChange={(e) => setLocality(e.target.value)} /></Field>
          <Field label="State / province (ST)"><input value={state} onChange={(e) => setState(e.target.value)} /></Field>
          <Field label="Country (C)" hint="Two letters, e.g. TR">
            <input value={country} maxLength={2} onChange={(e) => setCountry(e.target.value.toUpperCase())} />
          </Field>
        </div>
      </details>

      <div className="row-actions">
        <button className="primary" onClick={start} disabled={busy || cn.trim() === ''}>
          {busy ? 'Generating…' : 'Generate the CSR'}
        </button>
        <button className="ghost" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  )
}

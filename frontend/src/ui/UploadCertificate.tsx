import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiPost } from '../api/client'
import { Modal, Field, Problem } from './kit'

/**
 * Takes a certificate the operator already has into the inventory.
 *
 * Estates do not start empty: the certificates that expire unnoticed are the ones bought years
 * ago and installed by hand. Tracking has to begin with those, without pretending this product
 * issued them.
 */
export default function UploadCertificate({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [certPem, setCertPem] = useState('')
  const [chainPem, setChainPem] = useState('')
  const [keyPem, setKeyPem] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  async function save() {
    setBusy(true); setError(null)
    try {
      const res = await apiPost('/api/v1/certificates/import', {
        certPem,
        chainPem: chainPem.trim() || null,
        keyPem: keyPem.trim() || null,
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.title ?? `Import failed (${res.status})`)
      onDone()
      navigate(`/certificates/${body.certificateId}`)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  async function readInto(file: File | undefined, set: (text: string) => void) {
    if (file) set(await file.text())
  }

  return (
    <Modal title="Add a certificate you already have" onClose={onClose} wide>
      {error && <Problem error={error} />}
      <p className="muted small">
        Paste the PEM text, or pick the file. RemoteSSL reads the name, the dates and the issuer
        from the certificate itself — there is nothing else to fill in.
      </p>

      <Field label="Certificate (required)" hint="Begins with -----BEGIN CERTIFICATE-----">
        <>
          <input type="file" accept=".pem,.crt,.cer,.txt"
            onChange={(e) => readInto(e.target.files?.[0], setCertPem)} />
          <textarea rows={7} value={certPem} onChange={(e) => setCertPem(e.target.value)}
            placeholder="-----BEGIN CERTIFICATE-----" />
        </>
      </Field>

      <Field label="Chain (optional)" hint="Intermediates, if the CA sent them separately.">
        <textarea rows={4} value={chainPem} onChange={(e) => setChainPem(e.target.value)} />
      </Field>

      <Field
        label="Private key (optional)"
        hint="Needed only to install this certificate on a server. Stored encrypted and never shown again."
      >
        <textarea rows={4} value={keyPem} onChange={(e) => setKeyPem(e.target.value)}
          placeholder="-----BEGIN PRIVATE KEY-----" />
      </Field>

      <div className="row-actions">
        <button className="primary" onClick={save} disabled={busy || certPem.trim() === ''}>
          {busy ? 'Reading…' : 'Add to inventory'}
        </button>
        <button className="ghost" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  )
}

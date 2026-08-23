import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { apiPost, apiDelete, API_BASE } from '../api/client'
import { Page, Card, Loading, Problem, useApi, CopyButton, Field, shortDateTime, Pill } from './kit'
import InstallWizard, { type PresetLocation } from './InstallWizard'

/**
 * A renewal, shown as the three things a person actually does with a commercial CA: take the
 * CSR, wait, then bring back what was signed and put it where the old certificate is serving.
 *
 * The states the engine tracks are finer than that, but an operator does not need a state
 * machine — they need to know whether the ball is with them or with the CA.
 */

interface Place {
  id: string; storeId: string; targetId: string; target: string
  adapter: string; storePath: string; alias: string | null; serviceBindingJson: string
}

interface Renewal {
  id: string
  certificateId: string | null
  commonName: string
  sansJson: string
  keyAlgorithm: string
  keySizeOrCurve: number
  state: string
  csrPem: string | null
  errorMessage: string | null
  issuedVersionId: string | null
  environment: string | null
  createdAt: string
  updatedAt: string
  places: Place[]
}

/** Which of the three steps this renewal is on, in the operator's terms. */
function stage(state: string): 1 | 2 | 3 {
  if (['Issued', 'ReadyForDeployment', 'Active'].includes(state)) return 3
  if (['SubmittedToCa', 'PendingIssuance', 'WaitingForCertificate'].includes(state)) return 2
  return 1
}

const STEPS = ['Take the CSR to your CA', 'Wait for the signed certificate', 'Install it where it is used']

export default function Renewal() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { data, error, loading, reload } = useApi<Renewal>(id ? `/api/v1/certificates/requests/${id}` : null)

  const [certPem, setCertPem] = useState('')
  const [chainPem, setChainPem] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)
  const [installing, setInstalling] = useState<PresetLocation[] | null>(null)

  async function upload() {
    setBusy(true); setProblem(null)
    try {
      const res = await apiPost(`/api/v1/certificates/requests/${id}/certificate`, {
        certPem: certPem.trim(), chainPem: chainPem.trim() || null,
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.title ?? `The certificate was not accepted (${res.status})`)
      }
      setCertPem(''); setChainPem('')
      reload()
    } catch (e: unknown) {
      setProblem(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  async function abandon() {
    if (!confirm('Abandon this renewal? The generated key and CSR are discarded.')) return
    const res = await apiDelete(`/api/v1/certificates/requests/${id}`)
    if (res.ok) navigate('/renewals')
    else alert(`It could not be removed (${res.status}).`)
  }

  function installWhereItIsUsed() {
    if (!data) return
    setInstalling(data.places.map((p) => {
      let service: Record<string, string> = {}
      try {
        const parsed = JSON.parse(p.serviceBindingJson || '{}') as Record<string, unknown>
        for (const [k, v] of Object.entries(parsed)) {
          if (typeof v === 'string' || typeof v === 'number') service[k] = String(v)
        }
      } catch { service = {} }
      return {
        targetId: p.targetId,
        targetName: p.target,
        adapterType: p.adapter,
        siteName: service.iisSiteName ?? service.certPath ?? p.alias ?? p.storePath,
        storeId: p.storeId,
        storePath: p.storePath,
        service,
        currently: null,
      }
    }))
  }

  if (loading && !data) return <Page title="Renewal"><Loading what="this renewal" /></Page>
  if (error) return <Page title="Renewal"><Problem error={error} /></Page>
  if (!data) return null

  const at = stage(data.state)
  const sans: string[] = (() => { try { return JSON.parse(data.sansJson) as string[] } catch { return [] } })()

  return (
    <Page
      title={`Renewing ${data.commonName}`}
      lead={`Started ${shortDateTime(data.createdAt)} · ${data.keyAlgorithm} ${data.keySizeOrCurve}`
        + (data.environment ? ` · ${data.environment}` : '')}
      actions={
        <>
          {data.certificateId && (
            <button onClick={() => navigate(`/certificates/${data.certificateId}`)}>The certificate</button>
          )}
          <button className="danger" onClick={abandon}>Abandon</button>
        </>
      }
    >
      <ol className="steps">
        {STEPS.map((label, i) => (
          <li key={label} className={i + 1 === at ? 'current' : i + 1 < at ? 'done' : ''}>
            <span className="step-no">{i + 1}</span> {label}
          </li>
        ))}
      </ol>

      {data.errorMessage && <Problem error={data.errorMessage} />}
      {problem && <Problem error={problem} />}

      <Card title="1 · The CSR" aside={data.csrPem ? <CopyButton text={data.csrPem} label="Copy the CSR" /> : undefined}>
        {data.csrPem ? (
          <>
            <p className="muted small">
              Paste this into your CA's portal or attach it to the ticket. It contains the names
              below and the new public key; the private key stays here.
            </p>
            <p className="small">
              <strong>{data.commonName}</strong>
              {sans.length > 0 && <span className="muted"> · also {sans.join(', ')}</span>}
            </p>
            <pre className="pem">{data.csrPem}</pre>
            <a className="button" href={`${API_BASE}/api/v1/certificates/requests/${data.id}/csr`}>
              Download as a file
            </a>
          </>
        ) : (
          <p className="muted small">No CSR on this request yet.</p>
        )}
      </Card>

      <Card title="2 · What the CA sent back">
        {at === 3 ? (
          <p className="ok small">The signed certificate is in. Nothing more to upload.</p>
        ) : (
          <>
            <p className="muted small">
              When the CA issues it, paste the certificate here — the same PEM they email or the
              file you download from their portal.
            </p>
            <Field label="Certificate">
              <>
                <input type="file" accept=".pem,.crt,.cer,.txt"
                  onChange={async (e) => { const f = e.target.files?.[0]; if (f) setCertPem(await f.text()) }} />
                <textarea rows={7} value={certPem} onChange={(e) => setCertPem(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----" />
              </>
            </Field>
            <Field label="Chain (optional)" hint="Intermediates, when they come as a separate file.">
              <textarea rows={3} value={chainPem} onChange={(e) => setChainPem(e.target.value)} />
            </Field>
            <div className="row-actions">
              <button className="primary" onClick={upload} disabled={busy || certPem.trim() === ''}>
                {busy ? 'Checking it…' : 'Upload it'}
              </button>
            </div>
          </>
        )}
      </Card>

      <Card
        title="3 · Put it where the old one is serving"
        aside={at === 3 && data.places.length > 0
          ? <button className="primary" onClick={installWhereItIsUsed}>
            Install on {data.places.length} place(s)
          </button>
          : undefined}
      >
        {data.places.length === 0 ? (
          <p className="muted small">
            RemoteSSL does not know anywhere this certificate is installed. Find the servers under
            <strong> Servers</strong>, ask what they are serving, and install it on the sites that
            need it.
          </p>
        ) : (
          <>
            <p className="muted small">
              {at === 3
                ? 'These are the places the old certificate is serving from. Installing replaces it on each of them.'
                : 'When the signed certificate arrives it goes to these places:'}
            </p>
            <table className="grid">
              <thead><tr><th>Server</th><th>Place</th><th>Runs</th></tr></thead>
              <tbody>
                {data.places.map((p) => (
                  <tr key={p.id}>
                    <td>{p.target}</td>
                    <td className="small muted">{p.alias ?? p.storePath}</td>
                    <td className="small"><Pill tone="plain">{p.adapter}</Pill></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Card>

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

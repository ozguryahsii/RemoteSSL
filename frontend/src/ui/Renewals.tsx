import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Page, Card, Loading, Problem, Empty, useApi, Pill, shortDateTime } from './kit'
import StartRenewal from './StartRenewal'

/**
 * Renewals in flight. With a commercial CA a renewal is not an event but a week: the CSR goes
 * out, somebody at the CA validates, the file comes back, and only then is anything installed.
 * A list of what is mid-flight is how that week stops being invisible.
 */

interface Row {
  id: string
  commonName: string
  state: string
  environment: string | null
  requestedBy: string | null
  createdAt: string
  updatedAt: string
  issuedVersionId: string | null
  errorMessage: string | null
}

/** The engine's states, said as who is holding the ball. */
function waitingOn(state: string): { text: string; tone: 'critical' | 'warning' | 'calm' | 'plain' } {
  switch (state) {
    case 'Draft': case 'Validated': case 'CsrGenerated':
      return { text: 'You: send the CSR', tone: 'warning' }
    case 'PendingApproval':
      return { text: 'An approver', tone: 'warning' }
    case 'SubmittedToCa': case 'PendingIssuance': case 'WaitingForCertificate':
      return { text: 'The CA', tone: 'plain' }
    case 'Issued': case 'ReadyForDeployment':
      return { text: 'You: install it', tone: 'warning' }
    case 'Active':
      return { text: 'Done', tone: 'calm' }
    case 'Rejected': case 'FailedBlocked':
      return { text: 'Stopped', tone: 'critical' }
    case 'FailedRetryable':
      return { text: 'Failed, can retry', tone: 'critical' }
    default:
      return { text: state, tone: 'plain' }
  }
}

export default function Renewals() {
  const { data, error, loading } = useApi<Row[]>('/api/v1/certificates/requests?take=200')
  const navigate = useNavigate()
  const [requesting, setRequesting] = useState(false)

  const rows = data ?? []
  const open = rows.filter((r) => !['Active', 'Rejected', 'FailedBlocked'].includes(r.state))
  const closed = rows.filter((r) => ['Active', 'Rejected', 'FailedBlocked'].includes(r.state))

  return (
    <Page
      title="Renewals"
      lead="Certificates being bought or re-issued right now, and who is holding them up."
      actions={<button className="primary" onClick={() => setRequesting(true)}>Request a certificate</button>}
    >
      {error && <Problem error={error} />}
      {loading && !data && <Loading what="renewals" />}

      {data && rows.length === 0 && (
        <Empty title="No renewals in flight.">
          Start one from a certificate: <strong>Certificates</strong> → pick it → <strong>Renew</strong>.
          RemoteSSL makes the CSR; you take it to your CA.
        </Empty>
      )}

      {open.length > 0 && (
        <Card title={`In flight (${open.length})`}>
          <table className="grid">
            <thead><tr><th>Certificate</th><th>Waiting on</th><th>Started</th><th>Last change</th></tr></thead>
            <tbody>
              {open.map((r) => {
                const w = waitingOn(r.state)
                return (
                  <tr key={r.id} className="clickable" onClick={() => navigate(`/renewals/${r.id}`)}>
                    <td>
                      <strong>{r.commonName}</strong>
                      {r.environment && <span className="tag">{r.environment}</span>}
                      {r.errorMessage && <div className="bad small">{r.errorMessage}</div>}
                    </td>
                    <td><Pill tone={w.tone}>{w.text}</Pill></td>
                    <td className="small muted">{shortDateTime(r.createdAt)}</td>
                    <td className="small muted">{shortDateTime(r.updatedAt)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </Card>
      )}

      {closed.length > 0 && (
        <Card title="Finished">
          <table className="grid">
            <thead><tr><th>Certificate</th><th>Outcome</th><th>Finished</th></tr></thead>
            <tbody>
              {closed.slice(0, 20).map((r) => {
                const w = waitingOn(r.state)
                return (
                  <tr key={r.id} className="clickable" onClick={() => navigate(`/renewals/${r.id}`)}>
                    <td>{r.commonName}</td>
                    <td><Pill tone={w.tone}>{w.text}</Pill></td>
                    <td className="small muted">{shortDateTime(r.updatedAt)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </Card>
      )}
      {requesting && (
        <StartRenewal
          certificateId={null}
          commonName=""
          sans={[]}
          keySize={2048}
          keyAlgorithm="RSA"
          environment={null}
          onClose={() => setRequesting(false)}
          onStarted={(id) => navigate(`/renewals/${id}`)}
        />
      )}
    </Page>
  )
}

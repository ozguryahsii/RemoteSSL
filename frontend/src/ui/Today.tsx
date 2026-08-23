import { useNavigate } from 'react-router-dom'
import { Page, Card, Loading, Problem, Empty, useApi, Expiry } from './kit'

/**
 * The screen the product opens on: what has to be done, most urgent first.
 *
 * Everything here is a step of the same cycle — a certificate nears its end, a CSR goes to the
 * CA, the issued file comes back, it gets installed everywhere it is used, and an installation
 * sometimes fails. Showing that as one ordered list is the whole point: the old dashboard showed
 * counts, and a count tells you there is a problem without telling you what to do about it.
 */

interface WorkItem {
  kind: string
  severity: 'critical' | 'warning' | 'info'
  title: string
  detail: string
  action: string
  route: string
  daysLeft: number | null
  certificateId: string | null
  requestId: string | null
  jobId: string | null
}

/** The cycle, in order, with the plain-language heading each step gets. */
const GROUPS: { kind: string; heading: string; blurb: string }[] = [
  { kind: 'deployment-failed', heading: 'Installations that failed', blurb: 'The certificate did not reach the server, or was rolled back.' },
  { kind: 'runner-offline', heading: 'Runners that are down', blurb: 'Nothing can be installed or discovered while a runner is offline.' },
  { kind: 'expiring', heading: 'Certificates running out', blurb: 'Start the renewal: RemoteSSL makes the CSR, you send it to your CA.' },
  { kind: 'approval', heading: 'Waiting for an approver', blurb: 'Somebody has to say yes before this continues.' },
  { kind: 'csr-ready', heading: 'CSRs ready to send', blurb: 'Copy the CSR into your CA’s portal or ticket.' },
  { kind: 'awaiting-certificate', heading: 'Waiting on the CA', blurb: 'When the signed certificate arrives, upload it here.' },
  { kind: 'not-installed', heading: 'Bought, not yet in place', blurb: 'The certificate exists but somewhere still serves the old one.' },
]

export default function Today() {
  const { data, error, loading, reload } = useApi<WorkItem[]>('/api/v1/worklist')
  const navigate = useNavigate()

  const items = data ?? []
  const critical = items.filter((i) => i.severity === 'critical').length

  return (
    <Page
      title="Today"
      lead={loading ? 'Working out what needs doing…'
        : items.length === 0 ? 'Nothing needs your attention.'
          : `${items.length} thing(s) to deal with${critical > 0 ? `, ${critical} urgent` : ''}.`}
      actions={<button onClick={reload} disabled={loading}>Refresh</button>}
    >
      {error && <Problem error={error} />}
      {loading && !data && <Loading what="your work list" />}

      {data && items.length === 0 && (
        <Empty title="All quiet.">
          Nothing is expiring within 90 days, no certificate is waiting to be installed, and every
          runner is online. New certificates appear here as they approach their end date.
        </Empty>
      )}

      {GROUPS.map((group) => {
        const rows = items.filter((i) => i.kind === group.kind)
        if (rows.length === 0) return null
        return (
          <Card key={group.kind} title={`${group.heading} (${rows.length})`}>
            <p className="muted small">{group.blurb}</p>
            <ul className="work-list">
              {rows.map((item, i) => (
                <li key={i} className={item.severity}>
                  <div className="work-what">
                    <strong>{item.title}</strong>
                    <div className="muted small">{item.detail}</div>
                  </div>
                  {item.daysLeft !== null && <Expiry days={item.daysLeft} />}
                  <button onClick={() => navigate(item.route)}>{item.action}</button>
                </li>
              ))}
            </ul>
          </Card>
        )
      })}
    </Page>
  )
}

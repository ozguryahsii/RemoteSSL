import { Link } from 'react-router-dom'
import { useData } from './SimplePages'

interface Metrics {
  certificatesTotal: number
  certificatesExpiring: number
  certificatesCritical: number
  monitorsTotal: number
  probeSuccessRate: number | null
  deploymentSuccessRate: number | null
  deploymentDurationSeconds: number | null
  rollbackCount: number
  runnersOnline: number
  runnersTotal: number
  queueDepth: number
  renewalFailureCount: number
  driftDetectedCount: number
  pendingApprovals: number
  probeLatencyP50Ms: number | null
  probeLatencyP95Ms: number | null
  probeLatencySamples: number
  caRequestLatencyP50Ms: number | null
  caRequestLatencyP95Ms: number | null
  caRequestLatencySamples: number
  auditPipelineFailures: number
}

interface ExpiryBucket {
  bucket: string
  minDays: number | null
  maxDays: number | null
  count: number
  severity: string
}

interface TrendPoint {
  day: string
  count: number
  p50Ms: number | null
  p95Ms: number | null
}

interface DashboardData {
  metrics: Metrics
  alerts: { type: string; severity: string; message: string }[]
  criticalCertificates: {
    id: string; commonName: string; environment: string | null; issuer: string | null
    notAfter: string | null; daysLeft: number | null; health: string
    autoRenew: boolean; monitorCount: number; deploymentCount: number
  }[]
  failedJobs: {
    id: string; status: string; certificate: string; requestedBy: string
    targetCount: number; failedTargets: number; completedAt: string | null
  }[]
  runners: { id: string; name: string; segment: string | null; status: string; version: string | null; lastHeartbeatAt: string | null }[]
  renewalQueue: {
    id: string; commonName: string; state: string; requestedBy: string
    createdAt: string; errorMessage: string | null; hasCa: boolean
  }[]
  pendingApprovals: { id: string; deploymentJobId: string; requestedBy: string; createdAt: string }[]
  recentDrift: { action: string; detailsJson: string; timestamp: string }[]
  expiryBuckets: ExpiryBucket[]
  expiryUnknown: number
  probeLatencyTrend: TrendPoint[]
  caRequestLatencyTrend: TrendPoint[]
}

function healthClass(h: string): string {
  switch (h) {
    case 'Healthy': return 'ok'
    case 'ExpiringSoon': return 'warn'
    case 'Unknown': return 'muted'
    default: return 'bad'
  }
}

function Metric({ label, value, suffix = '', tone = '' }: { label: string; value: number | string | null; suffix?: string; tone?: string }) {
  return (
    <div className="stat-card">
      <div className={`stat-value ${tone}`}>{value === null ? '—' : value}{value === null ? '' : suffix}</div>
      <div className="muted small">{label}</div>
    </div>
  )
}

/** Expiry breakdown (Faz 1 expiry dashboard): where the renewal wave sits. */
function ExpiryBreakdown({ buckets, unknown }: { buckets: ExpiryBucket[]; unknown: number }) {
  const max = Math.max(1, ...buckets.map((b) => b.count))
  return (
    <section className="dash-section">
      <h2>Expiry breakdown <Link className="small" to="/certificates">certificates →</Link></h2>
      <div className="bucket-list">
        {buckets.map((b) => (
          <div key={b.bucket} className="bucket-row">
            <span className="bucket-label">{b.bucket}</span>
            <span className="bucket-bar-track">
              <span className={`bucket-bar ${b.severity}`} style={{ width: `${(b.count / max) * 100}%` }} />
            </span>
            <span className={`bucket-count ${b.count > 0 ? b.severity : 'muted'}`}>{b.count}</span>
          </div>
        ))}
        {unknown > 0 && (
          <div className="bucket-row">
            <span className="bucket-label muted">No live version</span>
            <span className="bucket-bar-track" />
            <span className="bucket-count muted">{unknown}</span>
          </div>
        )}
      </div>
    </section>
  )
}

/** 7-day p50/p95 sparkline for a latency metric (§32.1). */
function LatencyTrend({ title, points, unit = 'ms' }: { title: string; points: TrendPoint[]; unit?: string }) {
  if (points.length === 0) return (
    <div className="trend-card">
      <div className="muted small">{title}</div>
      <div className="muted small">No samples yet.</div>
    </div>
  )
  const max = Math.max(1, ...points.map((p) => p.p95Ms ?? 0))
  return (
    <div className="trend-card">
      <div className="muted small">{title} — p95 over {points.length} day(s)</div>
      <div className="spark">
        {points.map((p) => (
          <span key={p.day} className="spark-col" title={`${p.day}: p50 ${p.p50Ms ?? '—'}${unit}, p95 ${p.p95Ms ?? '—'}${unit} (${p.count} samples)`}>
            <span className="spark-bar" style={{ height: `${((p.p95Ms ?? 0) / max) * 100}%` }} />
          </span>
        ))}
      </div>
      <div className="muted small">peak p95 {Math.round(max)}{unit}</div>
    </div>
  )
}

export default function Dashboard() {
  const [d, , error] = useData<DashboardData>('/api/v1/dashboard', 20000)
  if (!d) return (
    <div className="page">
      <h1>Overview</h1>
      {error
        ? <>
            <p className="bad">Dashboard could not be loaded: {error}</p>
            <p className="muted small">
              The API is reachable but this endpoint failed. Check the API console output, and make sure
              the API was restarted after the last pull so its database migrations are applied.
            </p>
          </>
        : <p className="muted">Loading…</p>}
    </div>
  )
  const m = d.metrics

  return (
    <div className="page">
      <h1>Overview</h1>

      {/* Active alerts (design doc §32.3) */}
      {(d.alerts ?? []).length > 0 && (
        <div className="alert-list">
          {(d.alerts ?? []).map((a, i) => (
            <div key={i} className={`alert-row ${a.severity}`}>
              <strong>{a.type}</strong> — {a.message}
            </div>
          ))}
        </div>
      )}
      {(d.alerts ?? []).length === 0 && <p className="ok small">No active alerts.</p>}

      {/*
        The estate in four numbers. Everything else that used to sit here — probe latency,
        queue depth, audit write failures — is operational telemetry: real, but not the
        question you open this screen to answer. It moved to "System health" at the bottom.
      */}
      <div className="stat-row">
        <Metric label="Certificates" value={m.certificatesTotal} />
        <Metric label="Expiring ≤30 days" value={m.certificatesExpiring} tone={m.certificatesExpiring > 0 ? 'warn' : ''} />
        <Metric label="Critical / expired" value={m.certificatesCritical} tone={m.certificatesCritical > 0 ? 'bad' : ''} />
        <Metric label="Waiting for approval" value={m.pendingApprovals} tone={m.pendingApprovals > 0 ? 'warn' : ''} />
      </div>

      <ExpiryBreakdown buckets={d.expiryBuckets ?? []} unknown={d.expiryUnknown ?? 0} />

      {/* Critical / expiring certificates (§43) */}
      <section className="dash-section">
        <h2>Needs attention <Link className="small" to="/certificates">all certificates →</Link></h2>
        <table className="data-table">
          <thead>
            <tr><th>Certificate</th><th>Status</th><th>Expires</th><th>Issuer</th><th>Env</th><th>Monitors</th><th>Deployments</th><th>Auto renew</th></tr>
          </thead>
          <tbody>
            {(d.criticalCertificates ?? []).map((c) => (
              <tr key={c.id}>
                <td>{c.commonName}</td>
                <td><span className={healthClass(c.health)}>{c.health}</span></td>
                <td>
                  <span className={healthClass(c.health)}>{c.daysLeft} days</span>
                  {c.notAfter && <div className="muted small">{new Date(c.notAfter).toLocaleDateString()}</div>}
                </td>
                <td className="small muted">{c.issuer ?? '—'}</td>
                <td className="small">{c.environment ?? '—'}</td>
                <td>{c.monitorCount}</td>
                <td>{c.deploymentCount}</td>
                <td>{c.autoRenew ? <span className="ok">yes</span> : <span className="muted">no</span>}</td>
              </tr>
            ))}
            {(d.criticalCertificates ?? []).length === 0 && (
              <tr><td colSpan={8} className="ok">Nothing expiring in the next 30 days.</td></tr>
            )}
          </tbody>
        </table>
      </section>

      <div className="dash-grid">
        {/* Failed jobs (§43) */}
        <section className="dash-section">
          <h2>Failed deployment jobs <Link className="small" to="/activity">all jobs →</Link></h2>
          <table className="data-table">
            <thead><tr><th>Certificate</th><th>Status</th><th>Targets</th><th>By</th><th>Finished</th></tr></thead>
            <tbody>
              {(d.failedJobs ?? []).map((j) => (
                <tr key={j.id}>
                  <td>{j.certificate}</td>
                  <td><span className="bad">{j.status}</span></td>
                  <td>{j.failedTargets}/{j.targetCount} failed</td>
                  <td className="small">{j.requestedBy}</td>
                  <td className="small muted">{j.completedAt ? new Date(j.completedAt).toLocaleString() : '—'}</td>
                </tr>
              ))}
              {(d.failedJobs ?? []).length === 0 && <tr><td colSpan={5} className="ok">No failed jobs.</td></tr>}
            </tbody>
          </table>
        </section>

        {/* Runner health (§43) */}
        <section className="dash-section">
          <h2>Runner health <Link className="small" to="/setup">runners →</Link></h2>
          <table className="data-table">
            <thead><tr><th>Runner</th><th>Segment</th><th>Status</th><th>Last heartbeat</th></tr></thead>
            <tbody>
              {(d.runners ?? []).map((r) => (
                <tr key={r.id}>
                  <td>{r.name}<div className="muted small">{r.version ?? ''}</div></td>
                  <td className="small">{r.segment ?? '—'}</td>
                  <td><span className={r.status === 'Online' ? 'ok' : 'bad'}>{r.status}</span></td>
                  <td className="small muted">{r.lastHeartbeatAt ? new Date(r.lastHeartbeatAt).toLocaleString() : 'never'}</td>
                </tr>
              ))}
              {(d.runners ?? []).length === 0 && <tr><td colSpan={4} className="warn">No runners registered.</td></tr>}
            </tbody>
          </table>
        </section>
      </div>

      <div className="dash-grid">
        {/* Renewal queue (§43) */}
        <section className="dash-section">
          <h2>Renewal queue <Link className="small" to="/certificates/requests">requests →</Link></h2>
          <table className="data-table">
            <thead><tr><th>Certificate</th><th>State</th><th>Requested by</th><th>Age</th></tr></thead>
            <tbody>
              {(d.renewalQueue ?? []).map((r) => (
                <tr key={r.id}>
                  <td>{r.commonName}{!r.hasCa && <span className="muted small"> (no CA)</span>}</td>
                  <td>
                    <span className={r.state.startsWith('Failed') ? 'bad' : r.state === 'Issued' || r.state === 'ReadyForDeployment' ? 'ok' : 'warn'}>{r.state}</span>
                    {r.errorMessage && <div className="bad small">{r.errorMessage}</div>}
                  </td>
                  <td className="small">{r.requestedBy}</td>
                  <td className="small muted">
                    {Math.max(0, Math.round((Date.now() - new Date(r.createdAt).getTime()) / 86400000))}d
                  </td>
                </tr>
              ))}
              {(d.renewalQueue ?? []).length === 0 && <tr><td colSpan={4} className="muted">Renewal queue is empty.</td></tr>}
            </tbody>
          </table>
        </section>

        {/* Pending approvals + recent drift */}
        <section className="dash-section">
          <h2>Pending approvals <Link className="small" to="/activity/approvals">approvals →</Link></h2>
          <table className="data-table">
            <thead><tr><th>Job</th><th>Requested by</th><th>Waiting</th></tr></thead>
            <tbody>
              {(d.pendingApprovals ?? []).map((a) => (
                <tr key={a.id}>
                  <td className="small">{a.deploymentJobId.slice(0, 8)}…</td>
                  <td className="small">{a.requestedBy}</td>
                  <td className="small muted">
                    {Math.max(0, Math.round((Date.now() - new Date(a.createdAt).getTime()) / 3600000))}h
                  </td>
                </tr>
              ))}
              {(d.pendingApprovals ?? []).length === 0 && <tr><td colSpan={3} className="muted">Nothing awaiting approval.</td></tr>}
            </tbody>
          </table>

          {(d.recentDrift ?? []).length > 0 && (
            <>
              <h3>Recent drift / vantage mismatch</h3>
              <ul className="small">
                {(d.recentDrift ?? []).map((e, i) => (
                  <li key={i}>
                    <span className="warn">{e.action}</span>{' '}
                    <span className="muted">{new Date(e.timestamp).toLocaleString()}</span>
                    <div className="muted" style={{ wordBreak: 'break-all' }}>{e.detailsJson}</div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>

      {/*
        Operational telemetry (§32.1/§32.2). Kept, because it is what tells you the platform
        itself is healthy — but at the bottom, and folded away, because it answers a different
        question from the one this screen exists for.
      */}
      <details className="dash-details">
        <summary>System health</summary>
        <div className="stat-row">
          <Metric label="Probe success rate" value={m.probeSuccessRate} suffix="%" tone={(m.probeSuccessRate ?? 100) < 100 ? 'warn' : 'ok'} />
          <Metric label="Deployment success rate" value={m.deploymentSuccessRate} suffix="%" tone={(m.deploymentSuccessRate ?? 100) < 100 ? 'warn' : 'ok'} />
          <Metric label="Avg deploy duration" value={m.deploymentDurationSeconds} suffix="s" />
          <Metric label="Rollbacks" value={m.rollbackCount} tone={m.rollbackCount > 0 ? 'warn' : ''} />
          <Metric label="Runners online" value={`${m.runnersOnline}/${m.runnersTotal}`} tone={m.runnersOnline < m.runnersTotal ? 'bad' : 'ok'} />
          <Metric label="Job queue depth" value={m.queueDepth} />
          <Metric label="Renewal failures" value={m.renewalFailureCount} tone={m.renewalFailureCount > 0 ? 'bad' : ''} />
          <Metric label="Drift (7d)" value={m.driftDetectedCount} tone={m.driftDetectedCount > 0 ? 'warn' : ''} />
          <Metric label="Probe latency p50 / p95" value={m.probeLatencySamples === 0 ? null
            : `${m.probeLatencyP50Ms ?? '—'} / ${m.probeLatencyP95Ms ?? '—'}`} suffix=" ms" />
          <Metric label="CA request latency p50 / p95" value={m.caRequestLatencySamples === 0 ? null
            : `${m.caRequestLatencyP50Ms ?? '—'} / ${m.caRequestLatencyP95Ms ?? '—'}`} suffix=" ms" />
          <Metric label="Audit write failures (24h)" value={m.auditPipelineFailures}
            tone={m.auditPipelineFailures > 0 ? 'bad' : 'ok'} />
        </div>

        <div className="trend-row">
          <LatencyTrend title="Probe latency" points={d.probeLatencyTrend ?? []} />
          <LatencyTrend title="CA request latency" points={d.caRequestLatencyTrend ?? []} />
        </div>
      </details>
    </div>
  )
}

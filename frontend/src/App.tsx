import { useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { API_BASE, getToken, setToken } from './api/client'
import { Login } from './pages/AdminPages'
import Today from './ui/Today'
import Certificates from './ui/Certificates'
import CertificateDetail from './ui/CertificateDetail'
import Renewals from './ui/Renewals'
import Renewal from './ui/Renewal'
import Servers from './ui/Servers'
import { Activity, ActivityDetail } from './ui/Activity'
import SettingsSection from './ui/Settings'
import './App.css'

/**
 * Five places, named after the job rather than the data model.
 *
 * The product manages one cycle: a certificate approaches its end, a CSR goes to the CA, the
 * signed file comes back, it is installed everywhere the old one is serving, and somebody has to
 * see when that fails. Each entry below is a step of that cycle, in order. Anything set up once —
 * runners, credentials, policies, people — is behind Settings, because it is not the daily work.
 *
 * The previous navigation had one entry per entity in the database. That is a faithful map of the
 * system and a useless map of the work: it asked the reader to already know that renewing means
 * visiting Certificates, then Requests, then Targets, then Deployments, in that order.
 */
const NAV = [
  { to: '/', label: 'Today', hint: 'What needs doing', end: true },
  { to: '/certificates', label: 'Certificates', hint: 'What you have and when it runs out' },
  { to: '/renewals', label: 'Renewals', hint: 'Being bought right now' },
  { to: '/servers', label: 'Servers', hint: 'Where certificates are serving' },
  { to: '/activity', label: 'Activity', hint: 'What has been installed' },
  { to: '/settings', label: 'Settings', hint: 'Set up once' },
]

/** Old links keep working: everything moved, and a dead bookmark is a support call. */
const MOVED: Record<string, string> = {
  '/endpoints': '/settings/monitors',
  '/monitors': '/settings/monitors',
  '/targets': '/servers',
  '/deployments': '/activity',
  '/setup': '/settings',
  '/setup/runners': '/settings/runners',
  '/setup/credentials': '/settings/credentials',
  '/setup/policies': '/settings/policies',
  '/setup/ca': '/settings/ca',
  '/setup/keys': '/settings/keys',
  '/setup/users': '/settings/users',
  '/certificates/requests': '/renewals',
  '/activity/approvals': '/settings/approvals',
  '/activity/audit': '/settings/audit',
}

/**
 * Whether the control plane is answering, and whether it is happy.
 *
 * The health endpoint answers 503 when a dependency it was told about is down, so a failed
 * request is not the same as an unreachable server — and saying "cannot reach the server" when
 * the server is right there, merely reporting a missing queue, sends people to the wrong problem.
 */
function Health() {
  const [state, setState] = useState<'checking' | 'ok' | 'degraded' | 'down'>('checking')

  useEffect(() => {
    let alive = true
    const check = async () => {
      try {
        const res = await fetch(`${API_BASE}/health`)
        const body = (await res.text()).trim()
        if (alive) setState(body === 'Healthy' ? 'ok' : 'degraded')
      } catch {
        if (alive) setState('down')
      }
    }
    check()
    const timer = setInterval(check, 30000)
    return () => { alive = false; clearInterval(timer) }
  }, [])

  const words = {
    checking: 'Checking…',
    ok: 'Connected',
    degraded: 'Connected, something is unhealthy',
    down: 'Cannot reach the server',
  }
  return <div className={`health ${state === 'degraded' ? 'checking' : state}`}>{words[state]}</div>
}

function Shell() {
  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">RemoteSSL</div>
        <ul>
          {NAV.map((n) => (
            <li key={n.to}>
              <NavLink to={n.to} end={n.end} className={({ isActive }) => isActive ? 'active' : ''}>
                <span className="nav-label">{n.label}</span>
                <span className="nav-hint">{n.hint}</span>
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="sidebar-foot">
          <Health />
          {getToken() && (
            <button className="ghost small" onClick={() => { setToken(null); window.location.href = '/login' }}>
              Sign out
            </button>
          )}
        </div>
      </nav>

      <main className="content">
        <Routes>
          <Route path="/" element={<Today />} />
          <Route path="/certificates" element={<Certificates />} />
          <Route path="/certificates/:id" element={<CertificateDetail />} />
          <Route path="/renewals" element={<Renewals />} />
          <Route path="/renewals/:id" element={<Renewal />} />
          <Route path="/servers" element={<Servers />} />
          <Route path="/activity" element={<Activity />} />
          <Route path="/activity/:id" element={<ActivityDetail />} />
          <Route path="/settings/*" element={<SettingsSection />} />
          {Object.entries(MOVED).map(([from, to]) => (
            <Route key={from} path={from} element={<Navigate to={to} replace />} />
          ))}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Shell />} />
      </Routes>
    </BrowserRouter>
  )
}

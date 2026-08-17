import { useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { apiGetText } from './api/client'
import Monitors from './pages/Monitors'
import Certificates from './pages/Certificates'
import Targets from './pages/Targets'
import Deployments from './pages/Deployments'
import Requests from './pages/Requests'
import { Runners, Credentials, Approvals, Audit } from './pages/SimplePages'
import Dashboard from './pages/Dashboard'
import Keys from './pages/Keys'
import { Login, Policies, CaIntegrations, Settings } from './pages/AdminPages'
import './App.css'

/**
 * The menu is grouped by what someone is trying to do, not by the order the entities were
 * built. Everyday certificate work comes first; governance stays visible as its own group
 * because approving and auditing are jobs in their own right, not settings; and the pieces you
 * configure once — runners, credentials, CAs — sit at the bottom where you go looking for them
 * rather than trip over them daily.
 */
const NAV_GROUPS = [
  {
    key: 'daily',
    items: [
      { path: '/', key: 'dashboard' },
      { path: '/certificates', key: 'certificates' },
      { path: '/monitors', key: 'monitors' },
      { path: '/targets', key: 'targets' },
      { path: '/requests', key: 'requests' },
      { path: '/deployments', key: 'deployments' },
    ],
  },
  {
    key: 'governance',
    items: [
      { path: '/approvals', key: 'approvals' },
      { path: '/audit', key: 'audit' },
    ],
  },
  {
    key: 'setup',
    items: [
      { path: '/runners', key: 'runners' },
      { path: '/credentials', key: 'credentials' },
      { path: '/keys', key: 'keys' },
      { path: '/ca-integrations', key: 'caIntegrations' },
      { path: '/policies', key: 'policies' },
      { path: '/settings', key: 'settings' },
    ],
  },
] as const

const NAV_ITEMS: readonly { path: string; key: string }[] =
  NAV_GROUPS.flatMap((g) => g.items as readonly { path: string; key: string }[])

function Placeholder({ titleKey }: { titleKey: string }) {
  const { t } = useTranslation()
  return (
    <div className="page">
      <h1>{t(`nav.${titleKey}`)}</h1>
      <p className="muted">{t('common.comingSoon')}</p>
    </div>
  )
}

function ApiStatusBadge() {
  const { t } = useTranslation()
  const [healthy, setHealthy] = useState<boolean | null>(null)

  useEffect(() => {
    let cancelled = false
    const check = () =>
      apiGetText('/health')
        .then((body) => !cancelled && setHealthy(body.trim() === 'Healthy'))
        .catch(() => !cancelled && setHealthy(false))
    check()
    const id = setInterval(check, 30_000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  if (healthy === null) return null
  return (
    <span className={`status-badge ${healthy ? 'ok' : 'bad'}`}>
      {t('common.apiStatus')}: {healthy ? t('common.healthy') : t('common.unreachable')}
    </span>
  )
}

export default function App() {
  const { t } = useTranslation()
  return (
    <BrowserRouter>
      <div className="layout">
        <aside className="sidebar">
          <div className="brand">{t('app.title')}</div>
          <nav>
            {NAV_GROUPS.map((group) => (
              <div key={group.key} className="nav-group">
                <div className="nav-group-label">{t(`nav.group.${group.key}`)}</div>
                {group.items.map((item) => (
                  <NavLink key={item.path} to={item.path} end={item.path === '/'}>
                    {t(`nav.${item.key}`)}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-footer">
            <ApiStatusBadge />
          </div>
        </aside>
        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/monitors" element={<Monitors />} />
            <Route path="/certificates" element={<Certificates />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/deployments" element={<Deployments />} />
            <Route path="/requests" element={<Requests />} />
            <Route path="/runners" element={<Runners />} />
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/keys" element={<Keys />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/login" element={<Login />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/ca-integrations" element={<CaIntegrations />} />
            <Route path="/settings" element={<Settings />} />
            {NAV_ITEMS.filter((i) => !['/', '/monitors', '/certificates', '/targets', '/deployments', '/requests', '/runners', '/credentials', '/approvals', '/audit', '/policies', '/ca-integrations', '/settings'].includes(i.path)).map((item) => (
              <Route key={item.path} path={item.path} element={<Placeholder titleKey={item.key} />} />
            ))}
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

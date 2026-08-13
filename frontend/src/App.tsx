import { useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { apiGetText } from './api/client'
import Monitors from './pages/Monitors'
import Certificates from './pages/Certificates'
import Targets from './pages/Targets'
import Deployments from './pages/Deployments'
import Requests from './pages/Requests'
import { Dashboard, Runners, Credentials, Approvals, Audit } from './pages/SimplePages'
import './App.css'

const NAV_ITEMS = [
  { path: '/', key: 'dashboard' },
  { path: '/certificates', key: 'certificates' },
  { path: '/monitors', key: 'monitors' },
  { path: '/targets', key: 'targets' },
  { path: '/requests', key: 'requests' },
  { path: '/deployments', key: 'deployments' },
  { path: '/approvals', key: 'approvals' },
  { path: '/runners', key: 'runners' },
  { path: '/credentials', key: 'credentials' },
  { path: '/ca-integrations', key: 'caIntegrations' },
  { path: '/policies', key: 'policies' },
  { path: '/audit', key: 'audit' },
  { path: '/settings', key: 'settings' },
] as const

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
            {NAV_ITEMS.map((item) => (
              <NavLink key={item.path} to={item.path} end={item.path === '/'}>
                {t(`nav.${item.key}`)}
              </NavLink>
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
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/audit" element={<Audit />} />
            {NAV_ITEMS.filter((i) => !['/', '/monitors', '/certificates', '/targets', '/deployments', '/requests', '/runners', '/credentials', '/approvals', '/audit'].includes(i.path)).map((item) => (
              <Route key={item.path} path={item.path} element={<Placeholder titleKey={item.key} />} />
            ))}
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

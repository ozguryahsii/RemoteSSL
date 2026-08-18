import { useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
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
 * Six places, named after the things an operator actually has: certificates, the servers they go
 * on, the endpoints being watched, what happened, and the setup behind it.
 *
 * There used to be fourteen entries, one per entity in the data model. That is a faithful map of
 * the system and a poor map of the work — it asked the reader to already know that installing a
 * certificate means visiting Targets, then Deployments, or that a CSR lives under a separate
 * screen from the certificate it will become. Everything is still here; the screens that belong
 * to one subject now sit behind that subject as tabs, so the top level stays small enough to hold
 * in your head.
 */
interface Tab { path: string; key: string; element: React.ReactNode }
interface Section { path: string; key: string; tabs?: Tab[]; element?: React.ReactNode }

const SECTIONS: Section[] = [
  { path: '/', key: 'home', element: <Dashboard /> },

  // A request is a certificate that does not exist yet, so it belongs with the certificates.
  {
    path: '/certificates',
    key: 'certificates',
    tabs: [
      { path: '', key: 'all', element: <Certificates /> },
      { path: 'requests', key: 'requests', element: <Requests /> },
    ],
  },

  { path: '/servers', key: 'servers', element: <Targets /> },
  { path: '/endpoints', key: 'endpoints', element: <Monitors /> },

  // What happened, and what is waiting on a person. Installations, approvals and the audit trail
  // answer the same question at different depths, so they are one section rather than three.
  {
    path: '/activity',
    key: 'activity',
    tabs: [
      { path: '', key: 'installations', element: <Deployments /> },
      { path: 'approvals', key: 'approvals', element: <Approvals /> },
      { path: 'audit', key: 'audit', element: <Audit /> },
    ],
  },

  // Everything you set up once and then stop thinking about.
  {
    path: '/setup',
    key: 'setup',
    tabs: [
      { path: '', key: 'runners', element: <Runners /> },
      { path: 'credentials', key: 'credentials', element: <Credentials /> },
      { path: 'keys', key: 'keys', element: <Keys /> },
      { path: 'authorities', key: 'authorities', element: <CaIntegrations /> },
      { path: 'policies', key: 'policies', element: <Policies /> },
      { path: 'general', key: 'general', element: <Settings /> },
    ],
  },
]

/**
 * Where the old screens used to live. Bookmarks and links in older messages keep working instead
 * of landing on a blank page.
 */
const MOVED: Record<string, string> = {
  '/monitors': '/endpoints',
  '/targets': '/servers',
  '/deployments': '/activity',
  '/requests': '/certificates/requests',
  '/approvals': '/activity/approvals',
  '/audit': '/activity/audit',
  '/runners': '/setup',
  '/credentials': '/setup/credentials',
  '/keys': '/setup/keys',
  '/ca-integrations': '/setup/authorities',
  '/policies': '/setup/policies',
  '/settings': '/setup/general',
}

/** Tab strip for a section that has more than one screen under it. */
function SectionTabs({ section }: { section: Section }) {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  if (!section.tabs) return null

  return (
    <div className="section-tabs">
      {section.tabs.map((tab) => {
        const to = tab.path ? `${section.path}/${tab.path}` : section.path
        // The default tab is also active on the bare section path.
        const active = pathname === to || (tab.path === '' && pathname === `${section.path}/`)
        return (
          <NavLink key={to} to={to} className={active ? 'active' : ''}>
            {t(`nav.tab.${section.key}.${tab.key}`)}
          </NavLink>
        )
      })}
    </div>
  )
}

function SectionShell({ section, children }: { section: Section; children: React.ReactNode }) {
  const { t } = useTranslation()
  return (
    <>
      {/* The section names the subject once; the tabs name the view of it. The screens inside
          no longer carry their own heading, so nothing is said twice. */}
      <h1 className="section-title">{t(`nav.${section.key}`)}</h1>
      <SectionTabs section={section} />
      {children}
    </>
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
            {SECTIONS.map((s) => (
              <NavLink key={s.path} to={s.path} end={s.path === '/'}
                className={({ isActive }) => (isActive ? 'active' : '')}>
                {t(`nav.${s.key}`)}
              </NavLink>
            ))}
          </nav>
          <div className="sidebar-footer">
            <ApiStatusBadge />
          </div>
        </aside>
        <main className="content">
          <Routes>
            {SECTIONS.map((s) =>
              s.tabs
                ? s.tabs.map((tab) => (
                    <Route
                      key={`${s.path}/${tab.path}`}
                      path={tab.path ? `${s.path}/${tab.path}` : s.path}
                      element={<SectionShell section={s}>{tab.element}</SectionShell>}
                    />
                  ))
                : <Route key={s.path} path={s.path} element={s.element} />,
            )}
            {Object.entries(MOVED).map(([from, to]) => (
              <Route key={from} path={from} element={<Navigate to={to} replace />} />
            ))}
            <Route path="/login" element={<Login />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

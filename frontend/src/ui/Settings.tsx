import { NavLink, Route, Routes, Navigate } from 'react-router-dom'
import { Runners, Credentials, Approvals, Audit } from '../pages/SimplePages'
import { Policies, CaIntegrations, Settings as Users } from '../pages/AdminPages'
import Monitors from '../pages/Monitors'
import Keys from '../pages/Keys'

/**
 * Everything that is set up once and then left alone: who can sign in, what RemoteSSL signs in to
 * targets with, which runners exist, the alerting, the policies, the audit trail.
 *
 * Keeping it behind one door is the point. These were scattered through the main navigation, so
 * the daily job — renew this, install that — was buried among things nobody touches twice a year.
 */

const TABS = [
  { to: 'runners', label: 'Runners', blurb: 'The workers that reach your machines.' },
  { to: 'credentials', label: 'Credentials', blurb: 'How RemoteSSL signs in to them.' },
  { to: 'monitors', label: 'Watched addresses', blurb: 'Public endpoints polled for what they serve.' },
  { to: 'users', label: 'People', blurb: 'Who can sign in, and what they may do.' },
  { to: 'approvals', label: 'Approvals', blurb: 'Requests waiting on a second pair of eyes.' },
  { to: 'policies', label: 'Policies', blurb: 'What is allowed to be issued and deployed.' },
  { to: 'ca', label: 'Certificate authorities', blurb: 'Connections to the CAs you buy from.' },
  { to: 'keys', label: 'Keys', blurb: 'Private keys held centrally.' },
  { to: 'audit', label: 'Audit trail', blurb: 'Who did what, and when.' },
]

export default function SettingsSection() {
  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="lead">Set up once; the daily work happens on the other screens.</p>
        </div>
      </header>

      <nav className="subnav">
        {TABS.map((t) => (
          <NavLink key={t.to} to={t.to} className={({ isActive }) => isActive ? 'active' : ''} title={t.blurb}>
            {t.label}
          </NavLink>
        ))}
      </nav>

      <div className="subpage">
        <Routes>
          <Route index element={<Navigate to="runners" replace />} />
          <Route path="runners" element={<Runners />} />
          <Route path="credentials" element={<Credentials />} />
          <Route path="monitors" element={<Monitors />} />
          <Route path="users" element={<Users />} />
          <Route path="approvals" element={<Approvals />} />
          <Route path="policies" element={<Policies />} />
          <Route path="ca" element={<CaIntegrations />} />
          <Route path="keys" element={<Keys />} />
          <Route path="audit" element={<Audit />} />
        </Routes>
      </div>
    </section>
  )
}

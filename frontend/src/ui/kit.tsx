import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { apiGet } from '../api/client'

/**
 * The pieces every screen is built from.
 *
 * The old interface had each page inventing its own table, its own way of saying "loading", its
 * own word for the same thing. That is most of why it was unreadable: nothing looked like
 * anything else, so nothing could be learned once. These are deliberately few.
 */

/** Loads a URL, and gives the caller the three states it really has. */
export function useApi<T>(path: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(path !== null)

  const reload = useCallback(() => {
    if (path === null) return
    setLoading(true)
    apiGet<T>(path)
      .then((d) => { setData(d); setError(null) })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [path])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(reload, [path, ...deps])

  return { data, error, loading, reload }
}

export function Loading({ what }: { what: string }) {
  return <p className="muted">Loading {what}…</p>
}

export function Problem({ error }: { error: string }) {
  return (
    <div className="notice bad">
      <strong>That did not work.</strong>
      <div className="small">{error}</div>
    </div>
  )
}

/**
 * What to show when a list is empty. An empty table teaches nothing; the reason it is empty and
 * the one thing to do about it teaches everything.
 */
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="small muted">{children}</div>}
    </div>
  )
}

/** How long is left, said the way people say it, and coloured by how much it matters. */
export function Expiry({ days }: { days: number | null | undefined }) {
  if (days === null || days === undefined) return <span className="muted">unknown</span>
  if (days < 0) return <span className="pill critical">expired {-days}d ago</span>
  if (days <= 15) return <span className="pill critical">{days} days left</span>
  if (days <= 45) return <span className="pill warning">{days} days left</span>
  return <span className="pill calm">{days} days left</span>
}

export function Pill({ tone, children }: { tone: 'critical' | 'warning' | 'calm' | 'plain'; children: ReactNode }) {
  return <span className={`pill ${tone}`}>{children}</span>
}

/** One screen: a title that says what you are looking at, and optionally what to do here. */
export function Page({ title, lead, actions, children }: {
  title: string
  lead?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>{title}</h1>
          {lead && <p className="lead">{lead}</p>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </header>
      {children}
    </section>
  )
}

export function Card({ title, aside, children }: { title?: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <div className="card">
      {(title || aside) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {aside}
        </div>
      )}
      {children}
    </div>
  )
}

export function Modal({ title, onClose, children, wide }: {
  title: string
  onClose: () => void
  children: ReactNode
  wide?: boolean
}) {
  return (
    <div className="overlay" onClick={onClose}>
      <div className={wide ? 'sheet wide' : 'sheet'} onClick={(e) => e.stopPropagation()}>
        <div className="sheet-head">
          <h2>{title}</h2>
          <button className="ghost" onClick={onClose}>Close</button>
        </div>
        <div className="sheet-body">{children}</div>
      </div>
    </div>
  )
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )
}

/** Days between now and an ISO date, floored — the same arithmetic the API does. */
export function daysUntil(iso: string | null | undefined): number | null {
  if (!iso) return null
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86400000)
}

export function shortDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

export function shortDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined,
    { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
}

/** Copies text and says so, because a copy button with no feedback is a button you press twice. */
export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setDone(true)
          setTimeout(() => setDone(false), 2000)
        } catch { /* a browser that refuses the clipboard still shows the text on screen */ }
      }}
    >
      {done ? 'Copied' : label}
    </button>
  )
}

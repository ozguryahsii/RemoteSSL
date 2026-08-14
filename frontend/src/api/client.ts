const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:5200'

export function getToken(): string | null {
  return localStorage.getItem('remotessl.token')
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem('remotessl.token', token)
  else localStorage.removeItem('remotessl.token')
}

function headers(json = false): HeadersInit {
  const h: Record<string, string> = {}
  if (json) h['Content-Type'] = 'application/json'
  const token = getToken()
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

function check(res: Response): Response {
  if (res.status === 401 && !window.location.pathname.startsWith('/login')) {
    // Auth is enabled server-side and we have no valid token.
    window.location.href = '/login'
  }
  return res
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = check(await fetch(`${API_BASE}${path}`, { headers: headers() }))
  if (!res.ok) throw new Error(`GET ${path} → ${res.status} ${await errorDetail(res)}`)
  return res.json() as Promise<T>
}

/**
 * Like apiGet, but also reports how many rows exist in total (X-Total-Count, §27.2).
 * List endpoints return a page, so without the total a screen cannot tell a short list from a
 * truncated one — and a monitor the operator cannot see is a monitor they will not renew.
 */
export async function apiGetPage<T>(path: string): Promise<{ data: T; total: number | null }> {
  const res = check(await fetch(`${API_BASE}${path}`, { headers: headers() }))
  if (!res.ok) throw new Error(`GET ${path} → ${res.status} ${await errorDetail(res)}`)
  const header = res.headers.get('X-Total-Count')
  const total = header === null ? null : Number.parseInt(header, 10)
  return { data: (await res.json()) as T, total: Number.isNaN(total as number) ? null : total }
}

/** Pulls the server's reason out of a failed response so the UI can show it. */
async function errorDetail(res: Response): Promise<string> {
  try {
    const body = await res.text()
    if (!body) return ''
    try {
      const problem = JSON.parse(body) as { title?: string; detail?: string }
      return problem.title ?? problem.detail ?? body.slice(0, 300)
    } catch {
      return body.slice(0, 300)
    }
  } catch {
    return ''
  }
}

export async function apiGetText(path: string): Promise<string> {
  const res = check(await fetch(`${API_BASE}${path}`, { headers: headers() }))
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`)
  return res.text()
}

export async function apiPost(path: string, body?: unknown): Promise<Response> {
  return check(await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: headers(true),
    body: body === undefined ? undefined : JSON.stringify(body),
  }))
}

export async function apiPatch(path: string, body?: unknown): Promise<Response> {
  return check(await fetch(`${API_BASE}${path}`, {
    method: 'PATCH',
    headers: headers(true),
    body: body === undefined ? undefined : JSON.stringify(body),
  }))
}

export async function apiPut(path: string, body?: unknown): Promise<Response> {
  return check(await fetch(`${API_BASE}${path}`, {
    method: 'PUT',
    headers: headers(true),
    body: body === undefined ? undefined : JSON.stringify(body),
  }))
}

export async function apiDelete(path: string): Promise<Response> {
  return check(await fetch(`${API_BASE}${path}`, { method: 'DELETE', headers: headers() }))
}

export { API_BASE }

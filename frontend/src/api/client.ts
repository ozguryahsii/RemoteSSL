const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:5200'

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`)
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`)
  return res.json() as Promise<T>
}

export async function apiGetText(path: string): Promise<string> {
  const res = await fetch(`${API_BASE}${path}`)
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`)
  return res.text()
}

export { API_BASE }

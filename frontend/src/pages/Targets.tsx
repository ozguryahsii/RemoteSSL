import { useState } from 'react'
import { apiGet, apiDelete } from '../api/client'
import { useData, post } from './SimplePages'

interface TargetRow {
  id: string; name: string; targetType: string; adapterType: string
  environment: string | null; credentialRefId: string | null; connectionConfigJson: string
  stores: { id: string; storeType: string; storePath: string; alias: string | null }[]
}

const ADAPTERS = ['nginx', 'apache', 'haproxy', 'generic-file', 'windows-cert-store', 'iis',
  'java-keystore', 'java-truststore', 'oracle-wallet', 'f5-bigip', 'fortigate', 'paloalto', 'citrix-adc', 'cisco-ise']

/// Default management port per adapter — auto-filled on selection, always hand-editable.
const DEFAULT_PORTS: Record<string, number> = {
  nginx: 22, apache: 22, haproxy: 22, 'generic-file': 22,
  'windows-cert-store': 22, iis: 22, // Windows OpenSSH
  'java-keystore': 22, 'java-truststore': 22, 'oracle-wallet': 22,
  'f5-bigip': 443, fortigate: 443, paloalto: 443, 'citrix-adc': 443, 'cisco-ise': 443,
}

async function patchTarget(id: string, body: unknown): Promise<Response> {
  const { API_BASE, getToken } = await import('../api/client')
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = getToken()
  if (token) h['Authorization'] = `Bearer ${token}`
  return fetch(`${API_BASE}/api/v1/targets/${id}`, { method: 'PATCH', headers: h, body: JSON.stringify(body) })
}

export default function Targets() {
  const [targets, reload] = useData<TargetRow[]>('/api/v1/targets')
  const [creds] = useData<{ id: string; name: string }[]>('/api/v1/credentials')
  const [name, setName] = useState(''); const [adapter, setAdapter] = useState('nginx')
  const [host, setHost] = useState(''); const [port, setPort] = useState('22'); const [credId, setCredId] = useState('')
  const [portTouched, setPortTouched] = useState(false)
  const [winMethod, setWinMethod] = useState('winrm') // winrm | ssh, for windows adapters
  const [testResult, setTestResult] = useState<string | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const [eName, setEName] = useState(''); const [eAdapter, setEAdapter] = useState('nginx')
  const [eHost, setEHost] = useState(''); const [ePort, setEPort] = useState('22'); const [eCred, setECred] = useState('')
  const [eMethod, setEMethod] = useState('winrm')

  const isWindows = (a: string) => a === 'windows-cert-store' || a === 'iis'
  const isVendor = (a: string) => ['f5-bigip', 'fortigate', 'paloalto', 'citrix-adc', 'cisco-ise'].includes(a)

  function pickAdapter(value: string) {
    setAdapter(value)
    // Auto-fill the default port unless the user already typed one manually.
    if (!portTouched) {
      const p = isWindows(value) ? (winMethod === 'winrm' ? 5985 : 22) : DEFAULT_PORTS[value] ?? 22
      setPort(String(p))
    }
  }

  function pickWinMethod(value: string) {
    setWinMethod(value)
    if (!portTouched && isWindows(adapter)) setPort(value === 'winrm' ? '5985' : '22')
  }

  async function add(e: React.FormEvent) {
    e.preventDefault()
    const connectionConfig = isVendor(adapter)
      ? { managementUrl: `https://${host}:${port}` }
      : isWindows(adapter)
        ? { host, port: Number(port), method: winMethod, winRmUseSsl: winMethod === 'winrm' && Number(port) === 5986 }
        : { host, port: Number(port) }
    const res = await post('/api/v1/targets', {
      name, adapterType: adapter,
      targetType: isWindows(adapter) ? 'WindowsServer' : isVendor(adapter) ? 'NetworkDevice' : 'LinuxServer',
      connectionConfig,
      credentialRefId: credId || null,
    })
    if (!res.ok) { alert('Create failed: ' + ((await res.json()).title ?? res.status)); return }
    setName(''); setHost(''); setPortTouched(false); setPort(String(DEFAULT_PORTS[adapter] ?? 22)); reload()
  }

  function startEdit(t: TargetRow) {
    setEditing(t.id); setEName(t.name); setEAdapter(t.adapterType); setECred(t.credentialRefId ?? '')
    try {
      const c = JSON.parse(t.connectionConfigJson)
      if (c.managementUrl) {
        const u = new URL(c.managementUrl)
        setEHost(u.hostname); setEPort(u.port || '443')
      } else {
        setEHost(c.host ?? ''); setEPort(String(c.port ?? 22)); setEMethod(c.method ?? 'winrm')
      }
    } catch { setEHost(''); setEPort('22') }
  }

  async function saveEdit(id: string) {
    const connectionConfig = isVendor(eAdapter)
      ? { managementUrl: `https://${eHost}:${ePort}` }
      : isWindows(eAdapter)
        ? { host: eHost, port: Number(ePort), method: eMethod, winRmUseSsl: eMethod === 'winrm' && Number(ePort) === 5986 }
        : { host: eHost, port: Number(ePort) }
    const res = await patchTarget(id, {
      name: eName, adapterType: eAdapter, connectionConfig,
      credentialRefId: eCred || null, clearCredential: !eCred,
    })
    if (!res.ok) { alert('Update failed: ' + ((await res.json()).title ?? res.status)); return }
    setEditing(null); reload()
  }

  async function remove(t: TargetRow) {
    if (!window.confirm(`Delete target '${t.name}'? Its stores will be removed too.`)) return
    const res = await apiDelete(`/api/v1/targets/${t.id}`)
    if (!res.ok) alert('Delete failed: ' + ((await res.json()).title ?? res.status))
    reload()
  }

  async function removeStore(storeId: string) {
    const res = await apiDelete(`/api/v1/targets/stores/${storeId}`)
    if (!res.ok) alert('Delete failed: ' + ((await res.json()).title ?? res.status))
    reload()
  }

  async function addStore(targetId: string) {
    const path = window.prompt('Store path (e.g. /etc/nginx/ssl, LocalMachine\\My, /opt/app/truststore.jks):')
    if (!path) return
    await post(`/api/v1/targets/${targetId}/stores`, { storeType: 'auto', storePath: path, alias: null })
    reload()
  }

  async function testConnection(targetId: string) {
    setTestResult('testing…')
    const res = await post(`/api/v1/targets/${targetId}/test-connection`)
    const { jobId } = await res.json()
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 2000))
      const job = await apiGet<{ status: string; resultJson: string | null }>(`/api/v1/targets/jobs/${jobId}`)
      if (job.status === 'Succeeded') { setTestResult(`OK: ${JSON.parse(job.resultJson ?? '{}').output ?? ''}`); return }
      if (job.status === 'Failed') { setTestResult('FAILED'); return }
    }
    setTestResult('timeout — is a runner online?')
  }

  return (
    <div className="page">
      <h1>Managed Targets</h1>
      <form className="inline-form" onSubmit={add}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="target name" required />
        <select value={adapter} onChange={(e) => pickAdapter(e.target.value)}>
          {ADAPTERS.map((a) => <option key={a}>{a}</option>)}
        </select>
        {isWindows(adapter) && (
          <select value={winMethod} onChange={(e) => pickWinMethod(e.target.value)} title="Windows management channel">
            <option value="winrm">WinRM (PowerShell Remoting)</option>
            <option value="ssh">SSH (OpenSSH)</option>
          </select>
        )}
        <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="host" required />
        <input value={port} onChange={(e) => { setPort(e.target.value); setPortTouched(true) }}
               type="number" min={1} max={65535} style={{ width: 80 }} title="port (auto-filled per adapter, editable)" />
        <select value={credId} onChange={(e) => setCredId(e.target.value)}>
          <option value="">no credential</option>
          {(creds ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <button type="submit">Add target</button>
      </form>
      {testResult && <p className="small">{testResult}</p>}
      <table className="data-table">
        <thead><tr><th>Name</th><th>Adapter</th><th>Connection</th><th>Stores</th><th></th></tr></thead>
        <tbody>
          {(targets ?? []).map((t) => editing === t.id ? (
            <tr key={t.id} className="editing-row">
              <td><input value={eName} onChange={(e) => setEName(e.target.value)} /></td>
              <td>
                <select value={eAdapter} onChange={(e) => { setEAdapter(e.target.value); setEPort(String(DEFAULT_PORTS[e.target.value] ?? 22)) }}>
                  {ADAPTERS.map((a) => <option key={a}>{a}</option>)}
                </select>
              </td>
              <td>
                <input value={eHost} onChange={(e) => setEHost(e.target.value)} placeholder="host" style={{ width: 160 }} />{' '}
                <input value={ePort} onChange={(e) => setEPort(e.target.value)} type="number" style={{ width: 80 }} />
                {isWindows(eAdapter) && (
                  <select value={eMethod} onChange={(e) => setEMethod(e.target.value)}>
                    <option value="winrm">WinRM</option><option value="ssh">SSH</option>
                  </select>
                )}
              </td>
              <td>
                <select value={eCred} onChange={(e) => setECred(e.target.value)}>
                  <option value="">no credential</option>
                  {(creds ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </td>
              <td className="actions">
                <button onClick={() => saveEdit(t.id)}>Save</button>
                <button onClick={() => setEditing(null)}>Cancel</button>
              </td>
            </tr>
          ) : (
            <tr key={t.id}>
              <td>{t.name}</td><td>{t.adapterType}</td>
              <td className="small muted">{t.connectionConfigJson}</td>
              <td className="small">
                {t.stores.length === 0 ? '—' : t.stores.map((s) => (
                  <span key={s.id} className="store-chip">
                    {s.storePath}{s.alias ? ` (${s.alias})` : ''}
                    <button className="chip-x" title="Remove store" onClick={() => removeStore(s.id)}>×</button>
                  </span>
                ))}
              </td>
              <td className="actions">
                <button onClick={() => testConnection(t.id)}>Test connection</button>
                <button onClick={() => addStore(t.id)}>Add store</button>
                <button onClick={() => startEdit(t)}>Edit</button>
                <button className="danger" onClick={() => remove(t)}>Delete</button>
              </td>
            </tr>
          ))}
          {(targets ?? []).length === 0 && <tr><td colSpan={5} className="muted">No targets yet.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

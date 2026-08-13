import { useState } from 'react'
import { useData, post } from './SimplePages'

interface TargetRow {
  id: string; name: string; targetType: string; adapterType: string
  environment: string | null; credentialRefId: string | null; connectionConfigJson: string
  stores: { id: string; storeType: string; storePath: string; alias: string | null }[]
}

const ADAPTERS = ['nginx', 'apache', 'haproxy', 'generic-file', 'windows-cert-store', 'iis', 'java-keystore', 'java-truststore', 'oracle-wallet', 'f5-bigip']

export default function Targets() {
  const [targets, reload] = useData<TargetRow[]>('/api/v1/targets')
  const [creds] = useData<{ id: string; name: string }[]>('/api/v1/credentials')
  const [name, setName] = useState(''); const [adapter, setAdapter] = useState('nginx')
  const [host, setHost] = useState(''); const [port, setPort] = useState('22'); const [credId, setCredId] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)

  async function add(e: React.FormEvent) {
    e.preventDefault()
    await post('/api/v1/targets', {
      name, adapterType: adapter, targetType: adapter.startsWith('windows') || adapter === 'iis' ? 'WindowsServer' : 'LinuxServer',
      connectionConfig: { host, port: Number(port) }, credentialRefId: credId || null,
    })
    setName(''); setHost(''); reload()
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
      const job = await (await fetch(`${import.meta.env.VITE_API_BASE ?? 'http://localhost:5200'}/api/v1/targets/jobs/${jobId}`)).json()
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
        <select value={adapter} onChange={(e) => setAdapter(e.target.value)}>
          {ADAPTERS.map((a) => <option key={a}>{a}</option>)}
        </select>
        <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="host" required />
        <input value={port} onChange={(e) => setPort(e.target.value)} style={{ width: 80 }} />
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
          {(targets ?? []).map((t) => (
            <tr key={t.id}>
              <td>{t.name}</td><td>{t.adapterType}</td>
              <td className="small muted">{t.connectionConfigJson}</td>
              <td className="small">{t.stores.map((s) => s.storePath + (s.alias ? ` (${s.alias})` : '')).join(', ') || '—'}</td>
              <td className="actions">
                <button onClick={() => testConnection(t.id)}>Test connection</button>
                <button onClick={() => addStore(t.id)}>Add store</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

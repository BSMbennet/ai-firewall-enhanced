import React, { useCallback, useEffect, useState } from 'react'
import { Users, AppWindow, KeyRound, ShieldCheck, Plus, Ban, UserCheck, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../services/api'

const tabs = [
  { id: 'employees', label: 'Employees', icon: Users },
  { id: 'applications', label: 'Applications', icon: AppWindow },
  { id: 'keys', label: 'API keys', icon: KeyRound },
  { id: 'policies', label: 'Policies', icon: ShieldCheck },
]

const card = 'af-card'
const input = 'w-full rounded-xl border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-white outline-none focus:border-cyan-400'

export default function Organization() {
  const [tab, setTab] = useState('employees')
  const [org, setOrg] = useState(null)
  const [members, setMembers] = useState([])
  const [apps, setApps] = useState([])
  const [keys, setKeys] = useState([])
  const [policies, setPolicies] = useState([])
  const [loading, setLoading] = useState(true)
  const [employeeForm, setEmployeeForm] = useState({ email: '', full_name: '', role: 'member' })
  const [appForm, setAppForm] = useState({ name: '', environment: 'production', provider: 'openai', model: 'gpt-4o-mini' })
  const [keyForm, setKeyForm] = useState({ name: '', expires_days: 365, application_id: '', employee_id: '' })
  const [newKey, setNewKey] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [o, m, a, k, p] = await Promise.all([
        api.get('/organization'),
        api.get('/organization/members'),
        api.get('/organization/applications'),
        api.get('/api-keys'),
        api.get('/organization/policies'),
      ])
      setOrg(o.data)
      setMembers(m.data?.members || [])
      setApps(a.data?.applications || [])
      setKeys(k.data?.keys || [])
      setPolicies(p.data?.policies || [])
    } catch (error) {
      toast.error(error.response?.data?.detail || error.response?.data?.error || 'Unable to load organization')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const inviteEmployee = async (event) => {
    event.preventDefault()
    try {
      await api.post('/organization/members', employeeForm)
      toast.success('Invitation sent')
      setEmployeeForm({ email: '', full_name: '', role: 'member' })
      load()
    } catch (error) { toast.error(error.response?.data?.detail || 'Could not invite employee') }
  }

  const changeMember = async (member, changes) => {
    try {
      await api.patch(`/organization/members/${member.id}`, changes)
      toast.success('Employee access updated')
      load()
    } catch (error) { toast.error(error.response?.data?.detail || 'Could not update employee') }
  }

  const createApp = async (event) => {
    event.preventDefault()
    try {
      await api.post('/organization/applications', appForm)
      toast.success('Application created')
      setAppForm({ name: '', environment: 'production', provider: 'openai', model: 'gpt-4o-mini' })
      load()
    } catch (error) { toast.error(error.response?.data?.detail || 'Could not create application') }
  }

  const createKey = async (event) => {
    event.preventDefault()
    try {
      const result = await api.post('/api-keys', { ...keyForm, expires_days: Number(keyForm.expires_days) })
      setNewKey(result.data)
      toast.success('API key created — copy it now')
      load()
    } catch (error) { toast.error(error.response?.data?.detail || 'Could not create API key') }
  }

  const revokeKey = async (key) => {
    try { await api.delete(`/api-keys/${key.id}`); toast.success('API key revoked'); load() }
    catch (error) { toast.error(error.response?.data?.detail || 'Could not revoke API key') }
  }

  const updatePolicy = async (policy, patch) => {
    try { await api.patch(`/organization/policies/${policy.id}`, patch); toast.success('Policy saved'); load() }
    catch (error) { toast.error(error.response?.data?.detail || 'Could not save policy') }
  }

  if (loading) return <div className="af-page">Loading enterprise controls…</div>

  return (
    <div className="af-page">
      <div>
        <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm font-medium text-cyan-400">Enterprise control plane</p>
            <h1 className="text-3xl font-bold tracking-tight">{org?.name || 'Organization'}</h1>
            <p className="mt-1 text-sm text-slate-400">Manage people, AI applications, credentials and security policy from one place.</p>
          </div>
          <button onClick={load} className="inline-flex items-center gap-2 af-btn hover:bg-slate-800"><RefreshCw size={16}/> Refresh</button>
        </div>

        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <div className={`${card} p-4`}><div className="text-sm text-slate-400">Employees</div><div className="mt-1 text-2xl font-bold">{members.length}</div></div>
          <div className={`${card} p-4`}><div className="text-sm text-slate-400">Applications</div><div className="mt-1 text-2xl font-bold">{apps.length}</div></div>
          <div className={`${card} p-4`}><div className="text-sm text-slate-400">Active keys</div><div className="mt-1 text-2xl font-bold">{keys.filter(k => k.is_active).length}</div></div>
          <div className={`${card} p-4`}><div className="text-sm text-slate-400">Policies</div><div className="mt-1 text-2xl font-bold">{policies.length}</div></div>
        </div>

        <div className="mb-6 flex gap-2 overflow-x-auto border-b border-slate-800">
          {tabs.map(({ id, label, icon: Icon }) => <button key={id} onClick={() => setTab(id)} className={`flex shrink-0 items-center gap-2 border-b-2 px-4 py-3 text-sm ${tab === id ? 'border-cyan-400 text-cyan-200' : 'border-transparent text-slate-400 hover:text-white'}`}><Icon size={16}/>{label}</button>)}
        </div>

        {tab === 'employees' && <section className="space-y-5">
          <form onSubmit={inviteEmployee} className={`${card} p-5`}>
            <div className="mb-4 flex items-center gap-2"><Plus size={18} className="text-cyan-400"/><h2 className="font-semibold">Add employee</h2></div>
            <div className="grid gap-3 md:grid-cols-4">
              <input className={input} placeholder="Full name" value={employeeForm.full_name} onChange={e => setEmployeeForm({...employeeForm, full_name: e.target.value})}/>
              <input className={input} type="email" placeholder="Work email" required value={employeeForm.email} onChange={e => setEmployeeForm({...employeeForm, email: e.target.value})}/>
              <select className={input} value={employeeForm.role} onChange={e => setEmployeeForm({...employeeForm, role: e.target.value})}><option value="member">Member</option><option value="developer">Developer</option><option value="security">Security</option><option value="admin">Admin</option><option value="viewer">Viewer</option></select>
              <button className="af-btn af-btn-primary hover:bg-cyan-400">Send invitation</button>
            </div>
          </form>
          <div className={`${card} overflow-hidden`}>
            <div className="border-b border-slate-800 p-5"><h2 className="font-semibold">Employees</h2></div>
            <div className="divide-y divide-slate-800">{members.map(member => <div key={member.id} className="flex flex-col gap-3 p-5 md:flex-row md:items-center md:justify-between"><div><div className="font-medium">{member.full_name || member.email}</div><div className="text-sm text-slate-400">{member.email} · {member.role}</div></div><div className="flex items-center gap-2"><span className={`rounded-full px-2.5 py-1 text-xs ${member.status === 'active' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-amber-500/10 text-amber-300'}`}>{member.status}</span>{member.role !== 'owner' && <>{member.status === 'suspended' ? <button onClick={() => changeMember(member, {status: 'active'})} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs"><UserCheck size={14} className="inline mr-1"/>Restore</button> : <button onClick={() => changeMember(member, {status: 'suspended'})} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs"><Ban size={14} className="inline mr-1"/>Suspend</button>}</>}</div></div>)}</div>
          </div>
        </section>}

        {tab === 'applications' && <section className="space-y-5">
          <form onSubmit={createApp} className={`${card} p-5`}>
            <div className="mb-4 flex items-center gap-2"><Plus size={18} className="text-cyan-400"/><h2 className="font-semibold">Register AI application</h2></div>
            <div className="grid gap-3 md:grid-cols-4"><input className={input} required placeholder="Application name" value={appForm.name} onChange={e => setAppForm({...appForm, name: e.target.value})}/><select className={input} value={appForm.environment} onChange={e => setAppForm({...appForm, environment: e.target.value})}><option>production</option><option>staging</option><option>development</option></select><input className={input} placeholder="Provider" value={appForm.provider} onChange={e => setAppForm({...appForm, provider: e.target.value})}/><input className={input} placeholder="Model" value={appForm.model} onChange={e => setAppForm({...appForm, model: e.target.value})}/></div>
            <button className="mt-3 af-btn af-btn-primary">Create application</button>
          </form>
          <div className={`${card} overflow-hidden`}>{apps.map(app => <div key={app.id} className="flex items-center justify-between border-b border-slate-800 p-5 last:border-0"><div><div className="font-medium">{app.name}</div><div className="text-sm text-slate-400">{app.environment} · {app.provider} · {app.model}</div></div><span className="rounded-full bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300">{app.status}</span></div>)}</div>
        </section>}

        {tab === 'keys' && <section className="space-y-5">
          {newKey && <div className="af-card af-card-pad border-amber-500/30 bg-amber-500/[.06]"><div className="font-semibold text-amber-200">Copy this API key now</div><p className="mt-1 text-sm text-amber-100/70">For security, the secret is shown only when it is created.</p><code className="mt-3 block break-all rounded-xl bg-slate-950 p-3 text-sm text-cyan-300">{newKey.key}</code><button onClick={() => navigator.clipboard?.writeText(newKey.key)} className="mt-3 rounded-lg border border-amber-500/40 px-3 py-1.5 text-sm">Copy key</button></div>}
          <form onSubmit={createKey} className={`${card} p-5`}><h2 className="mb-4 font-semibold">Create gateway API key</h2><div className="grid gap-3 md:grid-cols-4"><input className={input} required placeholder="Key name" value={keyForm.name} onChange={e => setKeyForm({...keyForm, name: e.target.value})}/><select className={input} value={keyForm.application_id} onChange={e => setKeyForm({...keyForm, application_id: e.target.value})}><option value="">No application</option>{apps.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}</select><select className={input} value={keyForm.employee_id} onChange={e => setKeyForm({...keyForm, employee_id: e.target.value})}><option value="">No employee</option>{members.filter(m => m.status !== 'removed').map(m => <option key={m.id} value={m.id}>{m.full_name || m.email}</option>)}</select><input className={input} type="number" min="1" max="3650" value={keyForm.expires_days} onChange={e => setKeyForm({...keyForm, expires_days: e.target.value})}/></div><button className="mt-3 af-btn af-btn-primary">Generate key</button></form>
          <div className={`${card} overflow-hidden`}>{keys.map(key => <div key={key.id} className="flex flex-col gap-3 border-b border-slate-800 p-5 md:flex-row md:items-center md:justify-between"><div><div className="font-medium">{key.name}</div><div className="text-sm text-slate-400">Created {new Date(key.created_at).toLocaleDateString()} · Expires {new Date(key.expires_at).toLocaleDateString()}</div></div><button disabled={!key.is_active} onClick={() => revokeKey(key)} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs disabled:opacity-40">{key.is_active ? 'Revoke' : 'Revoked'}</button></div>)}</div>
        </section>}

        {tab === 'policies' && <section className="space-y-5">{policies.map(policy => <div key={policy.id} className={`${card} p-5`}><div className="mb-5 flex items-center justify-between"><div><h2 className="font-semibold">{policy.name}</h2><p className="text-sm text-slate-400">Organization-wide AI security controls</p></div><ShieldCheck className="text-cyan-400"/></div><div className="grid gap-3 md:grid-cols-2">{[['pii_protection','PII protection'],['prompt_injection_protection','Prompt injection protection'],['sensitive_content_protection','Sensitive content protection'],['audit_logging','Audit logging']].map(([field,label]) => <label key={field} className="flex items-center justify-between rounded-xl border border-slate-800 p-4"><span>{label}</span><input type="checkbox" checked={Boolean(policy[field])} onChange={e => updatePolicy(policy, {[field]: e.target.checked})}/></label>)}</div><label className="mt-4 block text-sm text-slate-300">Requests per minute<input className={`${input} mt-2`} type="number" min="1" max="10000" defaultValue={policy.rate_limit_per_minute} onBlur={e => updatePolicy(policy, {rate_limit_per_minute: Number(e.target.value)})}/></label></div>)}</section>}
      </div>
    </div>
  )
}

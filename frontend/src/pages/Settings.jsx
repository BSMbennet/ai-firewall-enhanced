import React, { useState, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { Key, Copy, RefreshCw, CreditCard, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../services/api'

const Settings = () => {
  const { user, role } = useAuth()
  const [apiKeys, setApiKeys] = useState([])
  const [loading, setLoading] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [billing, setBilling] = useState(null)
  const [usage, setUsage] = useState(null)
  const [billingLoading, setBillingLoading] = useState(false)

  useEffect(() => { if (user) { fetchApiKeys(); fetchBilling() } }, [user])

  const fetchApiKeys = async () => {
    setLoading(true)
    try { const { data } = await api.get('/api-keys'); setApiKeys(data.keys || []) }
    catch (error) { toast.error(error.response?.data?.detail || 'Failed to fetch API keys') }
    finally { setLoading(false) }
  }

  const fetchBilling = async () => {
    try { const [subscription, currentUsage] = await Promise.all([api.get('/billing/subscription'), api.get('/billing/usage')]); setBilling(subscription.data); setUsage(currentUsage.data) }
    catch (error) { console.warn('Billing unavailable:', error.response?.data?.detail || error.message) }
  }

  const createApiKey = async () => {
    setLoading(true)
    try { const { data } = await api.post('/api-keys', { name: newKeyName || 'Default Key' }); setNewKeyName(''); toast.success('API key created. Copy it now; it may only be shown once.'); if (data.key) setApiKeys(current => [{ ...data, key: data.key }, ...current]); else await fetchApiKeys() }
    catch (error) { toast.error(error.response?.data?.detail || 'Failed to create API key') }
    finally { setLoading(false) }
  }

  const revokeKey = async (keyId) => {
    if (!window.confirm('Are you sure you want to revoke this API key?')) return
    setLoading(true)
    try { await api.delete(`/api-keys/${keyId}`); toast.success('API key revoked'); await fetchApiKeys() }
    catch (error) { toast.error(error.response?.data?.detail || 'Failed to revoke API key') }
    finally { setLoading(false) }
  }

  const startCheckout = async (plan) => {
    setBillingLoading(true)
    try { const { data } = await api.post('/billing/checkout', { plan, seats: Math.max(1, billing?.subscription?.seat_quantity || 1) }); if (data.url) window.location.assign(data.url) }
    catch (error) { toast.error(error.response?.data?.detail || 'Billing checkout is not configured yet') }
    finally { setBillingLoading(false) }
  }

  const openPortal = async () => {
    setBillingLoading(true)
    try { const { data } = await api.post('/billing/portal'); if (data.url) window.location.assign(data.url) }
    catch (error) { toast.error(error.response?.data?.detail || 'Customer portal is not available yet') }
    finally { setBillingLoading(false) }
  }

  const copyToClipboard = async (text) => { if (!text) return; await navigator.clipboard.writeText(text); toast.success('Copied to clipboard') }
  const activePlan = billing?.plan || { name: 'Starter', included_seats: 5, requests_month: 10000 }
  const requestCount = usage?.usage?.request_count || 0
  const requestLimit = usage?.limits?.requests_month
  const isPrivileged = ['owner', 'admin'].includes(role)

  return <div className="af-page"><div className="max-w-6xl">
    <h1 className="af-title mb-6">Settings</h1>

    <div className="af-card af-card-pad mb-5">
      <div className="flex items-start justify-between gap-4 mb-5"><div><h2 className="font-semibold text-lg flex items-center gap-2"><CreditCard className="w-5 h-5 text-cyan-300" /> Organization Billing</h2><p className="af-muted">Subscription, seats and monthly AI gateway usage are controlled server-side.</p></div>{isPrivileged && billing?.subscription && <button onClick={openPortal} disabled={billingLoading} className="af-btn af-btn-primary flex items-center gap-2"><ExternalLink className="w-4 h-4" />Manage billing</button>}</div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-950/30 p-4"><p className="af-muted">Current plan</p><p className="text-xl font-bold mt-1">{activePlan.name}</p><p className="text-xs text-slate-500 mt-1">{billing?.subscription?.status || 'Not subscribed'}</p></div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/30 p-4"><p className="af-muted">Seats</p><p className="text-xl font-bold mt-1">{billing?.subscription?.seat_quantity || 0}</p><p className="text-xs text-slate-500 mt-1">Plan includes {activePlan.included_seats}</p></div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/30 p-4"><p className="af-muted">Requests this month</p><p className="text-xl font-bold mt-1">{requestCount.toLocaleString()} {requestLimit ? `/ ${requestLimit.toLocaleString()}` : ''}</p><p className="text-xs text-slate-500 mt-1">Server-enforced usage meter</p></div>
      </div>
      {isPrivileged && !billing?.subscription && <div className="mt-5 grid grid-cols-1 md:grid-cols-2 gap-4"><button onClick={() => startCheckout('starter')} disabled={billingLoading} className="rounded-xl border border-cyan-400/30 bg-cyan-400/10 p-4 text-left hover:bg-cyan-400/15"><p className="font-semibold">Starter · $29/seat/month</p><p className="text-sm text-slate-400 mt-1">10,000 protected AI requests/month.</p></button><button onClick={() => startCheckout('professional')} disabled={billingLoading} className="rounded-xl border border-violet-400/30 bg-violet-400/10 p-4 text-left hover:bg-violet-400/15"><p className="font-semibold">Professional · $79/seat/month</p><p className="text-sm text-slate-400 mt-1">100,000 protected AI requests/month plus SSO/SCIM.</p></button></div>}
    </div>

    <div className="af-card af-card-pad mb-5">
      <h2 className="font-semibold text-lg">API Keys</h2><p className="af-muted mb-4">Manage application access keys. Raw keys are only returned at creation time.</p>
      <div className="flex space-x-3 mb-6"><input type="text" value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="Key name (optional)" className="flex-1 px-4 py-2 border border-slate-700 bg-slate-950 rounded-xl text-white outline-none" /><button onClick={createApiKey} disabled={loading || !user} className="px-4 py-2 af-btn af-btn-primary transition disabled:opacity-50 flex items-center"><RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />Generate Key</button></div>
      <div className="space-y-3">{apiKeys.length === 0 ? <div className="text-center py-8 text-slate-400"><Key className="w-12 h-12 mx-auto mb-3 text-slate-600" /><p>No API keys created yet</p></div> : apiKeys.map(key => <div key={key.id} className="flex items-center justify-between p-4 border border-slate-800 rounded-xl bg-slate-950/30"><div className="flex-1"><div className="flex items-center space-x-2"><span className="font-medium">{key.name || 'Unnamed Key'}</span><span className={`text-xs px-2 py-0.5 rounded-full ${key.is_active ? 'bg-emerald-500/10 text-emerald-300' : 'bg-rose-500/10 text-rose-300'}`}>{key.is_active ? 'Active' : 'Revoked'}</span></div><div className="flex items-center space-x-2 mt-1"><code className="text-xs bg-slate-900 px-2 py-1 rounded font-mono">{key.key ? `${key.key.slice(0, 20)}...${key.key.slice(-10)}` : '••••••••••••••••'}</code>{key.key && <button onClick={() => copyToClipboard(key.key)} className="p-1 hover:bg-slate-900 rounded"><Copy className="w-3 h-3 text-slate-400" /></button>}</div>{key.expires_at && <p className="text-xs text-slate-500 mt-1">Expires: {new Date(key.expires_at).toLocaleDateString()}</p>}</div>{key.is_active && <button onClick={() => revokeKey(key.id)} className="text-rose-400 hover:text-rose-300 text-sm font-medium">Revoke</button>}</div>)}</div>
    </div>
  </div></div>
}
export default Settings

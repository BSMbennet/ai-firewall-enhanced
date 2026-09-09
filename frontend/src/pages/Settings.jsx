import React, { useState, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { Key, Copy, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../services/api'

const Settings = () => {
  const { user } = useAuth()
  const [apiKeys, setApiKeys] = useState([])
  const [loading, setLoading] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')

  useEffect(() => { if (user) fetchApiKeys() }, [user])

  const fetchApiKeys = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api-keys')
      setApiKeys(data.keys || [])
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to fetch API keys')
    } finally { setLoading(false) }
  }

  const createApiKey = async () => {
    setLoading(true)
    try {
      const { data } = await api.post('/api-keys', { name: newKeyName || 'Default Key' })
      setNewKeyName('')
      toast.success('API key created successfully! Copy it now; it may only be shown once.')
      if (data.key) setApiKeys(current => [{ ...data, key: data.key }, ...current])
      else await fetchApiKeys()
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create API key')
    } finally { setLoading(false) }
  }

  const revokeKey = async (keyId) => {
    if (!window.confirm('Are you sure you want to revoke this API key?')) return
    setLoading(true)
    try {
      await api.delete(`/api-keys/${keyId}`)
      toast.success('API key revoked')
      await fetchApiKeys()
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to revoke API key')
    } finally { setLoading(false) }
  }

  const copyToClipboard = async (text) => {
    if (!text) return
    await navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard!')
  }

  return <div className="af-page"><div className="max-w-6xl">
    <h1 className="af-title mb-6">Settings</h1>
    <div className="af-card af-card-pad mb-5">
      <h2 className="font-semibold text-lg">API Keys</h2><p className="af-muted mb-4">Manage your API keys for secure access</p>
      <div className="flex space-x-3 mb-6"><input type="text" value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="Key name (optional)" className="flex-1 px-4 py-2 border border-slate-700 bg-slate-950 rounded-xl text-white outline-none" /><button onClick={createApiKey} disabled={loading || !user} className="px-4 py-2 af-btn af-btn-primary transition disabled:opacity-50 flex items-center"><RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />Generate Key</button></div>
      <div className="space-y-3">{apiKeys.length === 0 ? <div className="text-center py-8 text-slate-400"><Key className="w-12 h-12 mx-auto mb-3 text-slate-600" /><p>No API keys created yet</p></div> : apiKeys.map(key => <div key={key.id} className="flex items-center justify-between p-4 border border-slate-800 rounded-xl bg-slate-950/30"><div className="flex-1"><div className="flex items-center space-x-2"><span className="font-medium">{key.name || 'Unnamed Key'}</span><span className={`text-xs px-2 py-0.5 rounded-full ${key.is_active ? 'bg-emerald-500/10 text-emerald-300' : 'bg-rose-500/10 text-rose-300'}`}>{key.is_active ? 'Active' : 'Revoked'}</span></div><div className="flex items-center space-x-2 mt-1"><code className="text-xs bg-slate-900 px-2 py-1 rounded font-mono">{key.key ? `${key.key.slice(0, 20)}...${key.key.slice(-10)}` : '••••••••••••••••'}</code>{key.key && <button onClick={() => copyToClipboard(key.key)} className="p-1 hover:bg-slate-900 rounded"><Copy className="w-3 h-3 text-slate-400" /></button>}</div>{key.expires_at && <p className="text-xs text-slate-500 mt-1">Expires: {new Date(key.expires_at).toLocaleDateString()}</p>}</div>{key.is_active && <button onClick={() => revokeKey(key.id)} className="text-rose-400 hover:text-rose-300 text-sm font-medium">Revoke</button>}</div>)}</div>
    </div>
    <div className="af-card af-card-pad"><h2 className="font-semibold text-lg mb-4">Usage Statistics</h2><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{['Total Requests','Blocked','Cost'].map(label => <div key={label} className="rounded-xl border border-slate-800 bg-slate-950/30 p-4"><p className="af-muted">{label}</p><p className="text-2xl font-bold">--</p></div>)}</div></div>
  </div></div>
}
export default Settings

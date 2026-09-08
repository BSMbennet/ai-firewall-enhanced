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

  return <div className="min-h-screen bg-gray-50 p-6"><div className="max-w-4xl mx-auto">
    <h1 className="text-2xl font-bold mb-6">Settings</h1>
    <div className="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 className="text-lg font-semibold">API Keys</h2><p className="text-sm text-gray-500 mb-4">Manage your API keys for secure access</p>
      <div className="flex space-x-3 mb-6"><input type="text" value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="Key name (optional)" className="flex-1 px-4 py-2 border border-gray-300 rounded-lg outline-none" /><button onClick={createApiKey} disabled={loading || !user} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition disabled:opacity-50 flex items-center"><RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />Generate Key</button></div>
      <div className="space-y-3">{apiKeys.length === 0 ? <div className="text-center py-8 text-gray-500"><Key className="w-12 h-12 mx-auto mb-3 text-gray-300" /><p>No API keys created yet</p></div> : apiKeys.map(key => <div key={key.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg"><div className="flex-1"><div className="flex items-center space-x-2"><span className="font-medium">{key.name || 'Unnamed Key'}</span><span className={`text-xs px-2 py-0.5 rounded-full ${key.is_active ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>{key.is_active ? 'Active' : 'Revoked'}</span></div><div className="flex items-center space-x-2 mt-1"><code className="text-xs bg-gray-100 px-2 py-1 rounded font-mono">{key.key ? `${key.key.slice(0, 20)}...${key.key.slice(-10)}` : '••••••••••••••••'}</code>{key.key && <button onClick={() => copyToClipboard(key.key)} className="p-1 hover:bg-gray-100 rounded"><Copy className="w-3 h-3 text-gray-500" /></button>}</div>{key.expires_at && <p className="text-xs text-gray-400 mt-1">Expires: {new Date(key.expires_at).toLocaleDateString()}</p>}</div>{key.is_active && <button onClick={() => revokeKey(key.id)} className="text-red-600 hover:text-red-700 text-sm font-medium">Revoke</button>}</div>)}</div>
    </div>
    <div className="bg-white rounded-xl shadow-sm p-6"><h2 className="text-lg font-semibold mb-4">Usage Statistics</h2><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{['Total Requests','Blocked','Cost'].map(label => <div key={label} className="bg-gray-50 rounded-lg p-4"><p className="text-sm text-gray-500">{label}</p><p className="text-2xl font-bold">--</p></div>)}</div></div>
  </div></div>
}
export default Settings

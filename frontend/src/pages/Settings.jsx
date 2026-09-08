import React, { useState, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { Key, Copy, RefreshCw, CheckCircle, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'

const Settings = () => {
  const { user } = useAuth()
  const [apiKeys, setApiKeys] = useState([])
  const [loading, setLoading] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')

  useEffect(() => {
    fetchApiKeys()
  }, [])

  const fetchApiKeys = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/v1/api-keys', {
        headers: { 'Authorization': `Bearer ${user?.access_token}` }
      })
      const data = await response.json()
      setApiKeys(data.keys || [])
    } catch (error) {
      toast.error('Failed to fetch API keys')
    } finally {
      setLoading(false)
    }
  }

  const createApiKey = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/v1/api-keys', {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${user?.access_token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name: newKeyName || 'Default Key' })
      })
      const data = await response.json()
      toast.success('API key created successfully!')
      setNewKeyName('')
      fetchApiKeys()
    } catch (error) {
      toast.error('Failed to create API key')
    } finally {
      setLoading(false)
    }
  }

  const revokeKey = async (keyId) => {
    if (!confirm('Are you sure you want to revoke this API key?')) return
    
    setLoading(true)
    try {
      await fetch(`/api/v1/api-keys/${keyId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${user?.access_token}` }
      })
      toast.success('API key revoked')
      fetchApiKeys()
    } catch (error) {
      toast.error('Failed to revoke API key')
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard!')
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">Settings</h1>

        {/* API Keys Section */}
        <div className="bg-white rounded-xl shadow-sm p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold">API Keys</h2>
              <p className="text-sm text-gray-500">Manage your API keys for secure access</p>
            </div>
          </div>

          <div className="flex space-x-3 mb-6">
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="Key name (optional)"
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
            />
            <button
              onClick={createApiKey}
              disabled={loading}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition disabled:opacity-50 flex items-center"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Generate Key
            </button>
          </div>

          <div className="space-y-3">
            {apiKeys.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <Key className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                <p>No API keys created yet</p>
              </div>
            ) : (
              apiKeys.map((key) => (
                <div key={key.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:border-gray-300 transition">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">{key.name || 'Unnamed Key'}</span>
                      {key.is_active ? (
                        <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">Active</span>
                      ) : (
                        <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full">Revoked</span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2 mt-1">
                      <code className="text-xs bg-gray-100 px-2 py-1 rounded font-mono">
                        {key.key?.slice(0, 20)}...{key.key?.slice(-10)}
                      </code>
                      <button
                        onClick={() => copyToClipboard(key.key)}
                        className="p-1 hover:bg-gray-100 rounded transition"
                      >
                        <Copy className="w-3 h-3 text-gray-500" />
                      </button>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">
                      Expires: {new Date(key.expires_at).toLocaleDateString()}
                    </p>
                  </div>
                  {key.is_active && (
                    <button
                      onClick={() => revokeKey(key.id)}
                      className="text-red-600 hover:text-red-700 text-sm font-medium transition"
                    >
                      Revoke
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Usage Stats */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold mb-4">Usage Statistics</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gray-50 rounded-lg p-4">
              <p className="text-sm text-gray-500">Total Requests</p>
              <p className="text-2xl font-bold">--</p>
            </div>
            <div className="bg-gray-50 rounded-lg p-4">
              <p className="text-sm text-gray-500">Blocked</p>
              <p className="text-2xl font-bold">--</p>
            </div>
            <div className="bg-gray-50 rounded-lg p-4">
              <p className="text-sm text-gray-500">Cost</p>
              <p className="text-2xl font-bold">--</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Settings
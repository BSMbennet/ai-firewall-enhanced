import axios from 'axios'
import { supabase } from '../lib/supabase'

const API_URL = (
  import.meta.env.VITE_API_URL ||
  'https://ai-firewall-enhanced.onrender.com'
).replace(/\/$/, '')

const api = axios.create({
  baseURL: `${API_URL}/v1`,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use(async (config) => {
  const { data } = await supabase.auth.getSession()
  const accessToken = data.session?.access_token
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`
  return config
})

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const requestUrl = String(error.config?.url || '')
    // Workspace provisioning is part of the post-login bootstrap. A transient/backend
    // authorization failure here must never destroy the freshly-created Supabase session.
    const isWorkspaceBootstrap = requestUrl === '/organization' || requestUrl.endsWith('/organization')

    if (error.response?.status === 401 && !isWorkspaceBootstrap) {
      try {
        await supabase.auth.signOut()
      } finally {
        localStorage.removeItem('token')
        localStorage.removeItem('access_token')
        localStorage.removeItem('user')
        if (window.location.pathname !== '/login') window.location.replace('/login')
      }
    }
    return Promise.reject(error)
  }
)

export default api

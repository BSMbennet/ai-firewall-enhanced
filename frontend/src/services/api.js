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

  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }

  return config
})

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const { data } = await supabase.auth.getSession()
      if (data.session) {
        await supabase.auth.signOut()
      }
    }
    return Promise.reject(error)
  }
)

export default api

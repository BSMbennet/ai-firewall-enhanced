// frontend/src/services/supabase.js
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.REACT_APP_SUPABASE_URL
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY

export const supabase = createClient(supabaseUrl, supabaseAnonKey)

// Real-time subscriptions for live updates
export const subscribeToAuditLogs = (callback) => {
  return supabase
    .channel('audit_logs_channel')
    .on('postgres_changes', 
      { event: 'INSERT', schema: 'public', table: 'audit_logs' },
      (payload) => callback(payload.new)
    )
    .subscribe()
}

// Fetch live stats
export const fetchLiveStats = async () => {
  const { data: blocked } = await supabase
    .from('audit_logs')
    .select('count', { count: 'exact' })
    .eq('action', 'BLOCK')
  
  const { data: allowed } = await supabase
    .from('audit_logs')
    .select('count', { count: 'exact' })
    .eq('action', 'ALLOW')
  
  return {
    blocked: blocked?.length || 0,
    allowed: allowed?.length || 0,
    total: (blocked?.length || 0) + (allowed?.length || 0)
  }
}

import { createClient } from '@supabase/supabase-js'

// Vercel can override these values with environment variables.
// The fallback uses the project's publishable key, which is safe for browser use.
const supabaseUrl =
  import.meta.env.VITE_SUPABASE_URL ||
  'https://xtfwoxggtaljuxtwmgxr.supabase.co'

const supabasePublishableKey =
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
  'sb_publishable__X2gAZy2vhbEXMLcEzMXIQ_nZ29X2TG'

if (!supabaseUrl || !supabasePublishableKey) {
  throw new Error('Missing Supabase frontend configuration')
}

export const supabase = createClient(supabaseUrl, supabasePublishableKey)

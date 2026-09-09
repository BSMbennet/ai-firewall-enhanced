import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import SessionTimeoutModal from '../components/SessionTimeoutModal'
import { clearSessionStorage, logoutAndRedirect, startSessionTracking } from '../utils/session'

const AuthContext = createContext(null)
export const useAuth = () => { const context = useContext(AuthContext); if (!context) throw new Error('useAuth must be used within an AuthProvider'); return context }

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null), [session, setSession] = useState(null), [profile, setProfile] = useState(null)
  const [authPolicy, setAuthPolicy] = useState({ require_mfa: false, require_sso: false })
  const [loading, setLoading] = useState(true), [profileLoading, setProfileLoading] = useState(false), [sessionWarning, setSessionWarning] = useState(false)

  const loadProfile = useCallback(async (currentUser) => {
    if (!currentUser) { setProfile(null); setAuthPolicy({ require_mfa: false, require_sso: false }); setProfileLoading(false); return }
    setProfileLoading(true)
    try {
      const { data, error } = await supabase.from('profiles').select('id,full_name,role,organization_id').eq('id', currentUser.id).maybeSingle()
      if (error) throw error
      setProfile(data ?? null)
      if (data?.organization_id) {
        const policy = await supabase.from('organization_settings').select('require_mfa,require_sso').eq('organization_id', data.organization_id).maybeSingle()
        if (!policy.error && policy.data) setAuthPolicy(policy.data)
      }
    } catch (error) { console.error('Failed to load authenticated profile', error); setProfile(null) }
    finally { setProfileLoading(false) }
  }, [])

  useEffect(() => {
    let mounted = true
    const init = async () => { const { data, error } = await supabase.auth.getSession(); if (!mounted) return; if (error) console.error(error); setSession(data.session ?? null); setUser(data.session?.user ?? null); setLoading(false); await loadProfile(data.session?.user ?? null) }
    init()
    const { data: subscription } = supabase.auth.onAuthStateChange((_event, next) => { if (!mounted) return; setSession(next ?? null); setUser(next?.user ?? null); setSessionWarning(false); setLoading(false); window.setTimeout(() => mounted && loadProfile(next?.user ?? null), 0) })
    return () => { mounted = false; subscription.subscription.unsubscribe() }
  }, [loadProfile])

  useEffect(() => {
    if (!user) { setSessionWarning(false); return undefined }
    return startSessionTracking({ role: profile?.role, onWarning: () => setSessionWarning(true), onActivity: () => setSessionWarning(false), onTimeout: () => logoutAndRedirect(signOut) })
  }, [user, profile?.role])

  const signIn = async (email, password) => { const { data, error } = await supabase.auth.signInWithPassword({ email, password }); if (error) throw error; setSession(data.session); setUser(data.user); await loadProfile(data.user); return data }
  const signInWithSSO = async (email) => { const domain = String(email || '').split('@')[1]?.trim().toLowerCase(); if (!domain) throw new Error('Enter your work email first'); const { data, error } = await supabase.auth.signInWithSSO({ domain, options: { redirectTo: `${window.location.origin}/auth/callback` } }); if (error) throw error; if (data?.url) window.location.assign(data.url); return data }
  const signInWithProvider = async (provider) => { const { data, error } = await supabase.auth.signInWithOAuth({ provider, options: { redirectTo: `${window.location.origin}/auth/callback` } }); if (error) throw error; return data }
  const signUp = async (email, password, metadata = {}) => { const { data, error } = await supabase.auth.signUp({ email, password, options: { data: metadata } }); if (error) throw error; return data }
  const signOut = async () => { try { const { error } = await supabase.auth.signOut(); if (error) throw error } finally { clearSessionStorage(); setSession(null); setUser(null); setProfile(null); setAuthPolicy({ require_mfa: false, require_sso: false }); setSessionWarning(false) } }
  const staySignedIn = () => setSessionWarning(false)

  return <AuthContext.Provider value={{ user, session, profile, role: profile?.role ?? null, organizationId: profile?.organization_id ?? null, authPolicy, loading, profileLoading, signIn, signInWithSSO, signInWithProvider, signUp, signOut, staySignedIn, supabase }}>{children}{sessionWarning && user && <SessionTimeoutModal onStaySignedIn={staySignedIn} onLogout={() => logoutAndRedirect(signOut)} />}</AuthContext.Provider>
}

import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import SessionTimeoutModal from '../components/SessionTimeoutModal'
import { clearSessionStorage, logoutAndRedirect, startSessionTracking } from '../utils/session'

const AuthContext = createContext(null)
export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within an AuthProvider')
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [session, setSession] = useState(null)
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(true)
  const [profileLoading, setProfileLoading] = useState(false)
  const [sessionWarning, setSessionWarning] = useState(false)

  const loadProfile = useCallback(async (currentUser) => {
    if (!currentUser) {
      setProfile(null)
      setProfileLoading(false)
      return
    }
    setProfileLoading(true)
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('id,full_name,role,organization_id')
        .eq('id', currentUser.id)
        .maybeSingle()
      if (error) throw error
      setProfile(data ?? null)
    } catch (error) {
      console.error('Failed to load authenticated profile', error)
      setProfile(null)
    } finally {
      setProfileLoading(false)
    }
  }, [])

  useEffect(() => {
    let mounted = true
    const init = async () => {
      const { data, error } = await supabase.auth.getSession()
      if (!mounted) return
      if (error) console.error('Failed to restore Supabase session', error)
      const nextSession = data.session ?? null
      setSession(nextSession)
      setUser(nextSession?.user ?? null)
      setLoading(false)
      await loadProfile(nextSession?.user ?? null)
    }
    init()

    const { data: subscription } = supabase.auth.onAuthStateChange((_event, next) => {
      if (!mounted) return
      setSession(next ?? null)
      setUser(next?.user ?? null)
      setSessionWarning(false)
      setLoading(false)
      window.setTimeout(() => {
        if (mounted) loadProfile(next?.user ?? null)
      }, 0)
    })

    return () => {
      mounted = false
      subscription.subscription.unsubscribe()
    }
  }, [loadProfile])

  useEffect(() => {
    if (!user) {
      setSessionWarning(false)
      return undefined
    }
    return startSessionTracking({
      role: profile?.role,
      onWarning: () => setSessionWarning(true),
      onActivity: () => setSessionWarning(false),
      onTimeout: () => logoutAndRedirect(signOut),
    })
  }, [user, profile?.role])

  const signIn = async (email, password) => {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) throw error
    setSession(data.session)
    setUser(data.user)
    await loadProfile(data.user)
    return data
  }

  const signInWithProvider = async (provider) => {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: window.location.origin },
    })
    if (error) throw error
    return data
  }

  const signUp = async (email, password, metadata = {}) => {
    const { data, error } = await supabase.auth.signUp({ email, password, options: { data: metadata } })
    if (error) throw error
    return data
  }

  const signOut = async () => {
    try {
      const { error } = await supabase.auth.signOut()
      if (error) throw error
    } finally {
      clearSessionStorage()
      setSession(null)
      setUser(null)
      setProfile(null)
      setSessionWarning(false)
    }
  }

  const staySignedIn = () => setSessionWarning(false)

  const value = {
    user,
    session,
    profile,
    role: profile?.role ?? null,
    organizationId: profile?.organization_id ?? null,
    loading,
    profileLoading,
    signIn,
    signInWithProvider,
    signUp,
    signOut,
    staySignedIn,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
      {sessionWarning && user && (
        <SessionTimeoutModal onStaySignedIn={staySignedIn} onLogout={() => logoutAndRedirect(signOut)} />
      )}
    </AuthContext.Provider>
  )
}

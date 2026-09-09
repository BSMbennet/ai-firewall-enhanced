import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import api from '../services/api'
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

  const loadProfile = useCallback(async (hasSession) => {
    if (!hasSession) {
      setProfile(null)
      setProfileLoading(false)
      return
    }
    setProfileLoading(true)
    try {
      const { data } = await api.get('/me')
      setProfile(data)
    } catch (error) {
      if (error.response?.status !== 401) console.error('Failed to load authenticated profile', error)
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
      setSession(data.session ?? null)
      setUser(data.session?.user ?? null)
      setLoading(false)
      await loadProfile(Boolean(data.session))
    }
    init()

    const { data: subscription } = supabase.auth.onAuthStateChange(async (_event, next) => {
      if (!mounted) return
      setSession(next ?? null)
      setUser(next?.user ?? null)
      setSessionWarning(false)
      setLoading(false)
      await loadProfile(Boolean(next))
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
    await loadProfile(Boolean(data.session))
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
    organization: profile?.organization ?? null,
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

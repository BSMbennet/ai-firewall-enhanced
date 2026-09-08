import { createContext, useContext, useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const AuthContext = createContext(null)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within an AuthProvider')
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true

    const initializeAuth = async () => {
      const { data, error } = await supabase.auth.getSession()
      if (!mounted) return

      if (error) {
        console.error('Failed to restore Supabase session', error)
      }

      setSession(data.session ?? null)
      setUser(data.session?.user ?? null)
      setLoading(false)
    }

    initializeAuth()

    const { data: subscription } = supabase.auth.onAuthStateChange(
      (_event, nextSession) => {
        if (!mounted) return
        setSession(nextSession ?? null)
        setUser(nextSession?.user ?? null)
        setLoading(false)
      }
    )

    return () => {
      mounted = false
      subscription.subscription.unsubscribe()
    }
  }, [])

  const signIn = async (email, password) => {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) throw error
    setSession(data.session)
    setUser(data.user)
    return data
  }

  const signUp = async (email, password, metadata = {}) => {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { data: metadata },
    })
    if (error) throw error
    return data
  }

  const signOut = async () => {
    const { error } = await supabase.auth.signOut()
    if (error) throw error
    setSession(null)
    setUser(null)
  }

  const value = { user, session, loading, signIn, signUp, signOut }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

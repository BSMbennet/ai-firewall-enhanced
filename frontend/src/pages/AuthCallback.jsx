import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import PublicShell from '../components/PublicShell'

export default function AuthCallback() {
  const navigate = useNavigate()
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    const finish = async () => {
      try {
        const code = new URLSearchParams(window.location.search).get('code')
        if (code) {
          const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(code)
          if (exchangeError) throw exchangeError
        }
        const { data } = await supabase.auth.getSession()
        if (data.session) navigate('/dashboard', { replace: true })
        else throw new Error('No authenticated session was returned by the identity provider')
      } catch (err) { if (active) setError(err.message || 'Unable to complete enterprise sign-in') }
    }
    finish()
    return () => { active = false }
  }, [navigate])
  return <PublicShell eyebrow="IDENTITY CALLBACK" title="Completing secure sign-in"><div className="af-card af-card-pad max-w-xl mx-auto text-center">{error ? <><p className="text-rose-300">{error}</p><button className="af-btn af-btn-primary mt-5" onClick={() => navigate('/login')}>Return to sign in</button></> : <><div className="mx-auto mb-4 h-8 w-8 rounded-full border-2 border-cyan-300 border-t-transparent animate-spin"/><p className="af-muted">Validating your organization identity…</p></>}</div></PublicShell>
}

import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Shield, Lock, ArrowRight } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../contexts/AuthContext'
import PublicShell from '../components/PublicShell.jsx'

export default function ResetPassword() {
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [ready, setReady] = useState(false)
  const { updatePassword } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    const hash = window.location.hash
    const query = new URLSearchParams(window.location.search)
    const hasRecoverySession = hash.includes('access_token') || query.has('code')
    setReady(hasRecoverySession || Boolean(window.location.hash))
  }, [])

  const submit = async (event) => {
    event.preventDefault()
    if (password.length < 8) return toast.error('Password must be at least 8 characters')
    if (password !== confirmPassword) return toast.error('Passwords do not match')

    setLoading(true)
    try {
      await updatePassword(password)
      toast.success('Password updated successfully')
      navigate('/login', { replace: true })
    } catch (error) {
      toast.error(error.message || 'Unable to update password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PublicShell title="Reset password">
      <div className="px-5 py-12 md:py-20">
        <section className="af-card af-card-pad mx-auto w-full max-w-md">
          <div className="text-center">
            <div className="mx-auto af-brand-icon"><Shield size={21} /></div>
            <h1 className="mt-5 font-[Space_Grotesk] text-3xl font-bold">Set a new password</h1>
            <p className="mt-2 text-sm leading-6 text-slate-400">Choose a new password for your AI Firewall account.</p>
          </div>

          <form onSubmit={submit} className="mt-8 space-y-5">
            <label className="block">
              <span className="af-label">NEW PASSWORD</span>
              <div className="relative mt-2">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                <input type="password" required minLength="8" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
              </div>
            </label>
            <label className="block">
              <span className="af-label">CONFIRM PASSWORD</span>
              <div className="relative mt-2">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                <input type="password" required minLength="8" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Repeat your password" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
              </div>
            </label>
            <button disabled={loading} className="w-full af-btn af-btn-primary py-3 disabled:opacity-50">{loading ? 'UPDATING…' : 'UPDATE PASSWORD'} <ArrowRight size={15} className="inline ml-2" /></button>
          </form>

          {!ready && <p className="mt-4 text-center text-xs text-amber-300">Open this page using the password-reset link sent to your email.</p>}
          <p className="mt-6 text-center text-sm text-slate-500"><Link to="/login" className="text-cyan-300">Return to sign in</Link></p>
        </section>
      </div>
    </PublicShell>
  )
}

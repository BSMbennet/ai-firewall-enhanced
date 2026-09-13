import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { Shield, Mail, Lock, ArrowRight, Building2 } from 'lucide-react'
import toast from 'react-hot-toast'
import PublicShell from '../components/PublicShell.jsx'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [ssoLoading, setSsoLoading] = useState(false)
  const { signIn, signInWithSSO, signOut } = useAuth()
  const navigate = useNavigate()

  const submit = async (event) => {
    event.preventDefault()
    setLoading(true)
    try {
      const result = await signIn(email.trim(), password)
      if (result.policy?.require_sso) {
        await signOut()
        throw new Error('This organization requires Enterprise SSO. Use your work email with SSO.')
      }
      if (result.policy?.require_mfa) navigate('/mfa')
      else {
        toast.success('Logged in successfully')
        navigate('/dashboard')
      }
    } catch (error) {
      toast.error(error.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const sso = async () => {
    setSsoLoading(true)
    try {
      await signInWithSSO(email.trim())
    } catch (error) {
      toast.error(error.message || 'Enterprise SSO is not configured for this email domain')
      setSsoLoading(false)
    }
  }

  return (
    <PublicShell title="Sign in" minimal>
      <div className="px-5 py-12 sm:py-16">
        <section className="af-card af-card-pad mx-auto w-full max-w-md">
          <div className="mb-8 text-center">
            <div className="mx-auto af-brand-icon"><Shield size={22} /></div>
            <h1 className="mt-5 font-[Space_Grotesk] text-3xl font-bold">Welcome back</h1>
            <p className="mt-2 text-sm text-slate-400">Sign in to your AI Firewall workspace.</p>
          </div>

          <div className="mb-5">
            <label className="block">
              <span className="af-label">WORK EMAIL</span>
              <div className="relative mt-2">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" autoComplete="email" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
              </div>
            </label>
            <button type="button" onClick={sso} disabled={ssoLoading || !email.trim()} className="w-full af-btn af-btn-primary mt-3 py-3 disabled:opacity-50">
              {ssoLoading ? 'REDIRECTING…' : 'CONTINUE WITH ENTERPRISE SSO'} <Building2 size={15} className="inline ml-2" />
            </button>
          </div>

          <div className="mb-5 flex items-center gap-3"><div className="h-px flex-1 bg-slate-800" /><span className="af-label">OR PASSWORD</span><div className="h-px flex-1 bg-slate-800" /></div>

          <form onSubmit={submit} className="space-y-5">
            <label className="block">
              <span className="af-label">PASSWORD</span>
              <div className="relative mt-2">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Your password" autoComplete="current-password" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
              </div>
            </label>
            <div className="flex justify-end"><Link to="/forgot-password" className="text-sm text-cyan-300 hover:text-cyan-200">Forgot password?</Link></div>
            <button disabled={loading || !email.trim()} className="w-full af-btn py-3 disabled:opacity-50">{loading ? 'AUTHENTICATING…' : 'SIGN IN WITH PASSWORD'} <ArrowRight size={15} className="inline ml-2" /></button>
          </form>

          <p className="mt-7 text-center text-sm text-slate-500">No workspace yet? <Link to="/register" className="text-cyan-300">Create an organization</Link></p>
        </section>
      </div>
    </PublicShell>
  )
}

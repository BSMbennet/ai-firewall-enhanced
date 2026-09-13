import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Mail, Lock, Building2, ArrowRight } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../contexts/AuthContext'
import PublicShell from '../components/PublicShell.jsx'

export default function Register() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [company, setCompany] = useState('')
  const [loading, setLoading] = useState(false)
  const { signUp } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (event) => {
    event.preventDefault()
    setLoading(true)
    try {
      const { session } = await signUp(email.trim(), password, { company: company.trim() || undefined })
      if (session) {
        toast.success('Account created successfully')
        navigate('/dashboard')
      } else {
        toast.success('Account created. Check your email to confirm your address.')
        navigate('/login')
      }
    } catch (error) {
      toast.error(error.message || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PublicShell title="Workspace registration" minimal>
      <div className="px-5 py-12 sm:py-16">
        <section className="af-card af-card-pad mx-auto w-full max-w-md">
          <div className="mb-8 text-center">
            <div className="mx-auto af-brand-icon"><Shield size={22} /></div>
            <h1 className="mt-5 font-[Space_Grotesk] text-3xl font-bold">Create account</h1>
            <p className="mt-2 text-sm text-slate-400">Create your AI Firewall workspace.</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <label className="block">
              <span className="af-label">WORK EMAIL</span>
              <div className="relative mt-2">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" autoComplete="email" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
              </div>
            </label>

            <label className="block">
              <span className="af-label">PASSWORD</span>
              <div className="relative mt-2">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                <input type="password" required minLength="8" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters" autoComplete="new-password" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
              </div>
            </label>

            <label className="block">
              <span className="af-label">ORGANIZATION / COMPANY</span>
              <div className="relative mt-2">
                <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                <input value={company} onChange={(e) => setCompany(e.target.value)} placeholder="Optional" autoComplete="organization" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
              </div>
            </label>

            <button disabled={loading} className="w-full af-btn af-btn-primary py-3 disabled:opacity-50">
              {loading ? 'CREATING ACCOUNT…' : 'CREATE ACCOUNT'} <ArrowRight size={15} className="inline ml-2" />
            </button>
          </form>

          <p className="mt-7 text-center text-sm text-slate-500">Already registered? <Link to="/login" className="text-cyan-300">Sign in</Link></p>
        </section>
      </div>
    </PublicShell>
  )
}

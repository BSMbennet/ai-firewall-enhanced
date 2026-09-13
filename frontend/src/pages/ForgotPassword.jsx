import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Mail, ArrowRight, CheckCircle2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../contexts/AuthContext'
import PublicShell from '../components/PublicShell.jsx'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)
  const { resetPassword } = useAuth()

  const submit = async (event) => {
    event.preventDefault()
    setLoading(true)
    try {
      await resetPassword(email.trim())
      setSent(true)
      toast.success('Recovery email sent')
    } catch (error) {
      toast.error(error.message || 'Unable to send recovery email')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PublicShell title="Account recovery">
      <div className="px-5 py-12 md:py-20">
        <section className="af-card af-card-pad mx-auto w-full max-w-md">
          <div className="text-center">
            <div className="mx-auto af-brand-icon"><Shield size={21} /></div>
            <h1 className="mt-5 font-[Space_Grotesk] text-3xl font-bold">Recover your account</h1>
            <p className="mt-2 text-sm leading-6 text-slate-400">Enter your work email and we will send you a secure password-reset link.</p>
          </div>

          {sent ? (
            <div className="mt-8 rounded-xl border border-cyan-300/20 bg-cyan-300/5 p-5 text-center">
              <CheckCircle2 className="mx-auto text-cyan-300" size={28} />
              <h2 className="mt-3 font-semibold text-white">Check your inbox</h2>
              <p className="mt-2 text-sm leading-6 text-slate-400">If an account exists for this email, a recovery link has been sent. Check spam if you do not see it.</p>
              <Link to="/login" className="mt-5 inline-flex af-btn af-btn-primary px-5 py-3">Return to sign in <ArrowRight size={15} className="ml-2" /></Link>
            </div>
          ) : (
            <form onSubmit={submit} className="mt-8 space-y-5">
              <label className="block">
                <span className="af-label">WORK EMAIL</span>
                <div className="relative mt-2">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                  <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400" />
                </div>
              </label>
              <button disabled={loading} className="w-full af-btn af-btn-primary py-3 disabled:opacity-50">{loading ? 'SENDING…' : 'SEND RESET LINK'} <ArrowRight size={15} className="inline ml-2" /></button>
            </form>
          )}

          <p className="mt-6 text-center text-sm text-slate-500">Remember your password? <Link to="/login" className="text-cyan-300">Sign in</Link></p>
        </section>
      </div>
    </PublicShell>
  )
}

import React,{useState}from'react'
import {useNavigate,Link}from'react-router-dom'
import {Shield,Mail,Lock,Building2,ArrowRight,CheckCircle2}from'lucide-react'
import toast from'react-hot-toast'
import {useAuth}from'../contexts/AuthContext'
import PublicShell from'../components/PublicShell.jsx'

export default function Register(){
 const[email,setEmail]=useState(''),[password,setPassword]=useState(''),[company,setCompany]=useState(''),[loading,setLoading]=useState(false)
 const{signUp}=useAuth();const navigate=useNavigate()
 const handleSubmit=async e=>{e.preventDefault();setLoading(true);try{const{session}=await signUp(email,password,{company:company||undefined});if(session){toast.success('Account created successfully');navigate('/dashboard')}else{toast.success('Account created. Check your email to confirm your address.');navigate('/login')}}catch(error){toast.error(error.message||'Registration failed')}finally{setLoading(false)}}
 return <PublicShell title="Workspace registration">
  <div className="px-5 py-12 md:py-16"><div className="mx-auto grid max-w-6xl items-center gap-12 lg:grid-cols-2">
   <section><div className="af-eyebrow">DEPLOY / PROTECT / CONTROL</div><h1 className="mt-4 font-[Space_Grotesk] text-5xl font-bold tracking-tight">Create your AI security workspace.</h1><p className="mt-5 max-w-lg text-slate-400 leading-7">Set up your organization and start routing AI traffic through a centralized security gateway.</p><div className="mt-8 grid gap-3">{[['Organization control','Manage employees, applications and API keys.'],['Threat protection','Inspect requests before they reach your AI providers.'],['Security visibility','Review activity, risk and audit evidence.']].map(([a,b])=><div className="af-card af-card-pad" key={a}><div className="flex items-center gap-3"><CheckCircle2 size={17} className="text-cyan-300"/><b className="text-sm">{a}</b></div><p className="mt-2 pl-7 text-xs text-slate-500">{b}</p></div>)}</div></section>
   <section className="af-card af-card-pad w-full max-w-md mx-auto"><div className="mb-7 text-center"><div className="mx-auto af-brand-icon"><Shield size={21}/></div><h1 className="mt-5 font-[Space_Grotesk] text-2xl font-bold">Create workspace</h1><p className="mt-2 text-sm text-slate-400">Start with a secure organization account.</p></div>
    <form onSubmit={handleSubmit} className="space-y-5"><label className="block"><span className="af-label">WORK EMAIL</span><div className="relative mt-2"><Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16}/><input type="email" required value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@company.com" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400"/></div></label><label className="block"><span className="af-label">PASSWORD</span><div className="relative mt-2"><Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16}/><input type="password" required minLength="8" value={password} onChange={e=>setPassword(e.target.value)} placeholder="At least 8 characters" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400"/></div></label><label className="block"><span className="af-label">ORGANIZATION / COMPANY</span><div className="relative mt-2"><Building2 className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16}/><input value={company} onChange={e=>setCompany(e.target.value)} placeholder="Optional" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400"/></div></label><button disabled={loading} className="w-full af-btn af-btn-primary py-3 disabled:opacity-50">{loading?'CREATING WORKSPACE…':'CREATE WORKSPACE'} <ArrowRight size={15} className="inline ml-2"/></button></form>
    <p className="mt-6 text-center text-sm text-slate-500">Already registered? <Link to="/login" className="text-cyan-300">Sign in</Link></p>
   </section>
  </div></div>
 </PublicShell>
}

import React,{useState}from'react'
import {useNavigate,Link}from'react-router-dom'
import {useAuth}from'../contexts/AuthContext'
import {Shield,Mail,Lock,ArrowRight}from'lucide-react'
import toast from'react-hot-toast'
import PublicShell from'../components/PublicShell.jsx'

export default function Login(){
 const[email,setEmail]=useState(''),[password,setPassword]=useState(''),[loading,setLoading]=useState(false)
 const{signIn,signInWithProvider}=useAuth();const navigate=useNavigate()
 const submit=async e=>{e.preventDefault();setLoading(true);try{await signIn(email,password);toast.success('Logged in successfully');navigate('/dashboard')}catch(error){toast.error(error.message||'Login failed')}finally{setLoading(false)}}
 const sso=async provider=>{try{await signInWithProvider(provider)}catch(error){toast.error(error.message||`${provider} SSO is not configured`)}}
 return <PublicShell title="Secure access">
  <div className="px-5 py-12 md:py-20"><div className="mx-auto grid max-w-6xl items-center gap-12 lg:grid-cols-2">
   <section className="hidden lg:block"><div className="af-eyebrow">ZERO TRUST / CONTROL PLANE</div><h1 className="mt-4 max-w-xl font-[Space_Grotesk] text-5xl font-bold tracking-tight">Your AI security command center starts here.</h1><p className="mt-5 max-w-lg text-slate-400 leading-7">Authenticate securely to monitor AI traffic, enforce policies, manage employees and review security events.</p><div className="mt-8 space-y-3">{['Organization-scoped access control','Real-time AI request visibility','Audit-ready security telemetry'].map(x=><div className="af-card af-card-pad flex items-center gap-3" key={x}><Shield size={17} className="text-cyan-300"/><span className="text-sm">{x}</span></div>)}</div></section>
   <section className="af-card af-card-pad w-full max-w-md mx-auto"><div className="mb-7 text-center"><div className="mx-auto af-brand-icon"><Shield size={21}/></div><h1 className="mt-5 font-[Space_Grotesk] text-2xl font-bold">Welcome back</h1><p className="mt-2 text-sm text-slate-400">Sign in to your AI Firewall workspace.</p></div>
    <div className="grid grid-cols-2 gap-3 mb-5"><button type="button" onClick={()=>sso('azure')} className="af-btn">Microsoft / Entra</button><button type="button" onClick={()=>sso('google')} className="af-btn">Google Workspace</button></div>
    <div className="mb-5 flex items-center gap-3"><div className="h-px flex-1 bg-slate-800"/><span className="af-label">OR EMAIL</span><div className="h-px flex-1 bg-slate-800"/></div>
    <form onSubmit={submit} className="space-y-5"><label className="block"><span className="af-label">EMAIL ADDRESS</span><div className="relative mt-2"><Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16}/><input type="email" required value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@company.com" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400"/></div></label><label className="block"><span className="af-label">PASSWORD</span><div className="relative mt-2"><Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16}/><input type="password" required value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••" className="w-full rounded-xl border border-slate-700 bg-slate-950/70 py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-cyan-400"/></div></label><button disabled={loading} className="w-full af-btn af-btn-primary py-3 disabled:opacity-50">{loading?'AUTHENTICATING…':'SIGN IN'} <ArrowRight size={15} className="inline ml-2"/></button></form>
    <p className="mt-6 text-center text-sm text-slate-500">No workspace yet? <Link to="/register" className="text-cyan-300">Create an account</Link></p>
   </section>
  </div></div>
 </PublicShell>
}

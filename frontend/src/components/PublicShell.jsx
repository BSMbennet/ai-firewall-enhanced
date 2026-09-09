import React,{useEffect,useState}from 'react'
import {Link}from'react-router-dom'
import {Shield,Menu,X,ArrowRight}from'lucide-react'

export default function PublicShell({children,title='Enterprise AI Security'}){
 const[open,setOpen]=useState(false),[block,setBlock]=useState(48291)
 useEffect(()=>{const t=setInterval(()=>setBlock(v=>v+1),8000);return()=>clearInterval(t)},[])
 return <div className="af-app min-h-screen text-white">
  <header className="af-header">
   <Link to="/" className="af-brand"><span className="af-brand-icon"><Shield size={20}/></span><span><b>AI Firewall</b><small>ENTERPRISE SECURITY</small></span></Link>
   <div className="af-live"><i/> LIVE <span className="af-header-block">ENCLAVE #{block}</span></div>
   <nav className="hidden md:flex items-center gap-2"><Link className="af-btn" to="/">PLATFORM</Link><Link className="af-btn" to="/login">SIGN IN</Link><Link className="af-btn af-btn-primary" to="/register">GET STARTED <ArrowRight size={13} className="inline ml-1"/></Link></nav>
   <button className="af-menu-btn" onClick={()=>setOpen(v=>!v)} aria-label="Open navigation">{open?<X size={18}/>:<Menu size={18}/>}</button>
  </header>
  <div className="af-status"><span className="pulse-dot"/> SECURITY ENCLAVE <b>//</b> BLOCK #{block} <span>ALL DEFENSE SYSTEMS NOMINAL</span></div>
  {open&&<div className="fixed z-40 top-[104px] left-3 right-3 rounded-xl border border-slate-800 bg-[#0d131e] p-3 shadow-2xl md:hidden"><Link className="af-nav" to="/" onClick={()=>setOpen(false)}>PLATFORM</Link><Link className="af-nav" to="/login" onClick={()=>setOpen(false)}>SIGN IN</Link><Link className="af-nav active" to="/register" onClick={()=>setOpen(false)}>GET STARTED</Link></div>}
  <main className="pt-[104px] min-h-screen">{title&&<div className="mx-auto max-w-7xl px-5 pt-8"><div className="af-eyebrow">AI FIREWALL / {title.toUpperCase()}</div></div>}{children}</main>
 </div>
}

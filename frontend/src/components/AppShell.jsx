import React,{useEffect,useState}from'react'
import {NavLink}from'react-router-dom'
import {useAuth}from'../contexts/AuthContext'
import {Shield,Terminal,BarChart3,Layers3,Building2,Bell,Settings as SettingsIcon,Menu,X,LogOut}from'lucide-react'

const nav=[
 ['/dashboard',Terminal,'COMMAND',null],
 ['/enterprise-operations',Bell,'LOGS',['owner','admin','security']],
 ['/compliance',BarChart3,'METRICS',null],
 ['/organization',Layers3,'POLICIES',['owner','admin','security']],
 ['/enterprise-security',Building2,'CONFIG',['owner','admin']],
 ['/settings',SettingsIcon,'SETTINGS',null],
]

export default function AppShell({children}){
 const {user,role,signOut}=useAuth(),[block,setBlock]=useState(48291),[open,setOpen]=useState(false),[loggingOut,setLoggingOut]=useState(false)
 useEffect(()=>{const t=setInterval(()=>setBlock(v=>v+1),8000);return()=>clearInterval(t)},[])
 const visibleNav=nav.filter(([, , , roles])=>!roles||roles.includes(role))
 const handleLogout=async()=>{if(loggingOut)return;setLoggingOut(true);try{await signOut()}finally{window.location.replace('/login')}}
 return <div className="af-app">
  <header className="af-header"><NavLink to="/dashboard" className="af-brand"><span className="af-brand-icon"><Shield size={20}/></span><span><b>AI Firewall</b><small>ENTERPRISE SECURITY</small></span></NavLink><div className="af-live"><i/> LIVE <span className="af-header-block">ENCLAVE #{block}</span></div><div className="af-profile"><span className="af-email">{user?.email||'operator@secure'}</span><span className="af-avatar">{(user?.email||'A')[0].toUpperCase()}</span><button className="af-menu-btn" onClick={()=>setOpen(!open)} aria-label="Open navigation menu">{open?<X size={18}/>:<Menu size={18}/>}</button></div></header>
  <div className="af-status"><span className="pulse-dot"/> SECURITY ENCLAVE <b>//</b> BLOCK #{block} <span>ALL DEFENSE SYSTEMS NOMINAL</span></div>
  <aside className={'af-sidebar '+(open?'open':'')}>{visibleNav.map(([to,Icon,label])=><NavLink key={to} to={to} onClick={()=>setOpen(false)} className={({isActive})=>'af-nav '+(isActive?'active':'')}><Icon size={18}/><span>{label}</span></NavLink>)}<div className="mt-auto border-t border-slate-800 pt-3"><button type="button" onClick={handleLogout} disabled={loggingOut} className="af-nav w-full text-red-400 hover:text-red-300 disabled:opacity-50"><LogOut size={18}/><span>{loggingOut?'LOGGING OUT…':'LOGOUT'}</span></button></div></aside>
  <main className="af-main">{children}</main><nav className="af-bottom-nav">{visibleNav.map(([to,Icon,label])=><NavLink key={to} to={to} className={({isActive})=>'af-bottom-item '+(isActive?'active':'')}><Icon size={19}/><span>{label}</span></NavLink>)}</nav>
 </div>
}
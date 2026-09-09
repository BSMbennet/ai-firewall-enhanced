import React,{useEffect,useState}from 'react'
import {NavLink,useLocation} from 'react-router-dom'
import {useAuth} from '../contexts/AuthContext'
import {Shield,Terminal,ScrollText,BarChart3,Layers3,Settings,Building2,Bell,Menu,X} from 'lucide-react'

const nav=[
 ['/dashboard',Terminal,'COMMAND'],['/enterprise-operations',Bell,'LOGS'],['/compliance',BarChart3,'METRICS'],
 ['/organization',Layers3,'POLICIES'],['/enterprise-security',Building2,'CONFIG']
]
export default function AppShell({children}){
 const {user}=useAuth(),[block,setBlock]=useState(48291),[open,setOpen]=useState(false),loc=useLocation()
 useEffect(()=>{const t=setInterval(()=>setBlock(v=>v+1),8000);return()=>clearInterval(t)},[])
 return <div className="af-app">
   <header className="af-header">
    <NavLink to="/dashboard" className="af-brand"><span className="af-brand-icon"><Shield size={20}/></span><span><b>AI Firewall</b><small>ENTERPRISE SECURITY</small></span></NavLink>
    <div className="af-live"><i/> LIVE <span className="af-header-block">ENCLAVE #{block}</span></div>
    <div className="af-profile"><span className="af-email">{user?.email||'operator@secure'}</span><span className="af-avatar">{(user?.email||'A')[0].toUpperCase()}</span><button className="af-menu-btn" onClick={()=>setOpen(!open)}>{open?<X size={18}/>:<Menu size={18}/>}</button></div>
   </header>
   <div className="af-status"><span className="pulse-dot"/> SECURITY ENCLAVE <b>//</b> BLOCK #{block} <span>ALL DEFENSE SYSTEMS NOMINAL</span></div>
   <aside className={'af-sidebar '+(open?'open':'')}>{nav.map(([to,Icon,label])=><NavLink key={to} to={to} onClick={()=>setOpen(false)} className={({isActive})=>'af-nav '+(isActive?'active':'')}><Icon size={18}/><span>{label}</span></NavLink>)}</aside>
   <main className="af-main">{children}</main>
   <nav className="af-bottom-nav">{nav.map(([to,Icon,label])=><NavLink key={to} to={to} className={({isActive})=>'af-bottom-item '+(isActive?'active':'')}><Icon size={19}/><span>{label}</span></NavLink>)}</nav>
 </div>
}
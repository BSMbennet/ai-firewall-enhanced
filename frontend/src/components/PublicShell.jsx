import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Menu, X, ArrowRight } from 'lucide-react'

export default function PublicShell({ children, title = 'Enterprise AI Security' }) {
  const [open, setOpen] = useState(false)
  const [block, setBlock] = useState(48291)

  useEffect(() => {
    const timer = setInterval(() => setBlock((value) => value + 1), 8000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="af-app min-h-screen text-white">
      <header className="af-header">
        <Link to="/" className="af-brand shrink-0">
          <span className="af-brand-icon"><Shield size={20} /></span>
          <span><b>AI Firewall</b><small>ENTERPRISE SECURITY</small></span>
        </Link>

        <div className="af-live hidden sm:flex shrink-0"><i /> LIVE <span className="af-header-block">ENCLAVE #{block}</span></div>

        <nav className="hidden xl:flex items-center gap-2">
          <Link className="af-btn" to="/">PLATFORM</Link>
          <Link className="af-btn" to="/login">SIGN IN</Link>
          <Link className="af-btn af-btn-primary" to="/register">GET STARTED <ArrowRight size={13} className="inline ml-1" /></Link>
        </nav>

        <button className="af-menu-btn xl:hidden" onClick={() => setOpen((value) => !value)} aria-label="Open navigation">
          {open ? <X size={18} /> : <Menu size={18} />}
        </button>
      </header>

      <div className="af-status">
        <span className="pulse-dot" /> SECURITY ENCLAVE <b>//</b> BLOCK #{block}
        <span className="hidden sm:inline">ALL DEFENSE SYSTEMS NOMINAL</span>
      </div>

      {open && (
        <div className="fixed z-40 top-[104px] left-3 right-3 rounded-xl border border-slate-800 bg-[#0d131e] p-3 shadow-2xl xl:hidden">
          <Link className="af-nav" to="/" onClick={() => setOpen(false)}>PLATFORM</Link>
          <Link className="af-nav" to="/login" onClick={() => setOpen(false)}>SIGN IN</Link>
          <Link className="af-nav active" to="/register" onClick={() => setOpen(false)}>GET STARTED</Link>
        </div>
      )}

      <main className="pt-[104px] min-h-screen">
        {title && <div className="mx-auto max-w-7xl px-5 pt-8"><div className="af-eyebrow">AI FIREWALL / {title.toUpperCase()}</div></div>}
        {children}
      </main>
    </div>
  )
}

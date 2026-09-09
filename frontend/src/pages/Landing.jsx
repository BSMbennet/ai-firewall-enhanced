import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Shield,
  ArrowRight,
  CheckCircle2,
  Eye,
  Network,
  Terminal,
  ChevronRight,
  Menu,
  X,
} from 'lucide-react'

export default function Landing() {
  const [open, setOpen] = useState(false)
  const [block, setBlock] = useState(48291)

  useEffect(() => {
    const timer = setInterval(() => setBlock((value) => value + 1), 7000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="min-h-screen bg-[#080d14] text-white overflow-hidden">
      <header className="fixed top-0 inset-x-0 z-50 border-b border-white/5 bg-[#080d14]/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto h-[72px] px-5 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <span className="w-10 h-10 rounded-xl grid place-items-center border border-cyan-300/30 bg-cyan-300/10 text-cyan-300">
              <Shield size={21} />
            </span>
            <span>
              <b className="font-[Space_Grotesk] text-lg">AI Firewall</b>
              <small className="block font-mono text-[9px] tracking-[.18em] text-slate-500">
                ENTERPRISE AI SECURITY
              </small>
            </span>
          </Link>

          <nav className="hidden md:flex gap-7 text-sm text-slate-400">
            <a href="#platform">Platform</a>
            <a href="#security">Security</a>
            <a href="#enterprise">Enterprise</a>
            <a href="#developers">Developers</a>
          </nav>

          <div className="hidden md:flex gap-3">
            <Link className="af-btn" to="/login">Sign in</Link>
            <Link className="af-btn af-btn-primary" to="/register">
              Get protected <ArrowRight size={14} className="inline ml-1" />
            </Link>
          </div>

          <button
            className="md:hidden text-slate-300"
            onClick={() => setOpen((value) => !value)}
            aria-label="Toggle navigation"
          >
            {open ? <X /> : <Menu />}
          </button>
        </div>

        {open && (
          <div className="md:hidden px-5 pb-5 space-y-3 border-t border-white/5 bg-[#0d131e]">
            <a className="block text-slate-300 pt-4" href="#platform">Platform</a>
            <a className="block text-slate-300" href="#security">Security</a>
            <a className="block text-slate-300" href="#enterprise">Enterprise</a>
            <a className="block text-slate-300" href="#developers">Developers</a>
            <Link className="block text-cyan-300" to="/login">Sign in →</Link>
          </div>
        )}
      </header>

      <main>
        <section className="relative pt-36 pb-24 px-5">
          <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_15%,rgba(0,242,254,.12),transparent_34%)]" />
          <div className="max-w-7xl mx-auto relative text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/[.06] px-4 py-2 text-[10px] font-mono tracking-wider text-cyan-200">
              <span className="pulse-dot" /> SECURITY ENCLAVE // BLOCK #{block}
            </div>
            <h1 className="max-w-5xl mx-auto mt-8 font-[Space_Grotesk] text-5xl md:text-7xl font-bold tracking-[-.055em] leading-[.98]">
              Secure every AI request.<br />
              <span className="text-cyan-300">Control every outcome.</span>
            </h1>
            <p className="max-w-2xl mx-auto mt-7 text-base md:text-lg leading-7 text-slate-400">
              AI Firewall gives companies and institutions a single security gateway for every AI model, employee, application and request.
            </p>
            <div className="mt-9 flex flex-col sm:flex-row justify-center gap-3">
              <Link to="/register" className="af-btn af-btn-primary text-center py-3 px-6">
                Deploy AI Firewall <ArrowRight size={16} className="inline ml-2" />
              </Link>
              <a href="#platform" className="af-btn text-center py-3 px-6">Explore platform</a>
            </div>

            <div className="mt-16 max-w-5xl mx-auto rounded-2xl border border-cyan-300/15 bg-[#0d131e]/90 shadow-2xl overflow-hidden text-left">
              <div className="h-11 border-b border-white/5 flex items-center px-5 gap-2">
                <span className="w-2 h-2 rounded-full bg-rose-400/70" />
                <span className="w-2 h-2 rounded-full bg-amber-300/70" />
                <span className="w-2 h-2 rounded-full bg-emerald-400/70" />
                <span className="ml-3 text-[10px] font-mono text-slate-500">AI FIREWALL // LIVE COMMAND CENTER</span>
              </div>
              <div className="grid md:grid-cols-4 gap-3 p-4">
                {[
                  ['2.4M', 'AI REQUESTS'],
                  ['47.3K', 'THREATS BLOCKED'],
                  ['23.4', 'AVG RISK SCORE'],
                  ['99.97%', 'UPTIME'],
                ].map(([value, label]) => (
                  <div className="rounded-xl border border-white/[.07] bg-white/[.025] p-4" key={label}>
                    <div className="text-2xl font-bold font-[Space_Grotesk]">{value}</div>
                    <div className="mt-1 text-[9px] font-mono tracking-wider text-slate-500">{label}</div>
                  </div>
                ))}
              </div>
              <div className="mx-4 mb-4 rounded-xl border border-cyan-300/10 bg-cyan-300/[.03] p-4 font-mono text-xs">
                <span className="text-slate-500">08:42:18</span>
                <span className="text-rose-300 ml-4">BLOCK</span>
                <span className="ml-4 text-slate-300">Prompt injection attempt intercepted</span>
                <span className="float-right text-cyan-300">RISK 96.4</span>
              </div>
            </div>
          </div>
        </section>

        <section id="platform" className="py-24 px-5 border-y border-white/5 bg-[#0b1119]">
          <div className="max-w-7xl mx-auto">
            <div className="af-eyebrow">ONE SECURITY LAYER / EVERY AI PROVIDER</div>
            <h2 className="font-[Space_Grotesk] text-4xl md:text-5xl font-bold tracking-tight mt-3 max-w-2xl">
              The enterprise control plane for AI.
            </h2>
            <div className="grid md:grid-cols-3 gap-5 mt-12">
              {[
                [Shield, 'THREAT DEFENSE', 'Detect and block prompt injection, jailbreaks, data leakage and malicious AI activity before it reaches the model.'],
                [Network, 'UNIFIED GATEWAY', 'One secure API endpoint for OpenAI, Anthropic and other AI providers—with centralized policy enforcement.'],
                [Eye, 'FULL VISIBILITY', 'Track every employee, application, request, risk score and security decision from one command center.'],
              ].map(([Icon, title, description]) => (
                <div className="af-card af-card-pad" key={title}>
                  <div className="w-10 h-10 grid place-items-center rounded-xl bg-cyan-300/10 text-cyan-300 border border-cyan-300/15">
                    <Icon size={20} />
                  </div>
                  <h3 className="font-[Space_Grotesk] text-xl font-semibold mt-7">{title}</h3>
                  <p className="text-sm leading-6 text-slate-400 mt-3">{description}</p>
                  <div className="mt-6 text-cyan-300 text-xs font-mono">
                    EXPLORE <ChevronRight size={14} className="inline" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="security" className="py-24 px-5">
          <div className="max-w-7xl mx-auto grid lg:grid-cols-2 gap-14 items-center">
            <div>
              <div className="af-eyebrow">SECURITY PIPELINE</div>
              <h2 className="font-[Space_Grotesk] text-4xl md:text-5xl font-bold tracking-tight mt-3">
                Every request is inspected before it reaches your AI.
              </h2>
              <div className="mt-8 space-y-4">
                {[
                  ['INGEST', 'Capture AI traffic through the secure gateway'],
                  ['ANALYZE', 'Score threats using multiple security engines'],
                  ['FILTER', 'Apply enterprise policies and controls'],
                  ['RESPOND', 'Forward safe requests and record every decision'],
                ].map(([name, description], index) => (
                  <div className="flex gap-4" key={name}>
                    <span className="w-8 h-8 shrink-0 rounded-full border border-cyan-300/20 bg-cyan-300/5 grid place-items-center font-mono text-xs text-cyan-200">
                      {index + 1}
                    </span>
                    <div>
                      <b className="text-sm">{name}</b>
                      <p className="text-sm text-slate-500 mt-1">{description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="af-card af-card-pad">
              <div className="af-label">SECURITY PIPELINE // LIVE</div>
              <div className="mt-8 flex flex-wrap items-center gap-2">
                {['INGEST', 'VALIDATE', 'SCORE', 'FILTER', 'RESPOND'].map((name, index) => (
                  <React.Fragment key={name}>
                    <span className={`rounded-full px-3 py-2 font-mono text-[10px] ${index < 4 ? 'bg-cyan-300/10 text-cyan-200 border border-cyan-300/20' : 'bg-slate-800 text-slate-400'}`}>
                      {name}
                    </span>
                    {index < 4 && <ArrowRight size={13} className="text-slate-600" />}
                  </React.Fragment>
                ))}
              </div>
              <div className="mt-8 rounded-xl bg-black/30 border border-white/5 p-4 font-mono text-xs space-y-3">
                <div><span className="text-slate-500">REQUEST</span><span className="float-right text-emerald-300">ALLOW</span></div>
                <div><span className="text-slate-500">THREAT SCAN</span><span className="float-right text-cyan-300">COMPLETE</span></div>
                <div><span className="text-slate-500">POLICY ENGINE</span><span className="float-right text-emerald-300">ENFORCED</span></div>
              </div>
            </div>
          </div>
        </section>

        <section id="enterprise" className="py-20 px-5 bg-cyan-300/[.035] border-y border-cyan-300/10">
          <div className="max-w-7xl mx-auto text-center">
            <div className="af-eyebrow">BUILT FOR ENTERPRISE AND GOVERNMENT</div>
            <h2 className="font-[Space_Grotesk] text-4xl md:text-5xl font-bold mt-3">Identity, control and compliance built in.</h2>
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-10 text-left">
              {[
                ['SSO & SCIM', 'Entra ID and Google Workspace'],
                ['EMPLOYEE CONTROL', 'Track AI activity by person'],
                ['SIEM & ALERTS', 'Connect your security operations'],
                ['AUDIT & COMPLIANCE', 'Export security evidence'],
              ].map(([title, description]) => (
                <div className="rounded-xl border border-white/[.07] bg-[#0d131e] p-5" key={title}>
                  <CheckCircle2 size={17} className="text-cyan-300" />
                  <b className="block mt-5 text-sm">{title}</b>
                  <p className="mt-2 text-xs text-slate-500">{description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="developers" className="py-24 px-5">
          <div className="max-w-4xl mx-auto text-center">
            <Terminal className="mx-auto text-cyan-300" size={26} />
            <h2 className="font-[Space_Grotesk] text-4xl md:text-5xl font-bold mt-5">Secure your AI stack in minutes.</h2>
            <p className="text-slate-400 mt-4">Create an organization, generate an API key, and route your existing AI requests through AI Firewall.</p>
            <div className="mt-8 flex justify-center gap-3">
              <Link to="/register" className="af-btn af-btn-primary py-3 px-6">
                Create your organization <ArrowRight size={15} className="inline ml-2" />
              </Link>
              <Link to="/login" className="af-btn py-3 px-6">Sign in</Link>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-white/5 px-5 py-8">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row gap-4 justify-between text-xs text-slate-600">
          <span>© {new Date().getFullYear()} AI Firewall. Enterprise AI Security.</span>
          <span className="flex gap-5">
            <span>Privacy</span>
            <span>Security</span>
            <span>System Status</span>
          </span>
        </div>
      </footer>
    </div>
  )
}

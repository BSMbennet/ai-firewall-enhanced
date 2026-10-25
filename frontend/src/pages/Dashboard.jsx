import React, { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, AlertTriangle, CheckCircle2, Clock, Eye, ShieldCheck, Users, Layers3, RefreshCw } from 'lucide-react'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'

const AUDIT_ROLES = ['owner', 'admin', 'security']
const fmt = (n) => (n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K' : String(n || 0))
const flag = (policies, key) => (policies.length ? policies.some((p) => p[key] !== false) : true)

// Everything on this page comes from the API. Failed or empty sources are shown as such - never replaced by sample data.
export default function Dashboard() {
  const { user, role } = useAuth()
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [policies, setPolicies] = useState([])
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(true)
  const canSeeEvents = AUDIT_ROLES.includes(role)

  const load = useCallback(async () => {
    if (!user) return
    setLoading(true)
    const [s, e, p] = await Promise.allSettled([
      api.get('/dashboard/stats'),
      canSeeEvents ? api.get('/dashboard/recent-requests?limit=12') : Promise.resolve(null),
      api.get('/organization/policies'),
    ])
    const next = {}
    if (s.status === 'fulfilled') setStats(s.value.data); else next.stats = 'Statistics could not be loaded.'
    if (e.status === 'fulfilled') setEvents(e.value?.data?.requests || []); else next.events = 'Recent decisions could not be loaded.'
    if (p.status === 'fulfilled') setPolicies(p.value.data?.policies || []); else next.policies = 'Policy status could not be loaded.'
    setErrors(next)
    setLoading(false)
  }, [user, canSeeEvents])
  useEffect(() => { load() }, [load])

  const metrics = stats && [
    ['TOTAL REQUESTS', fmt(stats.total_requests), Activity, 'All gateway requests recorded'],
    ['BLOCKED REQUESTS', fmt(stats.blocked_requests), AlertTriangle, `${Number(stats.threat_rate || 0).toFixed(1)}% of requests`],
    ['AVG LATENCY', `${Math.round(stats.avg_latency_ms || 0)} ms`, Clock, 'Gateway + provider time'],
    ['APPLICATIONS', fmt(stats.applications), Layers3, 'Registered AI applications'],
    ['ACTIVE EMPLOYEES', fmt(stats.employees), Users, 'Non-removed organisation members'],
  ]
  const protections = [
    ['Prompt injection detection', 'prompt_injection_protection', ShieldCheck],
    ['PII detection & redaction', 'pii_protection', Eye],
    ['Response filtering', 'sensitive_content_protection', ShieldCheck],
  ]

  return <div className="af-page">
    <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
      <div><div className="af-eyebrow">COMMAND CENTER</div><h1 className="af-title">Security Command Center</h1>
        <p className="af-subtitle">Gateway activity and policy status for your organisation.</p></div>
      <div className="flex gap-2">
        {canSeeEvents && <Link to="/enterprise-operations" className="af-btn">Logs &amp; analytics</Link>}
        <Link to="/compliance" className="af-btn af-btn-primary">Compliance &amp; audit export</Link>
        <button onClick={load} className="af-btn" aria-label="Refresh"><RefreshCw size={15} className={loading ? 'animate-spin' : ''} /></button>
      </div>
    </div>

    {errors.stats && <p role="alert" className="mt-4 text-sm text-amber-300">{errors.stats}</p>}
    <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5 my-6">
      {(metrics || Array(5).fill(null)).map((m, i) => m
        ? <div className="af-card af-card-pad" key={m[0]}><div className="flex justify-between"><div className="af-label">{m[0]}</div>{React.createElement(m[2], { size: 18, className: 'text-cyan-300' })}</div><div className="af-value">{m[1]}</div><div className="af-muted mt-3">{m[3]}</div></div>
        : <div className="af-card af-card-pad" key={i}><div className="af-label">{loading ? 'LOADING…' : 'UNAVAILABLE'}</div><div className="af-value">—</div></div>)}
    </section>

    <section className="mb-6">
      <div className="af-label mb-3">Active protections (from your organisation's policies)</div>
      {errors.policies && <p role="alert" className="mb-2 text-sm text-amber-300">{errors.policies}</p>}
      <div className="grid gap-4 md:grid-cols-3">{protections.map(([name, key, Icon]) => {
        const unknown = Boolean(errors.policies)
        const on = flag(policies, key)
        return <div className="af-card af-card-pad" key={key}><div className="flex justify-between"><Icon className="text-cyan-300" size={20} /><span className={'text-[10px] font-mono ' + (unknown ? 'text-slate-400' : on ? 'text-emerald-300' : 'text-amber-300')}>● {unknown ? 'UNKNOWN' : on ? 'ENABLED' : 'DISABLED'}</span></div><h3 className="font-semibold text-lg mt-5">{name}</h3>
          <div className="af-muted mt-1">Rule-based; not exhaustive. See known limitations.</div>
          {AUDIT_ROLES.includes(role) && <Link to="/organization" className="af-btn mt-4 w-full inline-block text-center">Manage policy</Link>}</div>
      })}</div>
    </section>

    <section className="af-card overflow-hidden">
      <div className="af-card-pad border-b border-slate-800"><div className="af-label">Recent gateway decisions</div>
        <div className="af-muted mt-1">{canSeeEvents ? (loading ? 'Loading…' : 'Latest requests recorded by the gateway') : 'Request-level activity is visible to owner, admin and security roles.'}</div></div>
      {errors.events && <p role="alert" className="px-5 py-3 text-sm text-amber-300">{errors.events}</p>}
      {canSeeEvents && !errors.events && <div className="overflow-x-auto">
        {events.length === 0 && !loading ? <p className="px-5 py-8 text-sm text-slate-400">No requests have been recorded yet. Send one through the gateway with an API key to see it here.</p>
          : <table className="w-full text-sm min-w-[700px]"><thead className="text-left bg-slate-950/40"><tr>{['TIME', 'DECISION', 'RISK', 'MODEL', 'REASON'].map((x) => <th className="px-5 py-3 af-label" key={x}>{x}</th>)}</tr></thead>
            <tbody>{events.map((e) => <tr className="border-t border-slate-800/70" key={e.id}>
              <td className="px-5 py-4 font-mono text-xs text-slate-400">{e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}</td>
              <td className="px-5 py-4"><span className={e.action === 'BLOCK' ? 'text-rose-300' : e.action === 'REVIEW' ? 'text-amber-300' : 'text-emerald-300'}>{e.action === 'ALLOW' ? <CheckCircle2 size={14} className="inline mr-1" /> : <AlertTriangle size={14} className="inline mr-1" />}{e.action}</span></td>
              <td className="px-5 py-4">{e.risk_score == null ? '—' : Number(e.risk_score).toFixed(1)}</td>
              <td className="px-5 py-4 text-slate-400">{e.model || '—'}</td>
              <td className="px-5 py-4 text-slate-400">{e.reason || '—'}</td></tr>)}</tbody></table>}
      </div>}
    </section>
  </div>
}

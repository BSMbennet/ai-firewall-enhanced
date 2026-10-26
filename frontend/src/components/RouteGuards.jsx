import React from 'react'
import { Navigate } from 'react-router-dom'
import AppShell from './AppShell.jsx'
import { useAuth } from '../contexts/AuthContext'

const SecurityLoading = ({ label = 'Initializing security enclave…' }) => (
  <div className="min-h-screen bg-slate-950 flex items-center justify-center text-cyan-300">{label}</div>
)

const Forbidden = () => (
  <div className="min-h-screen bg-slate-950 flex items-center justify-center px-6 text-center">
    <div>
      <p className="text-cyan-300 text-sm font-semibold tracking-widest">403 // ACCESS DENIED</p>
      <h1 className="mt-3 text-2xl font-bold text-white">Insufficient permissions</h1>
      <p className="mt-2 max-w-md text-sm text-slate-400">Your account is authenticated, but this area requires an organization administrator or security role.</p>
      <a href="/dashboard" className="mt-6 inline-flex rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950">Return to dashboard</a>
    </div>
  </div>
)

export const ProtectedRoute = ({ children, roles }) => {
  const { user, role, loading, profileLoading } = useAuth()
  if (loading) return <SecurityLoading />
  if (!user) return <Navigate to="/login" replace />
  if (roles && profileLoading) return <SecurityLoading label="Loading authorization policy…" />
  if (roles && !roles.includes(role)) return <Forbidden />
  return <AppShell>{children}</AppShell>
}

export const PublicOnly = ({ children }) => {
  const { user, loading } = useAuth()
  if (loading) return <SecurityLoading />
  return user ? <Navigate to="/dashboard" replace /> : children
}


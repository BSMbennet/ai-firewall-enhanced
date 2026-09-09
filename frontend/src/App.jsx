import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Landing from './pages/Landing.jsx'
import Organization from './pages/Organization.jsx'
import EnterpriseSecurity from './pages/EnterpriseSecurity.jsx'
import EnterpriseOperations from './pages/EnterpriseOperations.jsx'
import Compliance from './pages/Compliance.jsx'
import Login from './pages/Login.jsx'
import Register from './pages/Register.jsx'
import Settings from './pages/Settings.jsx'
import AppShell from './components/AppShell.jsx'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { Toaster } from 'react-hot-toast'

const ADMIN_ROLES = ['owner', 'admin', 'security']
const OWNER_ADMIN_ROLES = ['owner', 'admin']

const SecurityLoading = ({ label = 'Initializing security enclave…' }) => (
  <div className="min-h-screen bg-slate-950 flex items-center justify-center text-cyan-300">
    {label}
  </div>
)

const Forbidden = () => (
  <div className="min-h-screen bg-slate-950 flex items-center justify-center px-6 text-center">
    <div>
      <p className="text-cyan-300 text-sm font-semibold tracking-widest">403 // ACCESS DENIED</p>
      <h1 className="mt-3 text-2xl font-bold text-white">Insufficient permissions</h1>
      <p className="mt-2 max-w-md text-sm text-slate-400">
        Your account is authenticated, but this area requires an organization administrator or security role.
      </p>
      <a href="/dashboard" className="mt-6 inline-flex rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950">
        Return to dashboard
      </a>
    </div>
  </div>
)

const ProtectedRoute = ({ children, roles }) => {
  const { user, role, loading, profileLoading } = useAuth()
  if (loading) return <SecurityLoading />
  if (!user) return <Navigate to="/login" replace />
  if (roles && profileLoading) return <SecurityLoading label="Loading authorization policy…" />
  if (roles && !roles.includes(role)) return <Forbidden />
  return <AppShell>{children}</AppShell>
}

const PublicOnly = ({ children }) => {
  const { user, loading } = useAuth()
  if (loading) return null
  return user ? <Navigate to="/dashboard" replace /> : children
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/organization" element={<ProtectedRoute roles={ADMIN_ROLES}><Organization /></ProtectedRoute>} />
          <Route path="/enterprise-security" element={<ProtectedRoute roles={OWNER_ADMIN_ROLES}><EnterpriseSecurity /></ProtectedRoute>} />
          <Route path="/enterprise-operations" element={<ProtectedRoute roles={ADMIN_ROLES}><EnterpriseOperations /></ProtectedRoute>} />
          <Route path="/compliance" element={<ProtectedRoute><Compliance /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
          <Route path="/login" element={<PublicOnly><Login /></PublicOnly>} />
          <Route path="/register" element={<PublicOnly><Register /></PublicOnly>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
        <Toaster position="top-right" />
      </BrowserRouter>
    </AuthProvider>
  )
}

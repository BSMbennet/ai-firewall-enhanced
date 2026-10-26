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
import ForgotPassword from './pages/ForgotPassword.jsx'
import ResetPassword from './pages/ResetPassword.jsx'
import Settings from './pages/Settings.jsx'
import { AuthProvider } from './contexts/AuthContext'
import { ProtectedRoute, PublicOnly } from './components/RouteGuards.jsx'
import { Toaster } from 'react-hot-toast'

const ADMIN_ROLES = ['owner', 'admin', 'security']
const OWNER_ADMIN_ROLES = ['owner', 'admin']


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
          <Route path="/forgot-password" element={<PublicOnly><ForgotPassword /></PublicOnly>} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
        <Toaster position="top-right" />
      </BrowserRouter>
    </AuthProvider>
  )
}

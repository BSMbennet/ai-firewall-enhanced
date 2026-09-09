import React from 'react'
import {BrowserRouter,Routes,Route,Navigate} from 'react-router-dom'
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
import {AuthProvider,useAuth} from './contexts/AuthContext'
import {Toaster} from 'react-hot-toast'
const ProtectedRoute=({children})=>{const{user,loading}=useAuth();if(loading)return <div className="min-h-screen bg-slate-950 flex items-center justify-center text-cyan-300">Initializing security enclave…</div>;return user?<AppShell>{children}</AppShell>:<Navigate to="/login" replace/>}
const PublicOnly=({children})=>{const{user,loading}=useAuth();if(loading)return null;return user?<Navigate to="/dashboard" replace/>:children}
export default function App(){return <AuthProvider><BrowserRouter><Routes>
<Route path="/" element={<Landing/>}/><Route path="/dashboard" element={<ProtectedRoute><Dashboard/></ProtectedRoute>}/><Route path="/organization" element={<ProtectedRoute><Organization/></ProtectedRoute>}/><Route path="/enterprise-security" element={<ProtectedRoute><EnterpriseSecurity/></ProtectedRoute>}/><Route path="/enterprise-operations" element={<ProtectedRoute><EnterpriseOperations/></ProtectedRoute>}/><Route path="/compliance" element={<ProtectedRoute><Compliance/></ProtectedRoute>}/><Route path="/settings" element={<ProtectedRoute><Settings/></ProtectedRoute>}/><Route path="/login" element={<PublicOnly><Login/></PublicOnly>}/><Route path="/register" element={<PublicOnly><Register/></PublicOnly>}/><Route path="*" element={<Navigate to="/" replace/>}/>
</Routes><Toaster position="top-right"/></BrowserRouter></AuthProvider>}
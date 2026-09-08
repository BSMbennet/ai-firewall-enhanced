import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Mail, Lock, Building2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../contexts/AuthContext'

const Register = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [company, setCompany] = useState('')
  const [loading, setLoading] = useState(false)
  const { signUp } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (event) => {
    event.preventDefault()
    setLoading(true)
    try {
      const { session } = await signUp(email, password, {
        company: company || undefined,
      })

      if (session) {
        toast.success('Account created successfully!')
        navigate('/')
      } else {
        toast.success('Account created. Check your email to confirm your address.')
        navigate('/login')
      }
    } catch (error) {
      toast.error(error.message || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8">
        <div className="text-center mb-8">
          <Shield className="w-10 h-10 mx-auto text-blue-600" />
          <h1 className="mt-4 text-2xl font-bold">Create your account</h1>
        </div>
        <form onSubmit={handleSubmit} className="space-y-5">
          <label className="block text-sm font-medium">Email
            <div className="relative mt-1"><Mail className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
              <input className="w-full pl-10 p-2 border rounded-lg" type="email" value={email} onChange={e => setEmail(e.target.value)} required />
            </div>
          </label>
          <label className="block text-sm font-medium">Password
            <div className="relative mt-1"><Lock className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
              <input className="w-full pl-10 p-2 border rounded-lg" type="password" minLength="8" value={password} onChange={e => setPassword(e.target.value)} required />
            </div>
          </label>
          <label className="block text-sm font-medium">Company (optional)
            <div className="relative mt-1"><Building2 className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
              <input className="w-full pl-10 p-2 border rounded-lg" value={company} onChange={e => setCompany(e.target.value)} />
            </div>
          </label>
          <button disabled={loading} className="w-full bg-blue-600 text-white py-2.5 rounded-lg disabled:opacity-50">
            {loading ? 'Creating account...' : 'Create account'}
          </button>
          <p className="text-center text-sm text-gray-500">Already have an account? <button type="button" onClick={() => navigate('/login')} className="text-blue-600 font-medium">Sign in</button></p>
        </form>
      </div>
    </div>
  )
}
export default Register

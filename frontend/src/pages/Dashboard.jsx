import React, { useState, useEffect, useCallback } from 'react'
import {
  LineChart,
  Line,
  PieChart,
  Pie,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  Cell,
  ResponsiveContainer,
} from 'recharts'
import {
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Shield,
  Zap,
  DollarSign,
  Activity,
  Users,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { supabase } from '../lib/supabase'
import api from '../services/api'
import toast from 'react-hot-toast'

const EMPTY_STATS = {
  total_requests: 0,
  blocked_requests: 0,
  avg_latency_ms: 0,
  total_cost: 0,
  threat_rate: 0,
}

const Dashboard = () => {
  const { user } = useAuth()
  const [stats, setStats] = useState(null)
  const [recentActivity, setRecentActivity] = useState([])
  const [threatData, setThreatData] = useState([])
  const [loading, setLoading] = useState(false)
  const [timeRange, setTimeRange] = useState('24h')

  const fetchDashboardData = useCallback(async () => {
    if (!user) return

    setLoading(true)

    try {
      // Fetch each dashboard section independently. One failed endpoint
      // (for example, an empty/missing security_events table) must not
      // prevent the stats and recent activity from loading.
      const results = await Promise.allSettled([
        api.get('/dashboard/stats'),
        api.get('/dashboard/recent-requests?limit=20'),
        api.get('/dashboard/threat-timeline'),
      ])

      const [statsResult, activityResult, timelineResult] = results
      const failures = []

      if (statsResult.status === 'fulfilled') {
        setStats({ ...EMPTY_STATS, ...statsResult.value.data })
      } else {
        failures.push({ section: 'stats', error: statsResult.reason })
      }

      if (activityResult.status === 'fulfilled') {
        setRecentActivity(activityResult.value.data?.requests || [])
      } else {
        failures.push({ section: 'recent activity', error: activityResult.reason })
      }

      if (timelineResult.status === 'fulfilled') {
        setThreatData(timelineResult.value.data?.timeline || [])
      } else {
        failures.push({ section: 'threat timeline', error: timelineResult.reason })
      }

      if (failures.length > 0) {
        console.error('Dashboard endpoint failures:', failures)
        const firstError = failures[0].error
        const detail = firstError?.response?.data?.detail
        toast.error(detail || `Some dashboard data could not be loaded (${failures.length} section${failures.length === 1 ? '' : 's'})`)
      }
    } catch (error) {
      console.error('Unexpected dashboard error:', error)
      toast.error(error.response?.data?.detail || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [user])

  useEffect(() => {
    if (!user) return

    fetchDashboardData()

    const subscription = supabase
      .channel('dashboard-updates')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'audit_logs' },
        () => fetchDashboardData()
      )
      .subscribe()

    return () => {
      subscription.unsubscribe()
    }
  }, [user, timeRange, fetchDashboardData])

  const displayStats = stats || EMPTY_STATS

  const StatCard = ({ title, value, icon: Icon, color, subtitle }) => (
    <div className="bg-white rounded-xl shadow-sm p-6 transition-all hover:shadow-md">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-sm text-gray-500 font-medium">{title}</p>
          <p className="text-2xl font-bold mt-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-400 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  )

  const getStatusColor = (action) => {
    if (action === 'BLOCK') return 'text-red-600 bg-red-50'
    if (action === 'REVIEW') return 'text-yellow-600 bg-yellow-50'
    return 'text-green-600 bg-green-50'
  }

  const getRiskColor = (score) => {
    if (score > 70) return 'bg-red-500'
    if (score > 40) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  const COLORS = ['#3B82F6', '#EF4444', '#10B981', '#8B5CF6', '#F59E0B']

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-blue-600" />
            <div>
              <h1 className="text-xl font-bold">AI Firewall</h1>
              <p className="text-xs text-gray-500">Security Dashboard</p>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              {['1h', '24h', '7d'].map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1 text-sm rounded ${
                    timeRange === range
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-gray-500 hover:bg-gray-100'
                  }`}
                >
                  {range.toUpperCase()}
                </button>
              ))}
            </div>

            <button
              onClick={fetchDashboardData}
              disabled={loading}
              className="p-2 hover:bg-gray-100 rounded-full transition"
              aria-label="Refresh dashboard"
            >
              <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
            </button>

            <div className="flex items-center space-x-2">
              <Users className="w-5 h-5 text-gray-500" />
              <span className="text-sm text-gray-700">{user?.email || 'User'}</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Requests"
            value={displayStats.total_requests || 0}
            icon={Activity}
            color="bg-blue-50 text-blue-600"
            subtitle="All time"
          />
          <StatCard
            title="Blocked Requests"
            value={displayStats.blocked_requests || 0}
            icon={AlertTriangle}
            color="bg-red-50 text-red-600"
            subtitle={`${Number(displayStats.threat_rate || 0).toFixed(1)}% threat rate`}
          />
          <StatCard
            title="Avg Latency"
            value={`${Math.round(displayStats.avg_latency_ms || 0)}ms`}
            icon={Zap}
            color="bg-green-50 text-green-600"
            subtitle="Response time"
          />
          <StatCard
            title="Total Cost"
            value={`$${Number(displayStats.total_cost || 0).toFixed(2)}`}
            icon={DollarSign}
            color="bg-purple-50 text-purple-600"
            subtitle="LLM usage cost"
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <div className="bg-white rounded-xl shadow-sm p-6">
            <h3 className="text-lg font-semibold mb-4">Request Trend</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart
                  data={recentActivity.map((log) => ({
                    date: new Date(log.timestamp).toLocaleTimeString(),
                    requests: 1,
                    blocked: log.action === 'BLOCK' ? 1 : 0,
                  }))}
                >
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="requests" stroke="#3B82F6" />
                  <Line type="monotone" dataKey="blocked" stroke="#EF4444" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm p-6">
            <h3 className="text-lg font-semibold mb-4">Threat Distribution</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Injection', value: 45 },
                      { name: 'Data Leak', value: 25 },
                      { name: 'Harmful', value: 20 },
                      { name: 'Other', value: 10 },
                    ]}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    dataKey="value"
                  >
                    {[0, 1, 2, 3].map((index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold">Recent Activity</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50">
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Time</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Action</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Risk Score</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Model</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {recentActivity.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="px-6 py-8 text-center text-gray-500">
                      No recent activity
                    </td>
                  </tr>
                ) : (
                  recentActivity.map((log) => (
                    <tr key={log.id} className="hover:bg-gray-50 transition">
                      <td className="px-6 py-4 text-sm text-gray-500 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span className={`inline-flex px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(log.action)}`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center space-x-2">
                          <div className={`w-2 h-2 rounded-full ${getRiskColor(log.risk_score)}`} />
                          <span className="text-sm">{log.risk_score?.toFixed(1) || 'N/A'}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {log.model || 'gpt-4'}
                      </td>
                      <td className="px-6 py-4">
                        {log.action === 'ALLOW' ? (
                          <CheckCircle className="w-5 h-5 text-green-500" />
                        ) : (
                          <AlertTriangle className="w-5 h-5 text-red-500" />
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  )
}

export default Dashboard

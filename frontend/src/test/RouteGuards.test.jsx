import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

let auth
vi.mock('../contexts/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../components/AppShell.jsx', () => ({ default: ({ children }) => <div data-testid="shell">{children}</div> }))

import { ProtectedRoute, PublicOnly } from '../components/RouteGuards.jsx'

const ADMIN = ['owner', 'admin', 'security']
const OWNER_ADMIN = ['owner', 'admin']

const renderAt = (path) => render(
  <MemoryRouter initialEntries={[path]}>
    <Routes>
      <Route path="/login" element={<PublicOnly><div>login-page</div></PublicOnly>} />
      <Route path="/dashboard" element={<ProtectedRoute><div>dashboard-page</div></ProtectedRoute>} />
      <Route path="/organization" element={<ProtectedRoute roles={ADMIN}><div>org-page</div></ProtectedRoute>} />
      <Route path="/enterprise-security" element={<ProtectedRoute roles={OWNER_ADMIN}><div>ent-page</div></ProtectedRoute>} />
    </Routes>
  </MemoryRouter>)

beforeEach(() => { cleanup(); auth = { user: { id: 'u1' }, role: 'member', loading: false, profileLoading: false } })

describe('route guards', () => {
  it('redirects anonymous users to /login', () => {
    auth = { user: null, role: null, loading: false, profileLoading: false }
    renderAt('/dashboard')
    expect(screen.getByText('login-page')).toBeTruthy()
  })
  it('shows loading while the session resolves, never the page', () => {
    auth = { user: null, role: null, loading: true, profileLoading: false }
    renderAt('/organization')
    expect(screen.queryByText('org-page')).toBeNull()
    expect(screen.queryByText('login-page')).toBeNull()
  })
  it('does not render a role-gated page while the profile (role) is still loading', () => {
    auth = { user: { id: 'u1' }, role: null, loading: false, profileLoading: true }
    renderAt('/organization')
    expect(screen.queryByText('org-page')).toBeNull()
    expect(screen.queryByText(/ACCESS DENIED/)).toBeNull()
  })
  it('lets any signed-in user see ungated pages', () => {
    renderAt('/dashboard')
    expect(screen.getByText('dashboard-page')).toBeTruthy()
  })
  it.each([['member', false], ['viewer', false], [null, false], ['security', true], ['admin', true], ['owner', true]])(
    'admin pages for role %s -> allowed=%s', (role, allowed) => {
      auth = { user: { id: 'u1' }, role, loading: false, profileLoading: false }
      renderAt('/organization')
      expect(!!screen.queryByText('org-page')).toBe(allowed)
      expect(!!screen.queryByText(/ACCESS DENIED/)).toBe(!allowed)
    })
  it.each([['security', false], ['admin', true], ['owner', true], ['member', false]])(
    'owner/admin-only pages for role %s -> allowed=%s', (role, allowed) => {
      auth = { user: { id: 'u1' }, role, loading: false, profileLoading: false }
      renderAt('/enterprise-security')
      expect(!!screen.queryByText('ent-page')).toBe(allowed)
    })
  it('sends signed-in users away from /login', () => {
    renderAt('/login')
    expect(screen.getByText('dashboard-page')).toBeTruthy()
  })
})

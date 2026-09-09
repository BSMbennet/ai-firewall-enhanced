const DEFAULT_TIMEOUT_MS = 30 * 60 * 1000
const WARNING_BEFORE_MS = 5 * 60 * 1000
const ADMIN_TIMEOUT_MS = 15 * 60 * 1000

const ADMIN_ROLES = new Set(['owner', 'admin', 'security'])

export const getSessionTimeoutMs = (role) =>
  ADMIN_ROLES.has(role) ? ADMIN_TIMEOUT_MS : DEFAULT_TIMEOUT_MS

export const clearSessionStorage = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('access_token')
  localStorage.removeItem('user')
}

export const logoutAndRedirect = async (signOut) => {
  try {
    if (signOut) await signOut()
  } finally {
    clearSessionStorage()
    window.location.replace('/login')
  }
}

export const startSessionTracking = ({ role, onWarning, onActivity, onTimeout }) => {
  const timeoutMs = getSessionTimeoutMs(role)
  const warningMs = Math.max(timeoutMs - WARNING_BEFORE_MS, 60 * 1000)
  let logoutTimer
  let warningTimer
  let lastActivity = 0

  const clearTimers = () => {
    window.clearTimeout(logoutTimer)
    window.clearTimeout(warningTimer)
  }

  const reset = () => {
    const now = Date.now()
    // Avoid resetting several timers for a burst of mousemove events.
    if (now - lastActivity < 1000) return
    lastActivity = now

    clearTimers()
    onActivity?.()

    warningTimer = window.setTimeout(() => {
      onWarning?.(Math.round((timeoutMs - warningMs) / 60000))
    }, warningMs)

    logoutTimer = window.setTimeout(() => {
      onTimeout?.()
    }, timeoutMs)
  }

  const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click']
  events.forEach((event) => window.addEventListener(event, reset, { passive: true }))
  window.addEventListener('mousemove', reset, { passive: true })

  reset()

  return () => {
    events.forEach((event) => window.removeEventListener(event, reset))
    window.removeEventListener('mousemove', reset)
    clearTimers()
  }
}

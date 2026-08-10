import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react'
import { createElement } from 'react'
import axios from 'axios'
import api from '../api'
import type { User } from '../types'

interface AuthContextValue {
  user: User | null
  isAuthenticated: boolean
  loading: boolean  // true while we verify the token on mount
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

// Context is exported so Layout and other components can consume it
export const AuthContext = createContext<AuthContextValue | null>(null)

// Decode a JWT payload without verifying the signature.
// We trust the backend to issue valid tokens; this is purely for reading
// display fields (username, role) on the client side.
function decodePayload(token: string): User | null {
  try {
    const base64 = token.split('.')[1]
    const json = atob(base64.replace(/-/g, '+').replace(/_/g, '/'))
    const payload = JSON.parse(json)
    return { username: payload.sub, role: payload.role ?? 'viewer' }
  } catch {
    return null
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  // Start with the locally-decoded user so we have something to show while
  // the server-side verification request is in flight.
  const [user, setUser] = useState<User | null>(() => {
    const token = localStorage.getItem('token')
    return token ? decodePayload(token) : null
  })

  // loading stays true only if there's a stored token to verify — otherwise
  // start false so no effect has to synchronously call setLoading(false).
  // Components that render protected UI must wait for loading=false before
  // trusting isAuthenticated — this prevents the nav flash on stale tokens.
  const [loading, setLoading] = useState(() => localStorage.getItem('token') !== null)

  const isAuthenticated = user !== null

  const login = useCallback(async (username: string, password: string) => {
    const res = await axios.post('/api/auth/login', { username, password })
    const token: string = res.data.access_token
    localStorage.setItem('token', token)
    setUser(decodePayload(token))
  }, [])

  const logout = useCallback(async () => {
    // Best-effort: call the server so it can clear the httpOnly refresh
    // cookie. We always proceed to clear local state even if the request
    // fails (network error, expired token, server unreachable).
    try {
      await api.post('/auth/logout')
    } catch {
      // Ignore — local logout still proceeds.
    }
    localStorage.removeItem('token')
    setUser(null)
    window.location.href = '/login'
  }, [])

  // On mount, verify the stored token against the server.
  // loading was initialized to true only when a token was present, so no-token
  // start-up is already in its final state and this effect returns early.
  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return

    api.get<User>('/auth/me')
      .then((res) => {
        setUser(res.data)
      })
      .catch(() => {
        // Token is invalid or expired — treat as logged out
        localStorage.removeItem('token')
        setUser(null)
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  // Keep user state in sync if the token is cleared externally (e.g. by the
  // api.ts interceptor on a failed refresh)
  useEffect(() => {
    const handleStorage = (e: StorageEvent) => {
      if (e.key === 'token' && e.newValue === null) {
        setUser(null)
      }
    }
    window.addEventListener('storage', handleStorage)
    return () => window.removeEventListener('storage', handleStorage)
  }, [])

  return createElement(AuthContext.Provider, { value: { user, isAuthenticated, loading, login, logout } }, children)
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}

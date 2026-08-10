import { useState, type FormEvent } from 'react'
import { useNavigate, Navigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

export default function LoginPage() {
  const { login, isAuthenticated, loading: authLoading } = useAuth()
  const navigate = useNavigate()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  // Wait for token verification before deciding to redirect — avoids a race
  // where a stale token briefly passes isAuthenticated before /auth/me clears it.
  if (authLoading) return null

  // Already authenticated — bounce to dashboard using Navigate (not navigate()
  // in the render body, which causes a React setState-during-render warning).
  if (isAuthenticated) {
    return <Navigate to="/" replace />
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      await login(username, password)
      navigate('/', { replace: true })
    } catch {
      setError('Invalid username or password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ backgroundColor: 'var(--color-surface-0)' }}
    >
      {/* Subtle radial backdrop — atmospheric white wash */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse at 50% 30%, rgba(250,250,250,0.04) 0%, transparent 60%)',
        }}
      />

      <div
        className="relative w-full max-w-[400px] animate-fade-in"
        style={{
          background: 'var(--color-surface-1)',
          border: '1px solid var(--color-border-bright)',
          borderRadius: 12,
          padding: 32,
          boxShadow: '0 8px 40px rgba(0,0,0,0.5), 0 0 0 1px var(--color-border)',
        }}
      >
        {/* Northglass ensō — large brand mark */}
        <div className="flex flex-col items-center mb-8">
          <svg
            width="120"
            height="120"
            viewBox="0 0 200 200"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            style={{ marginBottom: 20 }}
            aria-label="Northglass Labs"
          >
            <circle
              cx="100"
              cy="100"
              r="78"
              fill="none"
              stroke="var(--color-text-primary)"
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray="440 32"
              transform="rotate(-30 100 100)"
            />
            <circle
              cx="100"
              cy="100"
              r="78"
              fill="none"
              stroke="var(--color-text-primary)"
              strokeWidth="6"
              strokeLinecap="round"
              strokeDasharray="22 460"
              transform="rotate(60 100 100)"
              opacity="0.6"
            />
          </svg>

          {/* SLINK wordmark */}
          <h1
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 32,
              fontWeight: 700,
              letterSpacing: '0.18em',
              color: 'var(--color-text-primary)',
              marginBottom: 6,
            }}
          >
            SLINK
          </h1>

          {/* Subtitle */}
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 10,
              fontWeight: 500,
              letterSpacing: '0.22em',
              color: 'var(--color-text-tertiary)',
              textTransform: 'uppercase',
              marginBottom: 8,
            }}
          >
            Threat Intelligence Monitor
          </p>

          {/* Parent-brand lockup */}
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 9,
              fontWeight: 500,
              letterSpacing: '0.28em',
              color: 'var(--color-text-tertiary)',
              opacity: 0.7,
              textTransform: 'uppercase',
            }}
          >
            by Northglass Labs
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="username"
              className="block text-[13px] font-medium mb-1.5"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                width: '100%',
                padding: '9px 12px',
                borderRadius: 8,
                fontSize: 13,
                fontFamily: 'var(--font-sans)',
                background: 'var(--color-surface-0)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-primary)',
                outline: 'none',
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = 'var(--color-accent)'
                e.currentTarget.style.boxShadow = '0 0 0 3px var(--color-accent-muted)'
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = 'var(--color-border)'
                e.currentTarget.style.boxShadow = 'none'
              }}
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-[13px] font-medium mb-1.5"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                width: '100%',
                padding: '9px 12px',
                borderRadius: 8,
                fontSize: 13,
                fontFamily: 'var(--font-sans)',
                background: 'var(--color-surface-0)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-primary)',
                outline: 'none',
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = 'var(--color-accent)'
                e.currentTarget.style.boxShadow = '0 0 0 3px var(--color-accent-muted)'
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = 'var(--color-border)'
                e.currentTarget.style.boxShadow = 'none'
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '10px 16px',
              fontSize: 14,
              fontWeight: 600,
              fontFamily: 'var(--font-sans)',
              background: loading ? 'var(--color-surface-4)' : 'var(--color-accent)',
              color: loading ? 'var(--color-text-secondary)' : 'var(--color-text-inverse)',
              border: 'none',
              borderRadius: 8,
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: loading ? 'none' : '0 2px 8px var(--color-accent-glow)',
              transition: 'all 0.15s ease',
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>

        {error && (
          <p
            className="text-[13px] text-center mt-4 animate-fade-in"
            style={{ color: 'var(--color-danger)' }}
          >
            {error}
          </p>
        )}
      </div>
    </div>
  )
}

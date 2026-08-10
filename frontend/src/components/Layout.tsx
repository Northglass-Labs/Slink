import { NavLink, Navigate, Outlet } from 'react-router-dom'
import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { ErrorBoundary } from './ErrorBoundary'
import { useActiveIncidents } from '../queries/useIncidents'

interface NavItem {
  to: string
  label: string
  adminOnly?: boolean
  badge?: boolean
}

export default function Layout() {
  const { isAuthenticated, loading, user, logout } = useAuth()
  // mobileOpen is closed explicitly by link onClick handlers rather than by a
  // useEffect(locationPathname) — avoids cascading renders from setState in effect.
  const [mobileOpen, setMobileOpen] = useState(false)
  const closeMenu = () => setMobileOpen(false)

  // Admin-only: live badge indicating active incidents. React Query dedups
  // this with IncidentsSection's fetch so there's no double call.
  const { data: activeIncidents } = useActiveIncidents()
  const activeIncidentCount =
    isAuthenticated && user?.role === 'admin' ? activeIncidents?.length ?? 0 : 0

  if (loading) return null
  if (!isAuthenticated) return <Navigate to="/login" replace />

  const navItems: NavItem[] = [
    { to: '/dashboard', label: 'Dashboard' },
    { to: '/detections', label: 'Detections' },
    { to: '/watchlist', label: 'Watchlist' },
    { to: '/sources', label: 'Sources' },
    { to: '/settings', label: 'Settings', badge: true },
    { to: '/admin/users', label: 'Users', adminOnly: true },
  ]
  const visibleItems = navItems.filter((n) => !n.adminOnly || user?.role === 'admin')

  const linkStyle = ({ isActive }: { isActive: boolean }) => ({
    backgroundColor: isActive ? 'var(--color-surface-3)' : 'transparent',
    color: isActive ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
  })

  return (
    <div
      className="min-h-screen flex flex-col"
      style={{ backgroundColor: 'var(--color-surface-0)', color: 'var(--color-text-primary)' }}
    >
      <nav
        className="flex-none min-h-[52px] flex items-center justify-between px-3 sm:px-5 border-b gap-2 py-1 relative"
        style={{
          backgroundColor: 'var(--color-surface-1)',
          borderColor: 'var(--color-border)',
        }}
      >
        {/* Logo — Slink watchful-eye mark + SLINK wordmark */}
        <div className="flex items-center flex-shrink-0" style={{ gap: 10 }}>
          <svg
            width="26"
            height="26"
            viewBox="0 0 1024 1024"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            aria-label="Slink"
          >
            {/* Watchful eye catching a break-in — Slink's own mark, not the Northglass ensō */}
            <g transform="translate(0.000000,1024.000000) scale(0.100000,-0.100000)" fill="var(--color-text-primary)" stroke="none"><path d="M4830 8179 c-1133 -112 -2116 -838 -2549 -1883 -23 -54 -41 -101 -41 -104 0 -2 21 15 48 39 200 187 582 462 902 652 81 48 178 115 220 153 467 414 1076 644 1710 644 197 0 467 -33 625 -75 16 -5 62 36 220 194 124 125 196 204 190 210 -23 20 -297 98 -445 126 -247 46 -653 67 -880 44z"/><path d="M6162 7647 l-464 -464 -75 18 c-184 44 -466 65 -653 50 -407 -34 -850 -168 -1325 -401 -650 -319 -1239 -776 -1806 -1400 -118 -131 -269 -316 -269 -330 0 -14 42 -67 184 -230 332 -383 661 -692 1044 -983 l153 -116 147 147 c81 82 223 225 315 319 l168 170 -30 76 c-171 431 -153 921 50 1347 225 472 665 816 1174 919 147 30 316 44 425 36 189 -14 405 -60 550 -119 l59 -24 348 349 c190 192 351 349 357 349 6 0 192 -181 413 -402 l403 -403 -347 -347 -346 -346 36 -84 c187 -436 173 -961 -38 -1403 -155 -324 -451 -616 -785 -774 -434 -205 -911 -221 -1356 -44 l-112 44 -183 -186 c-101 -103 -185 -188 -187 -189 -1 -2 86 -33 195 -69 669 -221 1098 -229 1741 -31 923 285 1859 948 2613 1850 l120 145 -97 117 c-279 334 -630 685 -938 938 l-38 32 228 232 c126 127 230 235 231 238 4 9 -1420 1432 -1433 1432 -5 0 -218 -209 -472 -463z m-3012 -1681 c-223 -545 -224 -1138 -5 -1680 25 -61 43 -111 42 -112 -10 -10 -357 263 -522 411 -120 107 -435 422 -492 492 l-35 43 38 48 c71 86 427 436 564 554 128 109 441 351 447 344 1 -1 -15 -46 -37 -100z m4242 -153 c222 -183 556 -507 683 -661 27 -32 27 -32 -1 -69 -57 -75 -454 -462 -595 -581 -141 -119 -421 -334 -426 -328 -2 2 17 54 42 117 166 413 207 842 120 1259 -13 63 -30 135 -38 160 -14 45 -14 45 52 113 36 37 67 67 68 67 1 0 44 -35 95 -77z"/><path d="M6173 6518 c-343 -343 -343 -343 -370 -325 -314 200 -738 251 -1093 130 -382 -130 -693 -454 -805 -838 -103 -353 -59 -698 131 -1028 l28 -48 -638 -638 c-556 -556 -637 -641 -628 -657 19 -35 306 -309 407 -390 1247 -988 3002 -878 4110 257 235 241 381 441 531 724 45 86 154 327 154 342 0 2 -38 -30 -85 -71 -251 -224 -569 -452 -865 -621 -76 -44 -168 -106 -210 -143 -383 -335 -846 -548 -1370 -629 -162 -25 -537 -25 -705 1 -340 51 -680 172 -965 342 -121 72 -340 228 -340 242 0 4 204 214 453 466 l452 459 88 -52 c378 -228 825 -252 1212 -66 364 175 614 495 701 895 26 119 26 381 0 500 -34 158 -103 325 -184 447 l-36 54 340 340 339 339 -155 155 -155 155 -342 -342z m-873 -662 c30 -8 68 -20 84 -26 30 -11 30 -11 -20 -40 -106 -60 -158 -150 -159 -275 0 -98 31 -170 101 -235 67 -62 124 -84 214 -84 120 1 223 62 274 163 27 53 34 47 60 -55 65 -252 -9 -526 -194 -715 -362 -370 -986 -269 -1219 198 -103 206 -102 463 2 669 114 226 322 377 572 418 54 8 229 -2 285 -18z"/></g>
          </svg>
          <span
            style={{
              fontFamily: "var(--font-heading)",
              fontSize: 15,
              fontWeight: 600,
              letterSpacing: '0.14em',
              color: 'var(--color-text-primary)',
            }}
          >
            SLINK
          </span>
          <span
            className="hidden md:inline"
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: 10,
              fontWeight: 500,
              letterSpacing: '0.18em',
              textTransform: 'uppercase',
              color: 'var(--color-text-tertiary)',
              marginLeft: 4,
              borderLeft: '1px solid var(--color-border)',
              paddingLeft: 10,
            }}
          >
            by Northglass Labs
          </span>
        </div>

        {/* Desktop nav links — hidden below sm, visible sm and up */}
        <div className="hidden sm:flex items-center gap-1 overflow-x-auto min-w-0 flex-1 ml-3">
          {visibleItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className="px-3 py-1.5 rounded text-[13px] font-medium transition-colors"
              style={(s) => ({
                ...linkStyle(s),
                position: 'relative' as const,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              })}
            >
              {item.label}
              {item.badge && activeIncidentCount > 0 && (
                <span
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: '50%',
                    background: '#f59e0b',
                    display: 'inline-block',
                    boxShadow: '0 0 4px rgba(245,158,11,0.6)',
                  }}
                  title={`${activeIncidentCount} active incident${activeIncidentCount > 1 ? 's' : ''}`}
                />
              )}
            </NavLink>
          ))}
        </div>

        {/* Right side — user info + logout (desktop). Hidden on mobile because
            the same controls live inside the hamburger menu. */}
        <div className="hidden sm:flex items-center gap-1 flex-shrink-0">
          <div
            className="flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs"
            style={{ color: 'var(--color-text-secondary)' }}
          >
            <span className="font-medium" style={{ color: 'var(--color-accent)' }}>
              {user?.username}
            </span>
            <span
              className="text-[10px] px-1.5 py-0.5 rounded uppercase tracking-wider"
              style={{
                backgroundColor: 'var(--color-accent-muted)',
                color: 'var(--color-accent)',
              }}
            >
              {user?.role}
            </span>
          </div>
          <button
            onClick={logout}
            className="px-2.5 py-1.5 rounded text-[13px] font-medium transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseOver={(e) => { e.currentTarget.style.color = 'var(--color-danger)' }}
            onMouseOut={(e) => { e.currentTarget.style.color = 'var(--color-text-secondary)' }}
          >
            Logout
          </button>
        </div>

        {/* Hamburger — mobile only */}
        <button
          aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={mobileOpen}
          onClick={() => setMobileOpen((v) => !v)}
          className="sm:hidden flex items-center justify-center"
          style={{
            width: 36,
            height: 36,
            borderRadius: 6,
            border: '1px solid var(--color-border)',
            background: 'transparent',
            color: 'var(--color-text-secondary)',
            cursor: 'pointer',
          }}
        >
          {mobileOpen ? (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M3 3 L13 13 M13 3 L3 13" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
          ) : (
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <path d="M2 5 L16 5 M2 9 L16 9 M2 13 L16 13" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
          )}
        </button>

        {/* Mobile dropdown — absolute so it overlays page content */}
        {mobileOpen && (
          <div
            className="sm:hidden"
            style={{
              position: 'absolute',
              top: '100%',
              left: 0,
              right: 0,
              background: 'var(--color-surface-1)',
              borderBottom: '1px solid var(--color-border)',
              padding: '8px 12px',
              display: 'flex',
              flexDirection: 'column',
              gap: 2,
              zIndex: 50,
              boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
            }}
          >
            {visibleItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={closeMenu}
                className="px-3 py-2 rounded text-[14px] font-medium transition-colors"
                style={(s) => ({
                  ...linkStyle(s),
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                })}
              >
                {item.label}
                {item.badge && activeIncidentCount > 0 && (
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: '50%',
                      background: '#f59e0b',
                      display: 'inline-block',
                    }}
                  />
                )}
              </NavLink>
            ))}
            <div
              style={{
                borderTop: '1px solid var(--color-border)',
                marginTop: 6,
                paddingTop: 6,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <span
                style={{
                  fontSize: 12,
                  color: 'var(--color-text-secondary)',
                  padding: '4px 8px',
                }}
              >
                <span style={{ color: 'var(--color-accent)', fontWeight: 500 }}>
                  {user?.username}
                </span>
                <span
                  className="text-[10px] ml-2 px-1.5 py-0.5 rounded uppercase tracking-wider"
                  style={{
                    backgroundColor: 'var(--color-accent-muted)',
                    color: 'var(--color-accent)',
                  }}
                >
                  {user?.role}
                </span>
              </span>
              <button
                onClick={logout}
                className="px-3 py-1.5 rounded text-[13px] font-medium"
                style={{
                  color: 'var(--color-danger)',
                  background: 'transparent',
                  border: '1px solid rgba(239,68,68,0.3)',
                }}
              >
                Logout
              </button>
            </div>
          </div>
        )}
      </nav>

      <main className="flex-1 p-4 sm:p-6">
        <ErrorBoundary>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  )
}

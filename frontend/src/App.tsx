import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './hooks/useAuth'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'

// Route-level code splitting — each page lazy-loads on first navigation so
// the initial bundle stays small. Login stays eager-loaded because it's the
// first render for every unauthenticated visitor and splitting it would add
// a round-trip before the form appears.
const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const DetectionFeed = lazy(() => import('./pages/DetectionFeed'))
const Watchlist = lazy(() => import('./pages/Watchlist'))
const SourceStatus = lazy(() => import('./pages/SourceStatus'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
const UserManagement = lazy(() => import('./pages/UserManagement'))

function RouteFallback() {
  return (
    <div style={{ padding: 40, color: 'var(--color-text-tertiary)', fontSize: 13 }}>
      Loading…
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<Layout />}>
            <Route
              path="/dashboard"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <DashboardPage />
                </Suspense>
              }
            />
            <Route
              path="/detections"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <DetectionFeed />
                </Suspense>
              }
            />
            <Route
              path="/watchlist"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <Watchlist />
                </Suspense>
              }
            />
            <Route
              path="/sources"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <SourceStatus />
                </Suspense>
              }
            />
            <Route
              path="/settings"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <SettingsPage />
                </Suspense>
              }
            />
            <Route
              path="/admin/users"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <UserManagement />
                </Suspense>
              }
            />
          </Route>
          <Route path="/" element={<Navigate to="/dashboard" />} />
          <Route path="*" element={<Navigate to="/dashboard" />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}

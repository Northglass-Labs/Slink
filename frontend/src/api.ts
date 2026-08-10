import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
})

// Attach Bearer token from localStorage to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// On 401, attempt a silent token refresh. If that fails, clear storage and
// send the user to the login page. This avoids forcing re-login on every
// minor expiry as long as the refresh token is still valid.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const refreshRes = await axios.post('/api/auth/refresh', null, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`,
          },
        })

        const newToken = refreshRes.data.access_token
        localStorage.setItem('token', newToken)
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch {
        // Refresh failed — session is truly expired
        localStorage.removeItem('token')
        window.location.href = '/login'
      }
    }

    return Promise.reject(error)
  }
)

export default api

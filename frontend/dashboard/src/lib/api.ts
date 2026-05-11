import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'
const tokenKey = 'sentinelai_token'

export const api = axios.create({
  baseURL,
  timeout: 10000,
})

export function getAuthToken(): string | null {
  return localStorage.getItem(tokenKey)
}

export function setAuthToken(token: string): void {
  localStorage.setItem(tokenKey, token)
}

export function clearAuthToken(): void {
  localStorage.removeItem(tokenKey)
}

api.interceptors.request.use((config) => {
  const token = getAuthToken()
  if (token) {
    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

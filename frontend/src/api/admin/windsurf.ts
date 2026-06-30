import { apiClient } from '../client'

export interface WindsurfTokenInfo {
  api_key: string
  name?: string
  email?: string
  api_server_url?: string
  session_token?: string
  auth_method?: string
}

export async function importToken(payload: {
  token: string
  proxy_id?: number
}): Promise<WindsurfTokenInfo> {
  const { data } = await apiClient.post<WindsurfTokenInfo>('/admin/windsurf/oauth/import-token', payload)
  return data
}

export async function loginWithPassword(payload: {
  email: string
  password: string
  proxy_id?: number
}): Promise<WindsurfTokenInfo> {
  const { data } = await apiClient.post<WindsurfTokenInfo>('/admin/windsurf/oauth/password-login', payload)
  return data
}

export default {
  importToken,
  loginWithPassword
}

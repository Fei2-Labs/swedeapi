import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores/app'
import { adminAPI } from '@/api/admin'
import type { WindsurfTokenInfo } from '@/api/admin/windsurf'

export function useWindsurfAuth() {
  const appStore = useAppStore()
  const { t } = useI18n()

  const loading = ref(false)
  const error = ref('')

  const resetState = () => {
    loading.value = false
    error.value = ''
  }

  const importToken = async (
    token: string,
    proxyId?: number | null
  ): Promise<WindsurfTokenInfo | null> => {
    loading.value = true
    error.value = ''
    try {
      return await adminAPI.windsurf.importToken({
        token: token.trim(),
        proxy_id: proxyId || undefined
      })
    } catch (err: any) {
      error.value = err.response?.data?.detail || t('admin.accounts.oauth.authFailed')
      appStore.showError(error.value)
      return null
    } finally {
      loading.value = false
    }
  }

  const loginWithPassword = async (payload: {
    email: string
    password: string
    proxyId?: number | null
  }): Promise<WindsurfTokenInfo | null> => {
    loading.value = true
    error.value = ''
    try {
      return await adminAPI.windsurf.loginWithPassword({
        email: payload.email.trim(),
        password: payload.password,
        proxy_id: payload.proxyId || undefined
      })
    } catch (err: any) {
      error.value = err.response?.data?.detail || t('admin.accounts.oauth.authFailed')
      appStore.showError(error.value)
      return null
    } finally {
      loading.value = false
    }
  }

  const buildCredentials = (tokenInfo: WindsurfTokenInfo): Record<string, unknown> => {
    const credentials: Record<string, unknown> = {
      api_key: tokenInfo.api_key
    }
    if (tokenInfo.api_server_url) {
      credentials.api_server_url = tokenInfo.api_server_url
    }
    if (tokenInfo.session_token) {
      credentials.session_token = tokenInfo.session_token
    }
    if (tokenInfo.email) {
      credentials.email = tokenInfo.email
    }
    return credentials
  }

  return {
    loading,
    error,
    resetState,
    importToken,
    loginWithPassword,
    buildCredentials
  }
}

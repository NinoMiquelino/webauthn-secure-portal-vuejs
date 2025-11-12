import { ref, computed, onMounted, onUnmounted } from 'vue'
import { secureDB } from '../utils/indexeddb'
import { validateJWT, generateJWT } from '../utils/jwt'

export function useSession() {
  const isAuthenticated = ref(false)
  const sessionUser = ref(null)
  const sessionStart = ref(null)
  const sessionTimeout = ref(900) // 15 minutos padrão
  const inactivityTimer = ref(null)
  const sessionToken = ref(null)

  // Inicializar sessão
  const initSession = async () => {
    // Verificar token válido no IndexedDB
    const token = await secureDB.getValidToken()
    
    if (token && validateJWT(token)) {
      sessionToken.value = token
      isAuthenticated.value = true
      sessionStart.value = new Date().toISOString()
      
      // Log de sessão iniciada
      await secureDB.logEvent('SESSION_START', 'system', {
        token: token.substring(0, 10) + '...'
      })
      
      startInactivityTimer()
      return true
    }
    
    return false
  }

  // Iniciar sessão
  const startSession = async (userData, credentialId) => {
    const token = generateJWT({
      userId: userData.id || 'anonymous',
      username: userData.username,
      credentialId: credentialId,
      timestamp: Date.now()
    })

    // Armazenar token
    await secureDB.storeToken(token, sessionTimeout.value)
    sessionToken.value = token
    isAuthenticated.value = true
    sessionUser.value = userData
    sessionStart.value = new Date().toISOString()

    // Log de sessão
    await secureDB.logEvent('SESSION_START', userData.username, {
      credentialId: credentialId,
      userAgent: navigator.userAgent
    })

    startInactivityTimer()
    return token
  }

  // Finalizar sessão
  const endSession = async (reason = 'user_logout') => {
    if (isAuthenticated.value) {
      await secureDB.logEvent('SESSION_END', sessionUser.value?.username || 'unknown', {
        reason: reason,
        duration: getSessionDuration()
      })
    }

    // Limpar timer de inatividade
    if (inactivityTimer.value) {
      clearTimeout(inactivityTimer.value)
      inactivityTimer.value = null
    }

    // Limpar dados da sessão
    isAuthenticated.value = false
    sessionUser.value = null
    sessionStart.value = null
    sessionToken.value = null

    // Limpar token do storage
    await secureDB.clearExpiredTokens()
  }

  // Timer de inatividade
  const startInactivityTimer = () => {
    if (inactivityTimer.value) {
      clearTimeout(inactivityTimer.value)
    }

    inactivityTimer.value = setTimeout(() => {
      endSession('inactivity_timeout')
    }, sessionTimeout.value * 1000)
  }

  // Resetar timer de inatividade
  const resetInactivityTimer = () => {
    if (isAuthenticated.value) {
      startInactivityTimer()
    }
  }

  // Atualizar timeout da sessão
  const updateSessionTimeout = (newTimeout) => {
    sessionTimeout.value = newTimeout
    if (isAuthenticated.value) {
      startInactivityTimer()
    }
  }

  // Duração da sessão
  const getSessionDuration = () => {
    if (!sessionStart.value) return 0
    const start = new Date(sessionStart.value)
    const now = new Date()
    return Math.floor((now - start) / 1000) // segundos
  }

  // Formatar duração
  const formatSessionDuration = () => {
    const duration = getSessionDuration()
    const hours = Math.floor(duration / 3600)
    const minutes = Math.floor((duration % 3600) / 60)
    const seconds = duration % 60

    if (hours > 0) {
      return `${hours}h ${minutes}m ${seconds}s`
    } else if (minutes > 0) {
      return `${minutes}m ${seconds}s`
    } else {
      return `${seconds}s`
    }
  }

  // Informações da sessão
  const sessionInfo = computed(() => ({
    isAuthenticated: isAuthenticated.value,
    user: sessionUser.value,
    startTime: sessionStart.value,
    duration: getSessionDuration(),
    formattedDuration: formatSessionDuration(),
    timeout: sessionTimeout.value
  }))

  // Event listeners para detecção de atividade
  const setupActivityListeners = () => {
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart']
    
    events.forEach(event => {
      document.addEventListener(event, resetInactivityTimer, { passive: true })
    })
  }

  const cleanupActivityListeners = () => {
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart']
    
    events.forEach(event => {
      document.removeEventListener(event, resetInactivityTimer)
    })
  }

  // Verificar validade da sessão periodicamente
  const startSessionValidation = () => {
    const interval = setInterval(async () => {
      if (isAuthenticated.value && sessionToken.value) {
        if (!validateJWT(sessionToken.value)) {
          await endSession('token_expired')
        }
      }
    }, 60000) // Verificar a cada minuto

    return interval
  }

  onMounted(() => {
    setupActivityListeners()
    const validationInterval = startSessionValidation()

    onUnmounted(() => {
      cleanupActivityListeners()
      clearInterval(validationInterval)
      
      if (inactivityTimer.value) {
        clearTimeout(inactivityTimer.value)
      }
    })
  })

  return {
    // Estado
    isAuthenticated,
    sessionUser,
    sessionInfo,
    
    // Ações
    initSession,
    startSession,
    endSession,
    updateSessionTimeout,
    resetInactivityTimer,
    getSessionDuration,
    formatSessionDuration
  }
}

// Hook para proteção de rotas
export function useRouteGuard(router) {
  const { isAuthenticated, initSession } = useSession()

  const setupRouteGuard = () => {
    router.beforeEach(async (to, from, next) => {
      const requiresAuth = to.matched.some(record => record.meta.requiresAuth)
      
      if (requiresAuth && !isAuthenticated.value) {
        // Tentar recuperar sessão
        const hasValidSession = await initSession()
        
        if (!hasValidSession) {
          next('/auth')
          return
        }
      }
      
      next()
    })
  }

  return {
    setupRouteGuard
  }
}

// Middleware de sessão para componentes
export function withSession(component) {
  return {
    ...component,
    setup(props, context) {
      const session = useSession()
      
      // Verificar sessão ao montar o componente
      onMounted(async () => {
        if (!session.isAuthenticated.value) {
          await session.initSession()
        }
      })

      return {
        ...component.setup?.(props, context),
        session
      }
    }
  }
}
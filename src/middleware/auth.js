import { secureDB } from '../utils/indexeddb'
import { validateJWT } from '../utils/jwt'

// Tipos de rotas
export const RouteType = {
  PUBLIC: 'public',
  PROTECTED: 'protected',
  AUTH_ONLY: 'auth_only' // Apenas para usuários não autenticados
}

// Configuração de rotas
const routeConfig = {
  '/': RouteType.PUBLIC,
  '/auth': RouteType.AUTH_ONLY,
  '/dashboard': RouteType.PROTECTED,
  '/security': RouteType.PROTECTED,
  '/profile': RouteType.PROTECTED
}

// Middleware principal de autenticação
export class AuthMiddleware {
  constructor(router) {
    this.router = router
    this.setupInterceptors()
  }

  // Configurar interceptors de navegação
  setupInterceptors() {
    this.router.beforeEach(async (to, from, next) => {
      const requiresAuth = this.requiresAuthentication(to.path)
      const isAuthRoute = this.isAuthenticationRoute(to.path)
      
      // Verificar autenticação atual
      const isAuthenticated = await this.checkAuthentication()
      
      // Redirecionar se tentar acessar rota protegida sem autenticação
      if (requiresAuth && !isAuthenticated) {
        await secureDB.logEvent('UNAUTHORIZED_ACCESS', 'system', {
          path: to.path,
          userAgent: navigator.userAgent
        })
        
        next('/auth')
        return
      }
      
      // Redirecionar se tentar acessar rota de auth já autenticado
      if (isAuthRoute && isAuthenticated) {
        next('/dashboard')
        return
      }
      
      // Registrar acesso à rota
      await this.logRouteAccess(to.path, isAuthenticated)
      
      next()
    })

    // Interceptor após navegação
    this.router.afterEach((to) => {
      this.updateDocumentTitle(to)
      this.trackPageView(to)
    })
  }

  // Verificar se rota requer autenticação
  requiresAuthentication(path) {
    const routeType = routeConfig[path] || RouteType.PUBLIC
    return routeType === RouteType.PROTECTED
  }

  // Verificar se é rota de autenticação
  isAuthenticationRoute(path) {
    const routeType = routeConfig[path] || RouteType.PUBLIC
    return routeType === RouteType.AUTH_ONLY
  }

  // Verificar autenticação atual
  async checkAuthentication() {
    try {
      const token = await secureDB.getValidToken()
      
      if (!token) {
        return false
      }

      // Validar JWT
      const isValid = validateJWT(token)
      
      if (!isValid) {
        await secureDB.clearExpiredTokens()
        return false
      }

      return true
    } catch (error) {
      console.error('Erro ao verificar autenticação:', error)
      return false
    }
  }

  // Registrar acesso à rota
  async logRouteAccess(path, isAuthenticated) {
    try {
      await secureDB.logEvent('ROUTE_ACCESS', isAuthenticated ? 'authenticated' : 'anonymous', {
        path: path,
        authenticated: isAuthenticated,
        timestamp: new Date().toISOString()
      })
    } catch (error) {
      console.error('Erro ao registrar acesso à rota:', error)
    }
  }

  // Atualizar título do documento
  updateDocumentTitle(to) {
    const titleMap = {
      '/': 'Portal Seguro',
      '/auth': 'Autenticação - Portal Seguro',
      '/dashboard': 'Dashboard - Portal Seguro',
      '/security': 'Segurança - Portal Seguro',
      '/profile': 'Perfil - Portal Seguro'
    }
    
    document.title = titleMap[to.path] || 'Portal Seguro'
  }

  // Rastrear visualização de página
  trackPageView(to) {
    // Integração com analytics (opcional)
    if (window.gtag) {
      window.gtag('config', 'GA_MEASUREMENT_ID', {
        page_title: document.title,
        page_location: window.location.href,
        page_path: to.path
      })
    }
  }

  // Middleware para componentes Vue
  static install(app) {
    app.mixin({
      async beforeRouteEnter(to, from, next) {
        const requiresAuth = routeConfig[to.path] === RouteType.PROTECTED
        
        if (requiresAuth) {
          const token = await secureDB.getValidToken()
          const isValid = token ? validateJWT(token) : false
          
          if (!isValid) {
            next('/auth')
            return
          }
        }
        
        next()
      },
      
      async beforeRouteUpdate(to, from, next) {
        const requiresAuth = routeConfig[to.path] === RouteType.PROTECTED
        
        if (requiresAuth) {
          const token = await secureDB.getValidToken()
          const isValid = token ? validateJWT(token) : false
          
          if (!isValid) {
            next('/auth')
            return
          }
        }
        
        next()
      }
    })
  }
}

// Proteção de rotas para composables
export function useRouteProtection() {
  const checkRouteAccess = async (path) => {
    const requiresAuth = routeConfig[path] === RouteType.PROTECTED
    
    if (requiresAuth) {
      const token = await secureDB.getValidToken()
      const isValid = token ? validateJWT(token) : false
      
      if (!isValid) {
        throw new Error('Acesso não autorizado')
      }
    }
    
    return true
  }

  const withAuth = (fn) => {
    return async (...args) => {
      await checkRouteAccess(window.location.pathname)
      return fn(...args)
    }
  }

  return {
    checkRouteAccess,
    withAuth
  }
}

// Hook para guardas de navegação
export function useNavigationGuard() {
  const { checkRouteAccess } = useRouteProtection()

  const setupNavigationGuard = (router) => {
    router.beforeEach(async (to, from, next) => {
      try {
        await checkRouteAccess(to.path)
        next()
      } catch (error) {
        console.warn('Bloqueando navegação não autorizada:', error.message)
        next('/auth')
      }
    })
  }

  return {
    setupNavigationGuard
  }
}

export default AuthMiddleware
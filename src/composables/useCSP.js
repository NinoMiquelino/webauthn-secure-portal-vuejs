export function setupCSP(trustedTypesPolicy) {
  // Gerar nonce para scripts
  const generateNonce = () => {
    const array = new Uint8Array(32)
    crypto.getRandomValues(array)
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
  }

  const nonce = generateNonce()

  // Configurar CSP meta tag
  const setupCSPMetaTag = () => {
    const csp = `
      default-src 'self';
      script-src 'self' 'nonce-${nonce}' 'strict-dynamic' https: 'unsafe-inline';
      style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
      font-src 'self' https://fonts.gstatic.com;
      connect-src 'self' https://api.yourapi.com;
      object-src 'none';
      base-uri 'self';
      form-action 'self';
      frame-ancestors 'none';
      ${trustedTypesPolicy ? `require-trusted-types-for 'script';` : ''}
    `.replace(/\s+/g, ' ').trim()

    const meta = document.createElement('meta')
    meta.httpEquiv = 'Content-Security-Policy'
    meta.content = csp
    document.head.appendChild(meta)

    return nonce
  }

  // Aplicar CSP
  const applyCSP = () => {
    const scriptNonce = setupCSPMetaTag()
    
    // Aplicar nonce aos scripts existentes
    document.querySelectorAll('script').forEach(script => {
      if (!script.nonce) {
        script.nonce = scriptNonce
      }
    })

    return scriptNonce
  }

  return { applyCSP, generateNonce }
}
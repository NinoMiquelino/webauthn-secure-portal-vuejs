import { ref, computed } from 'vue'
import { generateChallenge, base64ToArrayBuffer, arrayBufferToBase64 } from '../utils/crypto'
import { storeCredential, getStoredCredentials } from '../utils/indexeddb'

export function useWebAuthn() {
  const isSupported = ref(false)
  const isLoading = ref(false)
  const error = ref(null)

  // Verificar suporte do navegador
  const checkSupport = () => {
    isSupported.value = 
      window.PublicKeyCredential &&
      typeof window.PublicKeyCredential === 'function' &&
      typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function'
  }

  // Registrar nova credencial
  const register = async (username, displayName) => {
    try {
      isLoading.value = true
      error.value = null

      // Gerar challenge
      const challenge = generateChallenge(32)
      
      // Opções de criação
      const publicKeyCredentialCreationOptions = {
        challenge: base64ToArrayBuffer(challenge),
        rp: {
          name: "Portal Seguro",
          id: window.location.hostname
        },
        user: {
          id: base64ToArrayBuffer(generateChallenge(16)),
          name: username,
          displayName: displayName
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },  // ES256
          { type: "public-key", alg: -257 } // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required"
        },
        timeout: 60000,
        attestation: "direct"
      }

      // Criar credencial
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      })

      // Armazenar credencial
      await storeCredential({
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: arrayBufferToBase64(credential.response.attestationObject),
          clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
        }
      }, username)

      return { success: true, credential }
    } catch (err) {
      error.value = err.message
      return { success: false, error: err.message }
    } finally {
      isLoading.value = false
    }
  }

  // Autenticar
  const authenticate = async () => {
    try {
      isLoading.value = true
      error.value = null

      const challenge = generateChallenge(32)
      const credentials = await getStoredCredentials()

      const publicKeyCredentialRequestOptions = {
        challenge: base64ToArrayBuffer(challenge),
        allowCredentials: credentials.map(cred => ({
          id: base64ToArrayBuffer(cred.rawId),
          type: cred.type,
          transports: ['internal']
        })),
        timeout: 60000,
        userVerification: "required"
      }

      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      })

      return { 
        success: true, 
        assertion,
        credentialId: assertion.id 
      }
    } catch (err) {
      error.value = err.message
      return { success: false, error: err.message }
    } finally {
      isLoading.value = false
    }
  }

  return {
    isSupported,
    isLoading,
    error,
    checkSupport,
    register,
    authenticate
  }
}
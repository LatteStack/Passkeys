import { container } from 'tsyringe'
import { type CredentialEntity } from './adapters/Adapter'
import { OPTIONS } from './constants'
import { WebAuthn } from './WebAuthn'

const challenge = '39159cfedfa7251f0aeeb51b4d6b6e8c2cd6a99485e582040da6b431710b2fed'

const user = {
  id: 'b72d6ec61128cc22cea1f0d6d0ec9d91',
  name: 'test_user',
  displayName: 'test_user_display_name'
}

const attestation = {
  type: 'public-key',
  id: 'p0j2terIvM1Gfv8inptjEsmaZ3csdMMUH_Bk_MN1AUk',
  rawId: 'p0j2terIvM1Gfv8inptjEsmaZ3csdMMUH_Bk_MN1AUk',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMzkxNTljZmVkZmE3MjUxZjBhZWViNTFiNGQ2YjZlOGMyY2Q2YTk5NDg1ZTU4MjA0MGRhNmI0MzE3MTBiMmZlZCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
    attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAIKdI9rXqyLzNRn7_Ip6bYxLJmmd3LHTDFB_wZPzDdQFJpQECAyYgASFYIHst5tPHdegoY_eBWDpnX44MnOWJTo6IIEn_97QPh6rFIlgg7XSF-2qsbVB6pEPXfXMz5QWsANwcS1UbKeaIJCRGiM8',
    transports: [
      'internal'
    ]
  },
  clientExtensionResults: {}
}

const assertion = {
  type: 'public-key',
  id: 'p0j2terIvM1Gfv8inptjEsmaZ3csdMMUH_Bk_MN1AUk',
  rawId: 'p0j2terIvM1Gfv8inptjEsmaZ3csdMMUH_Bk_MN1AUk',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMzkxNTljZmVkZmE3MjUxZjBhZWViNTFiNGQ2YjZlOGMyY2Q2YTk5NDg1ZTU4MjA0MGRhNmI0MzE3MTBiMmZlZCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
    authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg',
    signature: 'MEUCIFdy-3gjQj13g35khwZoljRGTxz4mFf8ggncCgN6DDn8AiEAzKYzWRr9jSawM1cqdKljx8HVKR5dZVjuBLkKjvDG1DE',
    userHandle: null
  },
  clientExtensionResults: {}
}

const credential: CredentialEntity = {
  id: 'p0j2terIvM1Gfv8inptjEsmaZ3csdMMUH_Bk_MN1AUk',
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEey3m08d16Chj94FYOmdfjgyc5YlO\n' +
    'joggSf/3tA+HqsXtdIX7aqxtUHqkQ9d9czPlBawA3BxLVRsp5ogkJEaIzw==\n' +
    '-----END PUBLIC KEY-----\n',
  counter: 0,
  userHandle: null,
  transports: []
}

describe('WebAuthn', () => {
  beforeEach(() => {
    container.reset()
    container.register(WebAuthn, { useClass: WebAuthn })
    container.register(OPTIONS, {
      useValue: {
        secret: 'secret',
        origin: 'http://localhost:3000'
      }
    })
  })

  it('should be defined', () => {
    const instance = container.resolve(WebAuthn)
    expect(instance).toBeDefined()
  })

  describe('createCreationOptions', () => {
    it('should create creation options correctly', async () => {
      const instance = container.resolve(WebAuthn)
      const options = await instance.createCreationOptions({ user, challenge })

      expect(options.rp).toBeDefined()
      expect(options.user).toBeDefined()
      expect(options.challenge).toBeDefined()
      expect(options.pubKeyCredParams).toBeDefined()
      expect(options.timeout).toBeDefined()
      expect(options.excludeCredentials).toBeDefined()
      expect(options.authenticatorSelection).toBeDefined()
      expect(options.attestation).toBeDefined()
      expect(options.challenge).toBe(challenge)
    })

    it('should verify attestation correctly', async () => {
      const instance = container.resolve(WebAuthn)
      const attestationResult = await instance.verifyAttestation(attestation as any, { challenge })
      expect(attestationResult.credId).toBeDefined()
      expect(attestationResult.publicKey).toBeDefined()
      expect(attestationResult.counter).toBeDefined()
    })
  })

  describe('createRequestOptions', () => {
    it('should create request options correctly', async () => {
      const instance = container.resolve(WebAuthn)
      const options = await instance.createRequestOptions({
        challenge,
        allowCredentials: [credential]
      })

      expect(options.challenge).toBe(challenge)
    })

    it('should verify assertion correctly', async () => {
      const instance = container.resolve(WebAuthn)
      const assertionResult = await instance.verifyAssertion(assertion as any, {
        ...(credential as any),
        challenge
      })

      expect(assertionResult.userHandle).toBeDefined()
      expect(assertionResult.counter).toBeDefined()
    })
  })
})

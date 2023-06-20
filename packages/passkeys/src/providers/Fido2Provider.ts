import { randomUUID } from 'crypto'
import { inject, Lifecycle, scoped } from 'tsyringe'
import { Adapter, type UserEntity, type CredentialEntity } from '../adapters/Adapter'
import { OPTIONS } from '../constants'
import { Jwt } from '../Jwt'
import { type PasskeysOptions } from '../Passkeys'
import {
  type AuthResponse,
  type PublicKeyCredentialRequestOptionsJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialWithAttestationJSON,
  type PublicKeyCredentialWithAssertionJSON,
  type PublicKeyCredentialUserEntityJSON,
  type PublicKeyCredentialDescriptorJSON
} from '../types'
import { fromBase64Url, now } from '../utils'
import { WebAuthn } from '../WebAuthn'
import { Provider } from './Provider'
import { InvalidOperationException } from '../exceptions'

export interface Fido2ChallengeRequest {
  email: string
}

export interface Fido2ChallengeResponse {
  options: PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON
}

export interface Fido2SignInRequest {
  credential: PublicKeyCredentialWithAttestationJSON | PublicKeyCredentialWithAssertionJSON
}

interface CommonChallengePayload {
  verificationId: string
  subject: string
}

type ChallengePayloadForNewUser = CommonChallengePayload & {
  type: 'webauthn.create'
  email: string
}

type ChallengePayloadForExistingUser = CommonChallengePayload & {
  type: 'webauthn.get'
}

type ChallengePayloadForNewAuthenticator = CommonChallengePayload & {
  type: 'webauthn.create'
}

type ChallengePayload =
  | ChallengePayloadForNewUser
  | ChallengePayloadForExistingUser
  | ChallengePayloadForNewAuthenticator

@scoped(Lifecycle.ContainerScoped)
export class Fido2Provider extends Provider {
  override providerId = 'fido2'

  constructor (
    @inject(OPTIONS) protected override readonly options: PasskeysOptions,
    protected override readonly adapter: Adapter,
    protected override readonly jwt: Jwt,
    private readonly webauthn: WebAuthn
  ) {
    super(options, adapter, jwt)
  }

  async challenge (request: Fido2ChallengeRequest): Promise<Fido2ChallengeResponse> {
    const { email } = request
    const existingUser = await this.adapter.getUserByEmail(email)

    if (existingUser === null) {
      return await this.challengeForNewUser({ email })
    }

    const existingCredentials = existingUser?.credentials ?? []
    const webauthnUser: PublicKeyCredentialUserEntityJSON = {
      id: existingUser.id,
      name: email,
      displayName: existingUser.name ?? email.split('@')[0]
    }

    return existingCredentials.length > 0
      ? await this.challengeForExistingUser({
        allowCredentials: existingCredentials,
        webauthnUser
      })
      : await this.challengeForNewAuthenticator({
        excludeCredentials: existingCredentials,
        webauthnUser
      })
  }

  protected async challengeForNewUser (params: {
    email: string
  }): Promise<Fido2ChallengeResponse> {
    const { email } = params
    const webauthnUser: PublicKeyCredentialUserEntityJSON = {
      id: randomUUID(),
      name: email,
      displayName: email.split('@')[0]
    }

    return {
      options: await this.webauthn.createCreationOptions({
        user: webauthnUser,
        excludeCredentials: [],
        challenge: await this.signVerificationToken<ChallengePayloadForNewUser>({
          verificationId: randomUUID(),
          type: 'webauthn.create',
          subject: webauthnUser.id,
          email
        })
      })
    }
  }

  protected async challengeForExistingUser (params: {
    webauthnUser: PublicKeyCredentialUserEntityJSON
    allowCredentials: Array<Omit<PublicKeyCredentialDescriptorJSON, 'type'>>
  }): Promise<Fido2ChallengeResponse> {
    const { webauthnUser, allowCredentials } = params

    return {
      options: await this.webauthn.createRequestOptions({
        allowCredentials,
        challenge: await this.signVerificationToken<ChallengePayloadForExistingUser>({
          verificationId: randomUUID(),
          type: 'webauthn.get',
          subject: webauthnUser.id
        })
      })
    }
  }

  protected async challengeForNewAuthenticator (params: {
    webauthnUser: PublicKeyCredentialUserEntityJSON
    excludeCredentials: Array<Omit<PublicKeyCredentialDescriptorJSON, 'type'>>
  }): Promise<Fido2ChallengeResponse> {
    const { webauthnUser, excludeCredentials } = params

    return {
      options: await this.webauthn.createCreationOptions({
        user: webauthnUser,
        excludeCredentials,
        challenge: await this.signVerificationToken<ChallengePayloadForNewAuthenticator>({
          verificationId: randomUUID(),
          type: 'webauthn.create',
          subject: webauthnUser.id
        })
      })
    }
  }

  async signIn (request: Fido2SignInRequest): Promise<AuthResponse> {
    const { credential: publicKeyCredential } = request
    const { challenge } = JSON.parse(
      new TextDecoder('utf-8').decode(
        fromBase64Url(publicKeyCredential.response.clientDataJSON)
      )
    )

    const { payload } = await this.useVerificationToken<ChallengePayload>(challenge)
    const { type, subject } = payload
    const user = await this.adapter.getUser(subject)

    if (user == null) {
      if (type === 'webauthn.create') {
        const { email } = payload as ChallengePayloadForNewUser

        if (email != null) {
          return await this.signInAsNewUser({
            challenge,
            attestation: publicKeyCredential as PublicKeyCredentialWithAttestationJSON,
            newUser: {
              id: subject,
              email
            }
          })
        }
      }

      throw new InvalidOperationException()
    }

    // Must check user state
    this.assertUserState(user)

    return type === 'webauthn.create'
      ? await this.signInWithNewAuthenticator({
        challenge,
        user,
        attestation: publicKeyCredential as PublicKeyCredentialWithAttestationJSON
      })
      : await this.signInAsExistingUser({
        challenge,
        user,
        assertion: publicKeyCredential as PublicKeyCredentialWithAssertionJSON
      })
  }

  protected async signInAsNewUser (params: {
    newUser: Partial<UserEntity>
    challenge: string
    attestation: PublicKeyCredentialWithAttestationJSON
  }): Promise<AuthResponse> {
    const { newUser, challenge, attestation } = params
    const attestationResult = await this.webauthn.verifyAttestation(attestation, { challenge })

    const user = await this.createUser({
      ...newUser,
      lastSignInTime: now(),
      credentials: [{
        id: attestationResult.credId,
        publicKey: attestationResult.publicKey,
        counter: attestationResult.counter,
        userHandle: attestationResult.userHandle,
        transports: attestation.response.transports,
        createdAt: now()
      }]
    })

    return await this.createSession(user)
  }

  protected async signInAsExistingUser (params: {
    user: UserEntity
    challenge: string
    assertion: PublicKeyCredentialWithAssertionJSON
  }): Promise<AuthResponse> {
    const { user, challenge, assertion } = params
    const currentCredential = user.credentials.find(({ id }) => {
      return id === assertion.id
    })

    if (currentCredential == null) {
      throw new InvalidOperationException()
    }

    const { counter: nextCounter } = await this.webauthn.verifyAssertion(assertion, {
      challenge,
      publicKey: currentCredential.publicKey,
      counter: currentCredential.counter,
      userHandle: currentCredential.userHandle
    })

    await this.adapter.createCredential({
      ...currentCredential,
      counter: nextCounter
    })

    return await this.createSession(user)
  }

  protected async signInWithNewAuthenticator (params: {
    user: UserEntity
    challenge: string
    attestation: PublicKeyCredentialWithAttestationJSON
  }): Promise<AuthResponse> {
    const { user, challenge, attestation } = params
    const attestationResult = await this.webauthn.verifyAttestation(attestation, { challenge })

    await this.adapter.createCredential({
      id: attestationResult.credId,
      publicKey: attestationResult.publicKey,
      counter: attestationResult.counter,
      userHandle: attestationResult.userHandle,
      transports: attestation.response.transports,
      createdAt: now()
    })

    return await this.createSession(user)
  }
}

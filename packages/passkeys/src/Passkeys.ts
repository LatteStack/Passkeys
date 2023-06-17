import {
  type AuthResponse,
  type Constructor,
  type Registrations
} from './types'
// import { type Provider } from './providers/Provider'
import * as yup from 'yup'
import * as tsyringe from 'tsyringe'
import { OPTIONS } from './constants'
import { omit } from 'lodash'
import { type JwtOptions } from './Jwt'
import {
  type Fido2ChallengeRequest,
  type Fido2ChallengeResponse,
  Fido2Provider,
  type Fido2SignInRequest,
  Provider
} from './providers'

export interface PasskeysOptions {
  /** A random string is used to hash tokens. */
  secret: string

  /**
   * See: https://javascript.info/url
   */
  origin: string

  /** Using an adapter you can connect to common database. */
  // adapter: Adapter

  /** Hooks are asynchronous functions you can use to control what happens when an action is performed. */
  // hooks?: Hooks

  webAuthn?: {
    attestation?: AttestationConveyancePreference
    pubKeyCredParams?: PublicKeyCredentialParameters[]
    authenticatorSelection?: AuthenticatorSelectionCriteria
    /** See: https://w3c.github.io/webauthn/#rp-id */
    rp?: Partial<PublicKeyCredentialRpEntity>
  }

  jwt?: JwtOptions

  debug?: boolean
}

const optionsSchema: yup.ObjectSchema<PasskeysOptions> = yup.object({
  secret: yup.string().required(),
  origin: yup.string().required().transform((value) => new URL(value).origin),
  webAuthn: yup.mixed().optional(),
  jwt: yup.object().optional().shape({
    accessTokenMaxAge: yup.number().optional(),
    refreshTokenMaxAge: yup.number().optional()
  }),
  debug: yup.boolean().optional().transform((value) => Boolean(value))
})

@tsyringe.scoped(tsyringe.Lifecycle.ContainerScoped)
export class Passkeys {
  constructor (
    private readonly provider: Provider,
    private readonly fido2Provider: Fido2Provider
  ) {
    console.log(this.fido2Provider)
  }

  use (registrations: Registrations): void {
    for (const registration of registrations) {
      if (
        tsyringe.isClassProvider(registration) ||
        tsyringe.isFactoryProvider(registration) ||
        tsyringe.isValueProvider(registration) ||
        tsyringe.isTokenProvider(registration)
      ) {
        tsyringe.container.register(
          registration.token,
          omit(registration, ['token', 'options']) as any,
          // declare options as RegistrationOptions to avoid jest error
          registration.options as tsyringe.RegistrationOptions
        )
      }
    }
  }

  get<T = any>(token: tsyringe.InjectionToken): T {
    return tsyringe.container.resolve(token)
  }

  has (token: tsyringe.InjectionToken): boolean {
    return tsyringe.container.isRegistered(token)
  }

  static create (options: PasskeysOptions): Passkeys {
    tsyringe.container.register(OPTIONS, {
      useValue: optionsSchema.validateSync(options)
    })

    tsyringe.container.register(Passkeys, {
      useClass: Passkeys
    })

    return tsyringe.container.resolve(Passkeys)
  }

  signOut() {
    this.provider.signOut()
  }

  async challengeWithFido2 (request: Fido2ChallengeRequest): Promise<Fido2ChallengeResponse> {
    return await this.fido2Provider.challenge(request)
  }

  async signInWithFido2 (request: Fido2SignInRequest): Promise<AuthResponse> {
    return await this.fido2Provider.signIn(request)
  }

  // challengeWithEmailLink
  // signInWithEmailLink
  // signInWithCustomToken
  // signOut
  // verifyAccessToken
  // verifyRefreshToken
  //
}

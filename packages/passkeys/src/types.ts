import { type Provider, type InjectionToken, type RegistrationOptions } from 'tsyringe'

export type Assign<T, U> = Omit<T, keyof U> & U

export interface Constructor<T = any> extends Function {
  // eslint-disable-next-line @typescript-eslint/prefer-function-type
  new (...args: any[]): T
}

export type Registrations = Array<{
  token: InjectionToken
  options?: RegistrationOptions
} & Provider<any>>

export interface InjectionProvider<T = any> {
  token: InjectionToken
  useClass: Constructor<T>
}

export type Awaitable<T> = T | PromiseLike<T>

export type WithRequiredProperty<Type, Key extends keyof Type> = Type & {
  [Property in Key]-?: Type[Property]
}

interface CredPropsAuthenticationExtensionsClientOutputsJSON {
  rk: boolean
}

interface AuthenticationExtensionsClientOutputsJSON extends AuthenticationExtensionsClientOutputs {
  appidExclude?: boolean
  credProps?: CredPropsAuthenticationExtensionsClientOutputsJSON
}

export interface PublicKeyCredentialWithClientExtensionResults extends PublicKeyCredential {
  authenticatorAttachment?: string | null
  clientExtensionResults?: AuthenticationExtensionsClientOutputsJSON
}

export type AuthenticatorTransportJSON = AuthenticatorTransport | 'hybrid'

export interface PublicKeyCredentialDescriptorJSON {
  type: PublicKeyCredentialType
  id: string
  transports?: AuthenticatorTransportJSON[]
}

interface SimpleWebAuthnExtensionsJSON {
  appid?: string
  appidExclude?: string
  credProps?: boolean
}

interface SimpleClientExtensionResultsJSON {
  appid?: boolean
  appidExclude?: boolean
  credProps?: CredPropsAuthenticationExtensionsClientOutputsJSON
}

interface PublicKeyCredentialJSON {
  id: string
  type: PublicKeyCredentialType
  rawId: string
  authenticatorAttachment?: AuthenticatorAttachment | null
}

export interface PublicKeyCredentialUserEntityJSON extends PublicKeyCredentialEntity {
  displayName: string
  id: string
}

declare type ResidentKeyRequirement = 'discouraged' | 'preferred' | 'required'

interface AuthenticatorSelectionCriteriaJSON extends AuthenticatorSelectionCriteria {
  residentKey?: ResidentKeyRequirement
}

export interface PublicKeyCredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntity
  user: PublicKeyCredentialUserEntityJSON
  challenge: string
  pubKeyCredParams: PublicKeyCredentialParameters[]
  timeout?: number
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[]
  authenticatorSelection?: AuthenticatorSelectionCriteriaJSON
  attestation?: AttestationConveyancePreference
  extensions?: SimpleWebAuthnExtensionsJSON
}

export interface CredentialCreationOptionsJSON {
  publicKey: PublicKeyCredentialCreationOptionsJSON
  signal?: AbortSignal
}

export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: string
  attestationObject: string
  transports: AuthenticatorTransportJSON[]
  authenticatorAttachment?: AuthenticatorAttachment | null
}

export interface PublicKeyCredentialWithAttestationJSON extends PublicKeyCredentialJSON {
  response: AuthenticatorAttestationResponseJSON
  clientExtensionResults: SimpleClientExtensionResultsJSON
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string
  timeout?: number
  rpId?: string
  allowCredentials?: PublicKeyCredentialDescriptorJSON[]
  userVerification?: UserVerificationRequirement
  extensions?: SimpleWebAuthnExtensionsJSON
}

export interface CredentialRequestOptionsJSON {
  mediation?: CredentialMediationRequirement
  publicKey?: PublicKeyCredentialRequestOptionsJSON
  signal?: AbortSignal
}

interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: string
  authenticatorData: string
  signature: string
  userHandle: string | null
}

export interface PublicKeyCredentialWithAssertionJSON extends PublicKeyCredentialJSON {
  response: AuthenticatorAssertionResponseJSON
  clientExtensionResults: SimpleClientExtensionResultsJSON
}

export interface User {
  id: string
  state: | 'Active' | 'Disabled' | 'Destroyed'
  name: string | null
  email: string | null
  emailVerified: boolean
  picture: string | null
  creationTime: Date
  lastSignInTime: Date | null
  customClaims: Record<string, any>
}

export interface Tokens {
  idToken: string
  refreshToken: string
  expirationTime: string
}

export type OperationType = 'signIn' | 'reauthenticate' | 'link'

export interface AuthResponse {
  providerId?: string
  accessToken: string
  refreshToken: string
  expirationTime: string
}

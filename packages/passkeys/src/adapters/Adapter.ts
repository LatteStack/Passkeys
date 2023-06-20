/* eslint-disable @typescript-eslint/no-invalid-void-type */
import { type AuthenticatorTransportJSON } from '../types'

export interface BaseEntity {
  id: string
  createdAt: Date
}

export interface UserEntity extends BaseEntity {
  state: | 'Active' | 'Disabled'
  name: string | null
  email: string | null
  emailVerified: boolean
  picture: string | null
  customClaims: Record<string, any>
}

export interface SessionEntity extends BaseEntity {
  counter: number
  expiredAt: Date
  lastActiveAt: Date
  signInIp: string | null
  userAgent: string | null
  userId: string
}

export interface CredentialEntity extends BaseEntity {
  transports: AuthenticatorTransportJSON[]
  counter: number
  publicKey: string
  userHandle: string | null
  userId: string
}

export interface VerificationEntity extends BaseEntity {
  data: Record<string, any> | null
  expiredAt: Date
}

export abstract class Adapter {
  abstract getUserByEmail (email: string): Promise<UserEntity | null>
  abstract createUser (user: UserEntity): Promise<UserEntity>
  abstract getUser (userId: string): Promise<UserEntity | null>
  abstract updateUser (user: Partial<UserEntity>): Promise<UserEntity | void>
  abstract deleteUser (userId: string): Promise<UserEntity | void>

  abstract createCredential (credential: CredentialEntity): Promise<CredentialEntity | void>
  abstract getCredential (credentialId: string): Promise<CredentialEntity | null>
  abstract updateCredential (credential: Partial<CredentialEntity>): Promise<CredentialEntity | void>
  abstract deleteCredential (credentialId: string): Promise<CredentialEntity | void>

  abstract createSession (session: SessionEntity): Promise<SessionEntity>
  abstract getSession (sessionId: string): Promise<SessionEntity | null>
  abstract updateSession (session: Partial<SessionEntity>): Promise<SessionEntity | void>
  abstract deleteSession (sessionId: string): Promise<SessionEntity | void>

  abstract createVerification (verification: VerificationEntity): Promise<VerificationEntity>
  abstract useVerification (verificationId: string): Promise<VerificationEntity>
}

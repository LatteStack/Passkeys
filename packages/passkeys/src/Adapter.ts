export interface UserEntity {
  id: string
  state: | 'Active' | 'Disabled' | 'Destroyed'
  name: string | null
  email: string | null
  emailVerified: boolean
  picture: string | null
  creationTime: Date
  lastSignInTime: Date | null
  customClaims: Record<string, any>
  credentials: CredentialEntity[]
}

export interface SessionEntity {
  id: string
  counter: number
  createdAt: Date
  expiresAt: Date
  lastActiveAt: Date
  creationIp: string | null
  userAgent: string | null
  user: UserEntity
}

export interface CredentialEntity {
  id: string
  type: PublicKeyCredentialType
  transports: Array<AuthenticatorTransport | 'hybrid'>
  counter: number
  publicKey: string
  userHandle: string | null
}

export interface VerificationEntity<T extends object = any> {
  id: string
  data: T | null
  expiresAt: string
}

export abstract class Adapter {
  abstract createUser: (user: UserEntity) => Promise<UserEntity>
  abstract getUser: (userId: string) => Promise<UserEntity | null>
  abstract getUserByEmail: (email: string) => Promise<UserEntity | null>
  abstract updateUser: (user: Partial<UserEntity>) => Promise<UserEntity>

  abstract createSession: (session: SessionEntity) => Promise<SessionEntity>

  abstract getSession: (sessionId: string) => Promise<SessionEntity | null>
  abstract updateSession: (session: Partial<SessionEntity>) => Promise<SessionEntity>
  abstract deleteSession: (sessionId: string) => Promise<void>

  abstract createVerification: (verification: VerificationEntity) => Promise<VerificationEntity>
  abstract useVerification: (verificationId: string) => Promise<VerificationEntity | null>
}

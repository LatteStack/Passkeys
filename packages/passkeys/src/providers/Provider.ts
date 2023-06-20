import { randomUUID } from 'crypto'
import { addSeconds, isPast } from 'date-fns'
import { noop } from 'lodash'
import { inject, Lifecycle, scoped } from 'tsyringe'
import { Adapter, type SessionEntity, type UserEntity } from '../adapters/Adapter'
import { OPTIONS } from '../constants'
import {
  DuplicateEmailException,
  InvalidSessionException,
  InvalidUserException,
  InvalidVerificationException
} from '../exceptions'
import { Jwt } from '../Jwt'
import { type PasskeysOptions } from '../Passkeys'
import { type AuthResponse } from '../types'
import { now } from '../utils'

export interface SessionRequest {
  accessToken: string
  refreshToken: string
}

@scoped(Lifecycle.ContainerScoped)
export class Provider {
  providerId = 'unknown'

  constructor (
    @inject(OPTIONS) protected readonly options: PasskeysOptions,
    protected readonly adapter: Adapter,
    protected readonly jwt: Jwt
  ) {}

  protected async createUser (user: Partial<UserEntity>): Promise<UserEntity> {
    if (user.email != null) {
      const existingUser = await this.adapter.getUserByEmail(user.email)

      if (existingUser != null) {
        throw new DuplicateEmailException()
      }
    }

    return await this.adapter.createUser({
      id: randomUUID(),
      state: 'Active',
      name: null,
      email: null,
      emailVerified: false,
      picture: null,
      createdAt: now(),
      customClaims: {},
      ...user
    })
  }

  protected async signVerificationToken<
    Payload = any,
    ServerSideData extends Record<string, any> = Record<string, any>
  >(
    payload: Payload & { verificationId: string },
    serverSideData?: ServerSideData
  ): Promise<string> {
    const verificationId = randomUUID()
    const [verificationToken] = await Promise.all([
      this.jwt.signVerificationToken(payload),
      this.adapter.createVerification({
        id: verificationId,
        // Must set a non-null value here to avoid Three-Valued Logic (3VL)
        data: serverSideData ?? {},
        expiredAt: addSeconds(now(), this.jwt.verificationTokenMaxAge),
        createdAt: now()
      })
    ])

    return verificationToken
  }

  protected async useVerificationToken<
    Payload extends Record<string, any> = Record<string, any>,
    ServerSideData extends Record<string, any> = Record<string, any>
  >(verificationToken: string): Promise<{
    payload: Payload
    serverSideData: ServerSideData
  }> {
    const payload = await this.jwt.verifyVerificationToken(verificationToken)
    const serverSideData = await this.useVerification(payload.verificationId)

    return {
      payload: payload as unknown as Payload,
      serverSideData
    }
  }

  protected async useVerification<T = any>(verificationId: string): Promise<T> {
    const verification = await this.adapter.useVerification(verificationId)

    if (verification == null || isPast(new Date(verification.expiredAt))) {
      throw new InvalidVerificationException()
    }

    return verification.data as T
  }

  async session (refreshToken: string): Promise<AuthResponse> {
    const { sessionId } = await this.jwt.verifyRefreshToken(refreshToken)
    return await this.updateSession(sessionId)
  }

  protected async createSession (
    user: UserEntity,
    extraData?: Pick<SessionEntity, 'signInIp' | 'userAgent'>
  ): Promise<AuthResponse> {
    const sessionId = randomUUID()
    const currentDate = now()

    const expiresAt = addSeconds(currentDate, this.jwt.refreshTokenMaxAge)
    const [accessToken, refreshToken] = await Promise.all([
      this.signAccessToken(user, sessionId),
      this.jwt.signRefreshToken({ subject: user.id, sessionId }),
      this.adapter.createSession({
        id: sessionId,
        counter: 0,
        createdAt: currentDate,
        expiredAt: expiresAt,
        lastActiveAt: currentDate,
        signInIp: extraData?.signInIp ?? null,
        userAgent: extraData?.userAgent ?? null,
        userId: user.id
      })
    ])

    return {
      accessToken,
      refreshToken,
      expirationTime: expiresAt.toISOString()
    }
  }

  // Todo: add counter rollback detect
  protected async updateSession (sessionId: string): Promise<AuthResponse> {
    const session = await this.adapter.getSession(sessionId)

    if (session == null || isPast(new Date(session.expiredAt))) {
      throw new InvalidSessionException()
    }

    const user = await this.adapter.getUser(session.userId)
    this.assertUserState(user)

    const [nextAccessToken, nextRefreshToken] = await Promise.all([
      this.signAccessToken(user, session.id),
      this.jwt.signRefreshToken({ subject: user.id, sessionId: session.id })
    ])

    session.counter += 1
    session.lastActiveAt = now()
    session.expiredAt = addSeconds(now(), this.jwt.refreshTokenMaxAge)

    return {
      accessToken: nextAccessToken,
      refreshToken: nextRefreshToken,
      expirationTime: session.expiredAt.toISOString()
    }
  }

  async signOut (accessToken: string): Promise<void> {
    const { sessionId } = await this.jwt.verifyAccessToken(accessToken)
    await this.adapter.deleteSession(sessionId).catch(noop)
  }

  protected async getUserOrThrow (uid: string): Promise<UserEntity> {
    const user = await this.adapter.getUser(uid)
    this.assertUserState(user)
    return user
  }

  protected assertUserState (user: unknown): asserts user is UserEntity {
    if (user == null || (user as UserEntity).state !== 'Active') {
      throw new InvalidUserException()
    }
  }

  protected async signAccessToken (user: UserEntity, sessionId: string): Promise<string> {
    const { id: subject, picture, email, emailVerified, customClaims } = user
    return await this.jwt.signAccessToken({
      ...customClaims,
      picture,
      email,
      emailVerified,
      subject,
      sessionId
    })
  }
}

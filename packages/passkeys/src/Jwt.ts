import * as jose from 'jose'
import { encodeText } from './utils/encoders'
import { randomUUID } from 'crypto'
import { type PasskeysOptions } from './Passkeys'
import { now } from './utils/datetime'
import { addSeconds, fromUnixTime, getUnixTime, hoursToSeconds, isAfter, isBefore, minutesToMilliseconds } from 'date-fns'
import { inject, Lifecycle, scoped } from 'tsyringe'
import { OPTIONS } from './constants'
import { InvalidSecretException, InvalidTokenException } from './exceptions'
import * as yup from 'yup'

/** https://www.iana.org/assignments/jwt/jwt.xhtml */
export interface JwtPayload extends jose.JWTPayload {
  /** Session ID */
  sid?: string
  /** Value used to associate a Client session with an ID Token (MAY also be used for nonce values in other applications of JWTs) */
  nonce?: string
  /** Full name */
  name?: string
  /** Preferred e-mail address */
  email?: string
  /** True if the e-mail address has been verified; otherwise false. */
  email_verified?: boolean
  /** Time when the authentication occurred. */
  auth_time?: number
}

export interface VerifyResult<Payload extends JwtPayload = JwtPayload> {
  payload: Payload
  protectedHeader: jose.JWTVerifyResult['protectedHeader']
}

export interface JwtOptions {
  accessTokenMaxAge?: number
  refreshTokenMaxAge?: number
}

export type JwtAmr = 'accessToken' | 'refreshToken' | 'verificationToken'

@scoped(Lifecycle.ContainerScoped)
export class Jwt {
  private readonly secret: Uint8Array

  readonly verificationTokenMaxAge: number

  readonly accessTokenMaxAge: number

  readonly refreshTokenMaxAge: number

  constructor (@inject(OPTIONS) private readonly options: PasskeysOptions) {
    const { secret, jwt } = options

    if (secret == null) {
      throw new InvalidSecretException()
    }

    if (secret.length < 16) {
      console.warn(
        'The Secret you provided is too weak. ' +
        'It is recommended to use a Secret of at least 16 bytes. ' +
        'You can execute the following command in the terminal to generate a secure secret: ' +
        'openssl rand -base64 32'
      )
    }

    this.secret = new Uint8Array(encodeText(options.secret))
    this.verificationTokenMaxAge = minutesToMilliseconds(10)
    this.accessTokenMaxAge = jwt?.accessTokenMaxAge ?? hoursToSeconds(1)
    this.refreshTokenMaxAge = jwt?.refreshTokenMaxAge ?? hoursToSeconds(24 * 30)
  }

  async signVerificationToken <T extends jose.JWTPayload>(
    payload: T & { verificationId: string }
  ): Promise<string> {
    const currentDate = Date.now()
    const { verificationId, ...claims } = await yup.object({
      verificationId: yup.string().required()
    }).validate(payload)

    return await new jose.SignJWT({
      ...claims,
      verificationId,
      amr: 'verificationToken'
    })
      .setExpirationTime(getUnixTime(addSeconds(currentDate, this.verificationTokenMaxAge)))
      .setIssuedAt(getUnixTime(currentDate))
      .setIssuer(this.options.origin)
      .setJti(verificationId)
      .setProtectedHeader({ alg: 'HS256' })
      .sign(this.secret)
  }

  async verifyVerificationToken <T extends jose.JWTPayload = jose.JWTPayload>(token: string): Promise<T & { verificationId: string }> {
    const { payload } = await jose.jwtVerify(token, this.secret, {
      maxTokenAge: this.verificationTokenMaxAge,
      issuer: this.options.origin
    })

    const currentDate = now()
    const response = await yup.object({
      exp: yup.number().required().test((value) => isAfter(fromUnixTime(value), currentDate)),
      iat: yup.number().required().test((value) => isBefore(fromUnixTime(value), currentDate)),
      iss: yup.string().required().test((value) => value === this.options.origin),
      jti: yup.string().required()
    }).validate(payload)

    Object.assign(response, { verificationId: response.jti })

    return response as any
  }

  async signAccessToken (payload: Record<string, any> & {
    subject: string
    sessionId: string
    issuedAt?: Date
  }): Promise<string> {
    const { subject, sessionId, issuedAt, ...claims } = await yup.object({
      subject: yup.string().required(),
      sessionId: yup.string().required(),
      issuedAt: yup.date().default(now()).optional()
    }).validate(payload)

    return await new jose.SignJWT({
      ...claims,
      sub: subject,
      sid: sessionId,
      amr: 'accessToken'
    })
      .setExpirationTime(getUnixTime(addSeconds(issuedAt, this.accessTokenMaxAge)))
      .setIssuedAt(getUnixTime(issuedAt))
      .setIssuer(this.options.origin)
      .setJti(randomUUID())
      .setProtectedHeader({ alg: 'HS256' })
      .sign(this.secret)
  }

  async verifyAccessToken (token: string, options?: {
    subject?: string
  }): Promise<{
      subject: string
      sessionId: string
    }> {
    const { payload } = await jose.jwtVerify(token, this.secret, {
      maxTokenAge: this.accessTokenMaxAge,
      subject: options?.subject,
      issuer: this.options.origin
    })

    const currentDate = now()
    const { sub: subject, sid: sessionId } = await yup.object({
      exp: yup.number().required().test((value) => isAfter(fromUnixTime(value), currentDate)),
      iat: yup.number().required().test((value) => isBefore(fromUnixTime(value), currentDate)),
      iss: yup.string().required().test((value) => value === this.options.origin),
      jti: yup.string().required().uuid(),
      sub: yup.string().required(),
      sid: yup.string().required()
    }).validate(payload)

    return {
      subject,
      sessionId
    }
  }

  async signRefreshToken (payload: {
    subject: string
    sessionId: string
    issuedAt?: Date
  }): Promise<string> {
    const { subject, sessionId, issuedAt } = await yup.object({
      subject: yup.string().required(),
      sessionId: yup.string().required(),
      issuedAt: yup.date().default(now()).optional()
    }).validate(payload)

    return await new jose.SignJWT({
      sub: subject,
      sid: sessionId,
      amr: 'refreshToken'
    })
      .setExpirationTime(getUnixTime(addSeconds(issuedAt, this.refreshTokenMaxAge)))
      .setIssuedAt(getUnixTime(issuedAt))
      .setIssuer(this.options.origin)
      .setJti(randomUUID())
      .setProtectedHeader({ alg: 'HS256' })
      .sign(this.secret)
  }

  async verifyRefreshToken (token: string, options?: {
    subject?: string
  }): Promise<{
      subject: string
      sessionId: string
    }> {
    const { payload } = await jose.jwtVerify(token, this.secret, {
      maxTokenAge: this.accessTokenMaxAge,
      subject: options?.subject,
      issuer: this.options.origin
    })

    const currentDate = now()
    const { sub: subject, sid: sessionId } = await yup.object({
      exp: yup.number().required().test((value) => isAfter(fromUnixTime(value), currentDate)),
      iat: yup.number().required().test((value) => isBefore(fromUnixTime(value), currentDate)),
      iss: yup.string().required().test((value) => value === this.options.origin),
      jti: yup.string().required().uuid(),
      sid: yup.string().required(),
      sub: yup.string().required()
    }).validate(payload)

    return {
      subject,
      sessionId
    }
  }

  async verifyToken<T = any>(token: string): Promise<T> {
    const { amr } = jose.decodeJwt(token)
    switch (amr as JwtAmr) {
      case 'accessToken':
        return this.verifyAccessToken(token) as T

      case 'refreshToken':
        return this.verifyRefreshToken(token) as T

      case 'verificationToken':
        return this.verifyVerificationToken(token) as T

      default:
        throw new InvalidTokenException()
    }
  }
}

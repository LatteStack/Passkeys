import { container } from 'tsyringe'
import { OPTIONS } from './constants'
import { Jwt } from './Jwt'

describe('Jwt', () => {
  beforeEach(() => {
    container.reset()
    container.register(Jwt, { useClass: Jwt })
    container.register(OPTIONS, {
      useValue: {
        secret: 'secret',
        origin: 'https://localhost',
        webAuthn: {

        },
        jwt: {
          accessTokenMaxAge: 3600,
          refreshTokenMaxAge: 7200
        }
      }
    })
  })

  it('should be defined', () => {
    const instance = container.resolve(Jwt)
    expect(instance).toBeDefined()
  })

  it('should throw when secret is not provided', () => {
    container.reset()
    container.register(Jwt, { useClass: Jwt })
    container.register(OPTIONS, { useValue: {} })
    expect(() => new Jwt({} as any)).toThrow()
  })

  it('should sign/verify VerificationToken correctly', async () => {
    const instance = container.resolve(Jwt)
    const payload = { a: 'b', verificationId: 'verificationId' }
    const jwt = await instance.signVerificationToken(payload)
    const res = await instance.verifyVerificationToken<typeof payload>(jwt)

    expect(res.a).toBe(payload.a)
    expect(res.verificationId).toBe(payload.verificationId)
  })

  it('should sign/verify AccessToken correctly', async () => {
    const instance = container.resolve(Jwt)
    const payload = {
      subject: 'subject',
      sessionId: 'sessionId',
      issuedAt: new Date()
    }
    const jwt = await instance.signAccessToken(payload)
    const res = await instance.verifyAccessToken(jwt, { subject: payload.subject })

    expect(res.subject).toBe(payload.subject)
    expect(res.sessionId).toBe(payload.sessionId)
  })

  it('should sign/verify RefreshToken correctly', async () => {
    const instance = container.resolve(Jwt)
    const payload = {
      subject: 'subject',
      sessionId: 'sessionId',
      issuedAt: new Date()
    }
    const jwt = await instance.signRefreshToken(payload)
    const res = await instance.verifyRefreshToken(jwt, { subject: payload.subject })

    expect(res.subject).toBe(payload.subject)
    expect(res.sessionId).toBe(payload.sessionId)
  })
})

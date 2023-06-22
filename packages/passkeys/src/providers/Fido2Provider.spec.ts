/* eslint-disable @typescript-eslint/no-floating-promises */
import Database from 'better-sqlite3'
import { addSeconds } from 'date-fns'
import { container, type InjectionToken } from 'tsyringe'
import { createConnection, type DataSource } from 'typeorm'
import { Adapter, type VerificationEntity } from '../adapters/Adapter'
import { TypeOrmAdapter, typeOrmEntities } from '../adapters/TypeOrmAdapter'
import { OPTIONS } from '../constants'
import { type PasskeysOptions } from '../Passkeys'
import { Fido2Provider } from './Fido2Provider'

class MockTypeOrmAdapter extends TypeOrmAdapter {
  override async useVerification (verificationId: string): Promise<VerificationEntity> {
    return {
      id: verificationId,
      data: {},
      createdAt: new Date(),
      expiredAt: addSeconds(new Date(), 60)
    }
  }
}

describe('Fido2Provider', () => {
  let db!: Database.Database
  let dataSource!: DataSource

  beforeAll(async () => {
    const options: PasskeysOptions = {
      secret: 'sYZFzTDSBZPNmGz2mzEd2bVnsB+kkEKB1nqPqUPOv90=',
      origin: 'http://localhost:3000'
    }

    db = new Database(':memory:', { verbose: console.log })
    dataSource = await createConnection({
      name: 'default',
      type: 'better-sqlite3',
      database: ':memory:',
      entities: typeOrmEntities
    })

    const adapter = new MockTypeOrmAdapter(dataSource)

    container.register(OPTIONS, { useValue: options })
    container.register(Adapter as InjectionToken, { useValue: adapter })
  })

  afterAll(async () => {
    await dataSource.dropDatabase()
    await dataSource.destroy()
    db.close()
  })

  it('should be defined', () => {
    const instance = container.resolve(Fido2Provider)
    expect(instance).toBeDefined()
  })

  it('It should correctly return the challenge', async () => {
    const instance = container.resolve(Fido2Provider)
    const response = await instance.challenge({ email: 'xxx@lattestack.com' })

    expect(response.options).toBeDefined()

    // {
    //   options: {
    //     rp: {
    //       name: 'Anonymous App'
    //     },
    //     user: {
    //       id: 'f6b357b8-78a6-4fb5-9dbd-2ffcd0b06223',
    //       name: 'xxx@lattestack.com',
    //       displayName: 'xxx'
    //     },
    //     challenge: 'ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKMGVYQmxJam9pZDJWaVlYVjBhRzR1WTNKbFlYUmxJaXdpYzNWaWFtVmpkQ0k2SW1ZMllqTTFOMkk0TFRjNFlUWXROR1ppTlMwNVpHSmtMVEptWm1Oa01HSXdOakl5TXlJc0ltVnRZV2xzSWpvaWVIaDRRR3hoZEhSbGMzUmhZMnN1WTI5dElpd2laWGh3SWpveE5qZzNPRGsyTWprekxDSnBZWFFpT2pFMk9EY3lPVFl5T1RNc0ltbHpjeUk2SW1oMGRIQTZMeTlzYjJOaGJHaHZjM1E2TXpBd01DSXNJbXAwYVNJNklqWTFNR1V6TjJaaExUbGhOVEl0TkdRMFppMDVPRE14TFRoa01UWXhZak15TmpCa09TSjkubVpYeHRfLUd0MmcxdWw4UDA5YzJQcW1CNG9OTm5IMGhyR0lERjh2Zm42OA',
    //     pubKeyCredParams: [
    //       {
    //         type: 'public-key',
    //         alg: -7
    //       },
    //       {
    //         type: 'public-key',
    //         alg: -257
    //       }
    //     ],
    //     timeout: 600000,
    //     excludeCredentials: [],
    //     authenticatorSelection: {
    //       authenticatorAttachment: 'platform',
    //       userVerification: 'required'
    //     },
    //     attestation: 'none'
    //   }
    // }
  })

  let refreshToken!: string
  let accessToken!: string

  it('It should correctly return the challenge', async () => {
    const instance = container.resolve(Fido2Provider)
    const response = await instance.signIn({
      credential: {
        type: 'public-key',
        id: 'sTW6rb6cB7n_hC0iFNDWTP1f4DjhKs8L9X4Hd1BTxuo',
        rawId: 'sTW6rb6cB7n_hC0iFNDWTP1f4DjhKs8L9X4Hd1BTxuo',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWlhsS2FHSkhZMmxQYVVwSlZYcEpNVTVwU2prdVpYbEtNR1ZZUW14SmFtOXBaREpXYVZsWVZqQmhSelIxV1ROS2JGbFlVbXhKYVhkcFl6TldhV0Z0Vm1wa1EwazJTVzFaTWxscVRURk9Na2swVEZSak5GbFVXWFJPUjFwcFRsTXdOVnBIU210TVZFcHRXbTFPYTAxSFNYZE9ha2w1VFhsSmMwbHRWblJaVjJ4elNXcHZhV1ZJYURSUlIzaG9aRWhTYkdNelVtaFpNbk4xV1RJNWRFbHBkMmxhV0doM1NXcHZlRTVxWnpOUFJHc3lUV3ByZWt4RFNuQlpXRkZwVDJwRk1rOUVZM2xQVkZsNVQxUk5jMGx0YkhwamVVazJTVzFvTUdSSVFUWk1lVGx6WWpKT2FHSkhhSFpqTTFFMlRYcEJkMDFEU1hOSmJYQXdZVk5KTmtscVdURk5SMVY2VGpKYWFFeFViR2hPVkVsMFRrZFJNRnBwTURWUFJFMTRURlJvYTAxVVdYaFphazE1VG1wQ2EwOVRTamt1YlZwWWVIUmZMVWQwTW1jeGRXdzRVREE1WXpKUWNXMUNORzlPVG01SU1HaHlSMGxFUmpoMlptNDJPQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
          attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAILE1uq2-nAe5_4QtIhTQ1kz9X-A44SrPC_V-B3dQU8bqpQECAyYgASFYICLIyKQn5nd7HNALvFYaEWyT6t9kjS1TiVGVGLZY2LFDIlgg6m1HX3o2zwRUkJAP5Y65W5mxkXGvmPxw1BLHJgF8fOc',
          transports: [
            'internal'
          ]
        },
        clientExtensionResults: {}
      }
    })

    expect(response.accessToken).toBeDefined()
    expect(response.refreshToken).toBeDefined()
    expect(response.expirationTime).toBeDefined()

    refreshToken = response.refreshToken
    accessToken = response.accessToken
  })

  it('should correctly verify refreshToken and return tokens', async () => {
    const instance = container.resolve(Fido2Provider)

    const response = await instance.session({ refreshToken })
    expect(response).toBeDefined()
  })

  it('should signOut correctly', async () => {
    const instance = container.resolve(Fido2Provider)
    expect(instance.signOut(accessToken)).resolves.not.toThrow()
  })
})

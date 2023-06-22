import Database from 'better-sqlite3'
import { addSeconds } from 'date-fns'
import { container, type InjectionToken } from 'tsyringe'
import { createConnection, type DataSource } from 'typeorm'
import { Adapter, type VerificationEntity } from '../adapters/Adapter'
import { TypeOrmAdapter, typeOrmEntities } from '../adapters/TypeOrmAdapter'
import { EMAIL_LINK_OPTIONS, OPTIONS } from '../constants'
import { type PasskeysOptions } from '../Passkeys'
import { EmailLinkProvider, type EmailLinkProviderOptions } from './EmailLinkProvider'

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

describe('EmailLinkProvider', () => {
  let db!: Database.Database
  let dataSource!: DataSource
  let verificationToken!: string

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
    const emailLinkProviderOptions: EmailLinkProviderOptions = {
      server: {},
      async sendSignInLinkToEmail (params) {
        const url = new URL(params.url)
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        verificationToken = url.searchParams.get('verification_token')!
      }
    }

    container.register(OPTIONS, { useValue: options })
    container.register(EMAIL_LINK_OPTIONS as InjectionToken, { useValue: emailLinkProviderOptions })
    container.register(Adapter as InjectionToken, { useValue: adapter })
  })

  afterAll(async () => {
    await dataSource.dropDatabase()
    await dataSource.destroy()
    db.close()
  })

  it('should be defined', () => {
    const instance = container.resolve(EmailLinkProvider)
    expect(instance).toBeDefined()
  })

  it('It should correctly return the challenge', async () => {
    const instance = container.resolve(EmailLinkProvider)
    const response = await instance.challenge({
      email: 'xxx@lattestack.com',
      url: 'https://passkeys.lattestack.com/login?xxx=yyy#login'
    })
    console.log('response', typeof Request, typeof Response, typeof Blob)

    expect(response).toBeDefined()
  })

  let refreshToken!: string

  it('should correctly verify verificationToken and return tokens', async () => {
    const instance = container.resolve(EmailLinkProvider)
    const response = await instance.signIn({ verificationToken })

    expect(response.accessToken).toBeDefined()
    expect(response.refreshToken).toBeDefined()
    expect(response.expirationTime).toBeDefined()

    refreshToken = response.refreshToken
  })

  it('should correctly verify refreshToken and return tokens', async () => {
    const instance = container.resolve(EmailLinkProvider)

    const response = await instance.session({ refreshToken })
    expect(response).toBeDefined()
  })
})

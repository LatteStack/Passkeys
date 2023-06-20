/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable @typescript-eslint/no-floating-promises */
import { randomUUID } from 'crypto'
import { createConnection, type DataSource } from 'typeorm'
import Database from 'better-sqlite3'
import {
  type SessionEntity,
  type CredentialEntity,
  type UserEntity,
  type VerificationEntity
} from './Adapter'
import {
  TypeOrmUserEntity,
  TypeOrmCredentialEntity,
  TypeOrmSessionEntity,
  TypeOrmVerificationEntity,
  TypeOrmAdapter
} from './TypeOrmAdapter'
import { InvalidVerificationException } from '../exceptions'

describe('TypeormAdapter', () => {
  let db!: Database.Database
  let dataSource!: DataSource
  let adapter!: TypeOrmAdapter

  beforeAll(async () => {
    db = new Database(':memory:', { verbose: console.log })
    dataSource = await createConnection({
      name: 'default',
      type: 'better-sqlite3',
      database: ':memory:',
      entities: [
        TypeOrmUserEntity,
        TypeOrmCredentialEntity,
        TypeOrmSessionEntity,
        TypeOrmVerificationEntity
      ]
    })

    adapter = new TypeOrmAdapter(dataSource)

    if (!adapter.dataSource.manager.connection.isInitialized) {
      await adapter.dataSource.manager.connection.initialize()
    }
  })

  afterAll(async () => {
    await dataSource.dropDatabase()
    await dataSource.destroy()
    db.close()
  })

  beforeEach(async () => {
    // await adapter.dataSource.dropDatabase()
    // await adapter.dataSource.synchronize()
  })

  it('should be defined', () => {
    expect(adapter).toBeDefined()
  })

  describe('users', () => {
    const userId = randomUUID()
    const userToCreate: UserEntity = {
      id: userId,
      state: 'Active',
      name: null,
      email: 'xxx@lattestack.com',
      emailVerified: false,
      picture: null,
      createdAt: new Date(),
      customClaims: {}
    }

    beforeAll(async () => {
      await adapter.createUser(userToCreate)
    })

    it('should create user correctly', async () => {
      const user = await adapter.createUser(userToCreate)
      expect(user).toEqual(userToCreate)
    })

    it('should get user correctly', async () => {
      const user = await adapter.getUser(userId)
      expect(user).toEqual(userToCreate)
    })

    it('should update user correctly', async () => {
      const userToUpdate: UserEntity = { ...userToCreate, email: 'yyy@lattestack.com' }
      await adapter.updateUser(userToUpdate)
      const nextUser = await adapter.getUser(userToUpdate.id)
      expect(nextUser).toEqual(userToUpdate)
    })

    it('should delete user correctly', async () => {
      await adapter.deleteUser(userToCreate.id)
      const user = await adapter.getUser(userToCreate.id)
      expect(user).toBeNull()
    })

    it('should throw when two users have the same email', async () => {
      const sameEmail = 'same@lattestack.com'

      await adapter.createUser({
        ...userToCreate,
        id: randomUUID(),
        email: sameEmail
      })

      expect(
        adapter.createUser({
          ...userToCreate,
          id: randomUUID(),
          email: sameEmail
        })
      ).rejects.toThrow()
    })
  })

  describe('sessions', () => {
    const userId = randomUUID()
    const sessionId = randomUUID()
    const sessionToCreate: SessionEntity = {
      id: sessionId,
      counter: 0,
      createdAt: new Date(),
      expiredAt: new Date(),
      lastActiveAt: new Date(),
      signInIp: null,
      userAgent: null,
      userId
    }

    beforeAll(async () => {
      await adapter.createSession(sessionToCreate)
    })

    it('should create session correctly', async () => {
      const session = await adapter.createSession(sessionToCreate)
      expect(session).toEqual(sessionToCreate)
    })

    it('should get session correctly', async () => {
      const session = await adapter.getSession(sessionId)
      expect(session).toEqual(sessionToCreate)
    })

    it('should correctly get sessions by user id', async () => {
      const sessions = await adapter.getSessionsByUserId(userId)
      expect(sessions.length).toBeGreaterThan(0)
    })

    it('should update session correctly', async () => {
      const sessionToUpdate: SessionEntity = { ...sessionToCreate, counter: 2 }
      await adapter.updateSession(sessionToUpdate)
      const nextSession = await adapter.getSession(sessionToUpdate.id)
      expect(nextSession).toEqual(sessionToUpdate)
    })

    it('should delete session correctly', async () => {
      await adapter.deleteUser(sessionToCreate.id)
      const session = await adapter.getUser(sessionToCreate.id)
      expect(session).toBeNull()
    })
  })

  describe('credentials', () => {
    const userId = randomUUID()
    const credentialId = randomUUID()
    const credentialToCreate: CredentialEntity = {
      id: credentialId,
      counter: 0,
      transports: ['internal', 'ble'],
      publicKey: 'publicKey',
      userHandle: null,
      createdAt: new Date(),
      userId
    }

    beforeAll(async () => {
      await adapter.createCredential(credentialToCreate)
    })

    it('should create credential correctly', async () => {
      const credential = await adapter.createCredential(credentialToCreate)
      expect(credential).toEqual(credentialToCreate)
    })

    it('should get credential correctly', async () => {
      const credential = await adapter.getCredential(credentialId)
      expect(credential).toEqual(credentialToCreate)
    })

    it('should correctly get credentials by user id', async () => {
      const credentials = await adapter.getCredentialsByUserId(userId)
      expect(credentials.length).toBeGreaterThan(0)
    })

    it('should update credential correctly', async () => {
      const credentialToUpdate: CredentialEntity = { ...credentialToCreate, counter: 2 }
      await adapter.updateCredential(credentialToUpdate)
      const nextCredential = await adapter.getCredential(credentialToUpdate.id)
      expect(nextCredential).toEqual(credentialToUpdate)
    })

    it('should delete credential correctly', async () => {
      await adapter.deleteUser(credentialToCreate.id)
      const credential = await adapter.getUser(credentialToCreate.id)
      expect(credential).toBeNull()
    })
  })

  describe('verifications', () => {
    const verificationId = randomUUID()
    const verificationToCreate: VerificationEntity = {
      id: verificationId,
      createdAt: new Date(),
      data: { x: randomUUID() },
      expiredAt: new Date()
    }

    beforeAll(async () => {
      await adapter.createVerification(verificationToCreate)
    })

    it('should create verification correctly', async () => {
      const verification = await adapter.createVerification(verificationToCreate)
      expect(verification).toEqual(verificationToCreate)
    })

    it('should use verification correctly', async () => {
      const verification = await adapter.useVerification(verificationId)

      expect(verification).toEqual(verificationToCreate)
      expect(adapter.useVerification(verificationId)).rejects.toThrow(
        InvalidVerificationException
      )
    })
  })
})

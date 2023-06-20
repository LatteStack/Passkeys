/* eslint-disable @typescript-eslint/no-invalid-void-type */
/* eslint-disable @typescript-eslint/ban-ts-comment */
import { difference } from 'lodash'
import {
  Column,
  DataSource,
  type DataSourceOptions,
  Entity,
  PrimaryColumn,
  type EntityManager,
  type ValueTransformer
} from 'typeorm'
import { InvalidVerificationException } from '../exceptions'
import { type AuthenticatorTransportJSON } from '../types'
import {
  type UserEntity,
  type Adapter,
  type SessionEntity,
  type VerificationEntity,
  type CredentialEntity
} from './Adapter'

// declare const process: {
//   env: {
//     NODE_ENV: string
//   }
// }

const transformer: Record<'date', ValueTransformer> = {
  date: {
    from: (date: string | null) => date != null ? new Date(date) : null,
    to: (date?: Date) => date?.toISOString()
  }
}

const TableNames = {
  Users: 'passkeys_users',
  Sessions: 'passkeys_sessions',
  Credentials: 'passkeys_credentials',
  Verifications: 'passkeys_verifications'
} as const

@Entity({ name: TableNames.Users })
export class TypeOrmUserEntity implements UserEntity {
  @PrimaryColumn()
    id!: string

  @Column({ type: 'varchar' })
    state!: | 'Active' | 'Disabled'

  @Column({ type: 'varchar', nullable: true })
    name!: string | null

  @Column({ type: 'varchar', nullable: true, unique: true })
    email!: string | null

  @Column({ type: 'boolean' })
    emailVerified!: boolean

  @Column({ type: 'text', nullable: true })
    picture!: string | null

  @Column({ type: 'varchar', transformer: transformer.date })
    createdAt!: Date

  @Column({ type: 'varchar', nullable: true })
    lastSignInTime!: Date | null

  @Column({ type: 'simple-json' })
    customClaims!: Record<string, any>
}

@Entity({ name: TableNames.Sessions })
export class TypeOrmSessionEntity implements SessionEntity {
  @PrimaryColumn()
    id!: string

  @Column({ type: 'integer' })
    counter!: number

  @Column({ type: 'varchar', transformer: transformer.date })
    createdAt!: Date

  @Column({ type: 'varchar', transformer: transformer.date })
    expiredAt!: Date

  @Column({ type: 'varchar', nullable: true, transformer: transformer.date })
    lastActiveAt!: Date

  @Column({ type: 'varchar', nullable: true })
    signInIp!: string | null

  @Column({ type: 'text', nullable: true })
    userAgent!: string | null

  @Column({ type: 'varchar' })
    userId!: string
}

@Entity({ name: TableNames.Credentials })
export class TypeOrmCredentialEntity implements CredentialEntity {
  @PrimaryColumn()
    id!: string

  @Column({ type: 'simple-array' })
    transports!: AuthenticatorTransportJSON[]

  @Column({ type: 'integer', unsigned: true })
    counter!: number

  @Column()
    publicKey!: string

  @Column({ type: 'varchar', nullable: true })
    userHandle!: string | null

  @Column({ type: 'varchar', transformer: transformer.date })
    createdAt!: Date

  @Column({ type: 'varchar' })
    userId!: string
}

@Entity({ name: TableNames.Verifications })
export class TypeOrmVerificationEntity implements VerificationEntity {
  @PrimaryColumn()
    id!: string

  @Column({ type: 'simple-json' })
    data!: Record<string, any>

  @Column({ type: 'varchar', transformer: transformer.date })
    expiredAt!: Date

  @Column({ type: 'varchar', transformer: transformer.date })
    createdAt!: Date
}

export class TypeOrmAdapter implements Adapter {
  private isInitialized = false

  constructor (public readonly dataSource: DataSource) {}

  async getUserByEmail (email: string): Promise<UserEntity | null> {
    const manager = await this.getManager()
    return await manager.findOne(TypeOrmUserEntity, { where: { email } })
  }

  async createUser (user: UserEntity): Promise<UserEntity> {
    const manager = await this.getManager()
    return await manager.save(TypeOrmUserEntity, user)
  }

  async getUser (userId: string): Promise<UserEntity | null> {
    const manager = await this.getManager()
    return await manager.findOne(TypeOrmUserEntity, { where: { id: userId } })
  }

  async updateUser (user: Partial<UserEntity>): Promise<UserEntity | void> {
    const manager = await this.getManager()
    await manager.update(TypeOrmUserEntity, user.id, user)
  }

  async deleteUser (userId: string): Promise<UserEntity | void> {
    const manager = await this.getManager()
    await manager.delete(TypeOrmUserEntity, userId)
  }

  async createCredential (credential: CredentialEntity): Promise<CredentialEntity | void> {
    const manager = await this.getManager()
    return await manager.save(TypeOrmCredentialEntity, credential)
  }

  async getCredential (credentialId: string): Promise<CredentialEntity | null> {
    const manager = await this.getManager()
    return await manager.findOne(TypeOrmCredentialEntity, { where: { id: credentialId } })
  }

  async updateCredential (credential: Partial<CredentialEntity>): Promise<CredentialEntity | void> {
    const manager = await this.getManager()
    await manager.update(TypeOrmCredentialEntity, credential.id, credential)
  }

  async deleteCredential (credentialId: string): Promise<CredentialEntity | void> {
    const manager = await this.getManager()
    await manager.delete(TypeOrmCredentialEntity, credentialId)
  }

  async createSession (session: SessionEntity): Promise<SessionEntity> {
    const manager = await this.getManager()
    return await manager.save(TypeOrmSessionEntity, session)
  }

  async getSession (sessionId: string): Promise<SessionEntity | null> {
    const manager = await this.getManager()
    return await manager.findOne(TypeOrmSessionEntity, { where: { id: sessionId } })
  }

  async updateSession (session: Partial<SessionEntity>): Promise<SessionEntity | void> {
    const manager = await this.getManager()
    await manager.update(TypeOrmSessionEntity, session.id, session)
  }

  async deleteSession (sessionId: string): Promise<SessionEntity | void> {
    const manager = await this.getManager()
    await manager.delete(TypeOrmSessionEntity, sessionId)
  }

  async createVerification (verification: VerificationEntity): Promise<VerificationEntity> {
    const manager = await this.getManager()
    // @ts-expect-error
    return await manager.save(TypeOrmVerificationEntity, verification)
  }

  async useVerification (verificationId: string): Promise<VerificationEntity> {
    const manager = await this.getManager()
    return await manager.transaction<VerificationEntity>(async (entityManager) => {
      const verification = await entityManager.findOne(TypeOrmVerificationEntity, {
        where: { id: verificationId }
      })

      if (verification == null) {
        throw new InvalidVerificationException()
      }

      await entityManager.delete(TypeOrmVerificationEntity, verificationId)

      return verification
    })
  }

  async getManager (): Promise<EntityManager> {
    await this.initializeIfNeeded()

    const manager = this.dataSource.manager

    if (manager == null) {
      throw new Error('Can not get manager before connection is available.')
    }

    return manager
  }

  private async initializeIfNeeded (): Promise<void> {
    if (!this.dataSource.manager.connection.isInitialized) {
      await this.dataSource.manager.connection.initialize()
    }

    if (!this.isInitialized) {
      const queryRunner = this.dataSource.createQueryRunner()

      try {
        const excepedTables = Object.values(TableNames)
        const existingTables = await Promise.all(
          excepedTables.map<Promise<string>>(async (tableName) => {
            const hasTable = await queryRunner.hasTable(tableName)
            return hasTable ? tableName : ''
          })
        )
          .then<string[]>((tableNames) => {
          return tableNames.filter(Boolean)
        })

        if (existingTables.length !== excepedTables.length) {
          if (existingTables.length === 0) {
            await this.dataSource.synchronize()
          } else {
            const missingTables = difference(excepedTables, existingTables)

            throw new class MissingTablesException extends Error {
              override name = 'missing-tables'
              override message = `Missing following tables: ${missingTables.join(',')}`
            }()
          }
        }

        this.isInitialized = true
      } finally {
        await queryRunner.release()
      }
    }
  }

  static create (
    dataSourceOptions: DataSourceOptions
  ): TypeOrmAdapter {
    const dataSource = new DataSource({
      ...dataSourceOptions,
      entities: [
        TypeOrmUserEntity,
        TypeOrmCredentialEntity,
        TypeOrmSessionEntity,
        TypeOrmVerificationEntity
      ]
    })

    return new TypeOrmAdapter(dataSource)
  }
}

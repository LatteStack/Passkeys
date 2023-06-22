import { InvalidEmailException } from '../exceptions'

export * from './datetime'
export * from './encoders'

export function normalizeEmail (email: string): string {
  if (typeof email !== 'string') {
    throw new InvalidEmailException()
  }

  const [name = '', provider = ''] = email.trim().split('@')

  if (name.length === 0 || provider.length === 0) {
    throw new InvalidEmailException()
  }

  const normalizedName = name.toLowerCase()
  const normalizedEmail = `${normalizedName}@${provider}`

  return normalizedEmail
}

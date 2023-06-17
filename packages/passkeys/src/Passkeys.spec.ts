/* eslint-disable @typescript-eslint/no-extraneous-class */
import { randomUUID } from 'crypto'
import { container } from 'tsyringe'
import { Passkeys, type PasskeysOptions } from './Passkeys'

const defaultOptions: PasskeysOptions = {
  secret: randomUUID(),
  origin: 'http://localhost:3000'
}

describe('Passkeys', () => {
  beforeEach(() => {
    container.reset()
  })

  it('should be defined', () => {
    const passkeys = Passkeys.create(defaultOptions)

    expect(passkeys).toBeDefined()
  })

  it('should can register services', () => {
    const passkeys = Passkeys.create(defaultOptions)

    class Test {}

    passkeys.use([
      { token: 'a', useValue: 'a' },
      { token: 'b', useFactory: () => 'b' },
      { token: 'c', useClass: Test },
      { token: 'd', useToken: Test }
    ])

    expect(passkeys.has('a')).toBeTruthy()
    expect(passkeys.get('a')).toBe('a')
    expect(passkeys.get('b')).toBe('b')
    expect(passkeys.get('c') instanceof Test).toBe(true)
    expect(passkeys.get('d') instanceof Test).toBe(true)
  })
})

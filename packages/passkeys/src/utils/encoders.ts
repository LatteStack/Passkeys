import { Buffer } from 'buffer'

export function encodeText (input?: string): ArrayBuffer {
  return new TextEncoder().encode(input)
}

export function decodeText (input?: BufferSource): string {
  return new TextDecoder().decode(input)
}

export function toBase64Url (input: string): string {
  return Buffer.from(input).toString('base64url')
}

export function fromBase64Url (input: string): ArrayBuffer {
  return new Uint8Array(Buffer.from(input, 'base64url')).buffer
}

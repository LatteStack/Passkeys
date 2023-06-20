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

export function base64urlToPlain (input: string): string {
  return new TextDecoder().decode(
    fromBase64Url(input)
  )
}

export function parseClientDataJSON (clientDataJSON: string): unknown {
  return JSON.parse(
    new TextDecoder('utf-8').decode(
      fromBase64Url(clientDataJSON)
    )
  )
}

export function extractChallengeFromClientDataJSON (clientDataJSON: string): string {
  const clientData = parseClientDataJSON(clientDataJSON)

  if (typeof clientData === 'object') {
    if (clientData != null) {
      return (clientData as any).challenge
    }
  }

  return ''
}

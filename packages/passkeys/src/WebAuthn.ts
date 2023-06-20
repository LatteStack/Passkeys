import {
  Fido2Lib,
  type Fido2LibOptions,
  type Factor
} from 'fido2-lib'
import {
  type PublicKeyCredentialRequestOptionsJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialWithAttestationJSON,
  type PublicKeyCredentialWithAssertionJSON,
  type PublicKeyCredentialUserEntityJSON,
  type PublicKeyCredentialDescriptorJSON
} from './types'
import { merge } from 'lodash'
import { minutesToMilliseconds } from 'date-fns'
import { encodeText, fromBase64Url, toBase64Url } from './utils/encoders'
import { inject, Lifecycle, scoped } from 'tsyringe'
import * as yup from 'yup'
import { PasskeysOptions } from './Passkeys'
import { OPTIONS } from './constants'

export interface AttestationResult {
  credId: string
  publicKey: string
  counter: number
  userHandle: string | null
  transports: string[] | null
}

export interface AssertionResult {
  counter: number
  userHandle: string | null
}

function addTypeToDescriptors (
  descriptors: Array<Omit<PublicKeyCredentialDescriptorJSON, 'type'>>
): PublicKeyCredentialDescriptorJSON[] {
  return descriptors.map<PublicKeyCredentialDescriptorJSON>((descriptor) => ({
    ...descriptor,
    type: 'public-key'
  }))
}

@scoped(Lifecycle.ContainerScoped)
export class WebAuthn {
  private readonly fido2Lib: Fido2Lib

  private readonly timeout: number = minutesToMilliseconds(10)

  private readonly attestation: AttestationConveyancePreference = 'none'

  private readonly authenticatorSelection: AuthenticatorSelectionCriteria = {
    authenticatorAttachment: 'platform',
    userVerification: 'required'
  }

  private readonly rp: PublicKeyCredentialRpEntity = { name: 'Anonymous App' }

  constructor (@inject(OPTIONS) private readonly options: PasskeysOptions) {
    const { webAuthn } = options

    if (webAuthn?.attestation != null) {
      this.attestation = webAuthn.attestation
    }

    if (webAuthn?.authenticatorSelection != null) {
      this.authenticatorSelection = merge(
        this.authenticatorSelection,
        webAuthn.authenticatorSelection
      )
    }

    if (webAuthn?.rp != null) {
      this.rp = merge(this.rp, webAuthn.rp)
    }

    this.fido2Lib = new Fido2Lib({
      timeout: this.timeout,
      rpId: this.rp.id,
      rpName: this.rp.name,
      challengeSize: 128,
      authenticatorAttachment: this.authenticatorSelection?.authenticatorAttachment,
      authenticatorRequireResidentKey: this.authenticatorSelection?.requireResidentKey,
      authenticatorUserVerification: this.authenticatorSelection?.userVerification ?? 'required',
      attestation: this.attestation as Fido2LibOptions['attestation'] ?? 'none',
      cryptoParams: webAuthn?.pubKeyCredParams?.map(({ alg }) => alg)
    })
  }

  async createCreationOptions (options: {
    challenge: string
    user: PublicKeyCredentialUserEntityJSON
    excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptorJSON, 'type'>>
  }): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const optionsFromFido2Lib = await this.fido2Lib.attestationOptions()

    return {
      rp: optionsFromFido2Lib.rp,
      user: options.user,
      challenge: toBase64Url(options.challenge),
      pubKeyCredParams: optionsFromFido2Lib.pubKeyCredParams,
      timeout: optionsFromFido2Lib.timeout,
      excludeCredentials: addTypeToDescriptors(options.excludeCredentials ?? []),
      authenticatorSelection: optionsFromFido2Lib.authenticatorSelection,
      attestation: optionsFromFido2Lib.attestation
      // extensions: optionsFromFido2Lib.extensions ?? []
    }
  }

  async verifyAttestation (
    attestation: PublicKeyCredentialWithAttestationJSON,
    expectedAttestation: {
      challenge: string
      factor?: Factor
    }
  ): Promise<AttestationResult> {
    const { audit, authnrData } = await this.fido2Lib.attestationResult(
      {
        id: encodeText(attestation.id),
        rawId: fromBase64Url(attestation.rawId),
        transports: attestation.response.transports,
        response: {
          clientDataJSON: attestation.response.clientDataJSON,
          attestationObject: attestation.response.attestationObject
        }
      },
      {
        rpId: this.rp.id,
        origin: this.options.origin,
        challenge: expectedAttestation.challenge,
        factor: expectedAttestation.factor ?? 'either'
      }
    )

    await yup.object({
      complete: yup.bool().required().isTrue(),
      validRequest: yup.bool().required().isTrue(),
      validExpectations: yup.bool().required().isTrue()
    }).validate(audit)

    const { credId, publicKey, counter, userHandle, transports } = await yup.object({
      credId: yup.string().required(),
      publicKey: yup.string().required(),
      userHandle: yup.string().nullable().default(null),
      counter: yup.number().required(),
      transports: yup.array().of(yup.string().required()).optional().default([])
    }).validate({
      credId: toBase64Url(authnrData.get('credId')),
      publicKey: authnrData.get('credentialPublicKeyPem'),
      counter: authnrData.get('counter'),
      transports: authnrData.get('transports'),
      userHandle: authnrData.get('userHandle') != null
        ? toBase64Url(authnrData.get('userHandle'))
        : null
    })

    return {
      credId,
      publicKey,
      counter,
      userHandle,
      transports
    }
  }

  async createRequestOptions (options: {
    challenge: string
    allowCredentials?: Array<Omit<PublicKeyCredentialDescriptorJSON, 'type'>>
  }): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const optionsFromFido2Lib = await this.fido2Lib.assertionOptions()
    return {
      challenge: toBase64Url(options.challenge),
      rpId: optionsFromFido2Lib.rpId,
      userVerification: optionsFromFido2Lib.userVerification,
      timeout: optionsFromFido2Lib.timeout,
      allowCredentials: addTypeToDescriptors(options.allowCredentials ?? [])
      // extensions: optionsFromFido2Lib.extensions ?? []
    }
  }

  async verifyAssertion (
    assertion: PublicKeyCredentialWithAssertionJSON,
    expectedAssertion: {
      challenge: string
      factor?: Factor
      publicKey: string
      counter: number
      userHandle: string | null
      allowCredentials?: PublicKeyCredentialDescriptor[]
    }
  ): Promise<AssertionResult> {
    const { audit, authnrData } = await this.fido2Lib.assertionResult(
      {
        id: encodeText(assertion.id),
        rawId: fromBase64Url(assertion.rawId),
        response: {
          clientDataJSON: assertion.response.clientDataJSON,
          authenticatorData: fromBase64Url(assertion.response.authenticatorData),
          signature: assertion.response.signature,
          userHandle: assertion.response.userHandle ?? undefined
        }
      },
      {
        rpId: this.rp.id,
        challenge: expectedAssertion.challenge,
        origin: this.options.origin,
        factor: expectedAssertion.factor ?? 'either',
        publicKey: expectedAssertion.publicKey,
        prevCounter: expectedAssertion.counter,
        userHandle: expectedAssertion.userHandle
      }
    )

    await yup.object({
      complete: yup.bool().required().isTrue(),
      validRequest: yup.bool().required().isTrue(),
      validExpectations: yup.bool().required().isTrue()
    }).validate(audit)

    const { userHandle, nextCounter } = await yup.object({
      userHandle: yup.string().nullable().default(null),
      nextCounter: yup.number().required().test((value) => {
        return value > expectedAssertion.counter
      })
    }).validate({
      nextCounter: authnrData.get('counter'),
      userHandle: authnrData.get('userHandle') != null
        ? toBase64Url(authnrData.get('userHandle'))
        : null
    })

    return {
      userHandle,
      counter: nextCounter
    }
  }
}

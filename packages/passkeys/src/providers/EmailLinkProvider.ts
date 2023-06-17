import { Provider } from './Provider'
import * as nodemailer from 'nodemailer'
import type { Options as SMTPTransportOptions } from 'nodemailer/lib/smtp-transport'
import { inject, Lifecycle, scoped } from 'tsyringe'
import { type InjectionProvider } from '../types'
import { OPTIONS } from '../constants'
import { PasskeysOptions } from '../Passkeys'
import { Adapter } from '../Adapter'
import { Jwt } from '../Jwt'

const EMAIL_LINK_OPTIONS = Symbol('EMAIL_LINK_OPTIONS')

export interface EmailLinkProviderOptions {
  server: SMTPTransportOptions
}

@scoped(Lifecycle.ContainerScoped)
export class EmailLinkProvider extends Provider {
  constructor (
    @inject(OPTIONS) protected override readonly options: PasskeysOptions,
    protected override readonly adapter: Adapter,
    protected override readonly jwt: Jwt,
    @inject(EMAIL_LINK_OPTIONS) private readonly emailLinkOptions: EmailLinkProviderOptions
  ) {
    super(options, adapter, jwt)
  }

  // challenge
  // signIn
  // signOut

  static create(emailLinkOptions: EmailLinkProviderOptions): EmailLinkProvider {
    //
  }
}


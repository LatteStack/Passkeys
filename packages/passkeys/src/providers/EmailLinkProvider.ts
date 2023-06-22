import * as tsyringe from 'tsyringe'
import { Provider } from './Provider'
import { createTransport } from 'nodemailer'
import type { Options as SMTPTransportOptions } from 'nodemailer/lib/smtp-transport'
import { inject, Lifecycle, scoped } from 'tsyringe'
import { EMAIL_LINK_OPTIONS, OPTIONS } from '../constants'
import { PasskeysOptions } from '../Passkeys'
import { Adapter } from '../adapters/Adapter'
import { Jwt } from '../Jwt'
import { randomUUID } from 'crypto'
import { InvalidUrlException } from '../exceptions'
import { type AuthResponse } from '../types'
import * as yup from 'yup'
import { render } from 'mustache'
import { normalizeEmail } from '../utils'

export interface EmailLinkProviderOptions {
  server: SMTPTransportOptions
  /** @default "NextAuth <no-reply@example.com>" */
  from?: string
  sendSignInLinkToEmail?: (params: {
    url: string
    providerOptions: EmailLinkProviderOptions
  }) => Promise<any>
}

export interface EmailLinkChallengeRequest {
  email: string
  url: string
}

export type EmailLinkChallengeResponse = Record<string, any>

interface ChallengePayload {
  verificationId: string
  subject: string
  email: string
}

export interface EmailLinkSignInRequest {
  verificationToken: string
}

interface RendererProps {
  url: string
  logo?: string
  site: {
    origin: string
    hostname: string
  }
}

const template = `
<table border="0" cellpadding="0" cellspacing="0" width="100%">

  <tr>
    <td align="center" bgcolor="#e9ecef">
      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
        <tr>
          <td align="center" valign="top" style="padding: 36px 24px;">
            {{#logo}}
            <a href="{{origin}}" target="_blank" style="display: inline-block;">
              <img src="{{logo}}" alt="Logo" border="0" width="48" style="display: block; width: 48px; max-width: 48px; min-width: 48px;">
            </a>
            {{/logo}}
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <tr>
    <td align="center" bgcolor="#e9ecef">
      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
        <tr>
          <td align="left" bgcolor="#ffffff" style="padding: 36px 24px 0; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; border-top: 3px solid #d4dadf;">
            <h1 style="margin: 0; font-size: 32px; font-weight: 700; letter-spacing: -1px; line-height: 48px;">
              Sign in to {{hostName}}
            </h1>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <tr>
    <td align="center" bgcolor="#e9ecef">
      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">

        <tr>
          <td align="left" bgcolor="#ffffff" style="padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">
            <p style="margin: 0;">
              Click the button below to sign in to your account. The link will expire after five minutes.
            </p>
          </td>
        </tr>

        <tr>
          <td align="left" bgcolor="#ffffff">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td align="center" bgcolor="#ffffff" style="padding: 12px;">
                  <table border="0" cellpadding="0" cellspacing="0">
                    <tr>
                      <td align="center" bgcolor="#1a82e2" style="border-radius: 6px;">
                        <a href="{{url}}" target="_blank" style="display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #ffffff; text-decoration: none; border-radius: 6px;">
                          Sign In
                        </a>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <tr>
          <td align="left" bgcolor="#ffffff" style="padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px; border-bottom: 3px solid #d4dadf">
            <p style="margin: 0;">
              This message is automatically generated. Dot not reply to this email.
            </p>
          </td>
        </tr>

      </table>
    </td>
  </tr>

  <tr>
    <td align="center" bgcolor="#e9ecef" style="padding: 24px;">
      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
        <tr>
          <td align="center" bgcolor="#e9ecef" style="padding: 12px 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 14px; line-height: 20px; color: #666;">
            <p style="margin: 0;">
              Secured by <a style="text-decoration: none; color: #666;" href="https://passkeys.lattestack.com">Passkeys</a>
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

</table>
`

const optionsSchema = yup.object({
  server: yup.mixed().required(),
  from: yup.string().optional(),
  sendSignInLinkToEmail: yup.mixed().optional()
    .test((value) => typeof value === 'function')
})

@scoped(Lifecycle.ContainerScoped)
export class EmailLinkProvider extends Provider {
  override providerId = 'email-link'

  constructor (
    @inject(OPTIONS) protected override readonly options: PasskeysOptions,
    protected override readonly adapter: Adapter,
    protected override readonly jwt: Jwt,
    @inject(EMAIL_LINK_OPTIONS) private readonly initial: EmailLinkProviderOptions
  ) {
    super(options, adapter, jwt)
  }

  async challenge (request: EmailLinkChallengeRequest): Promise<EmailLinkChallengeResponse> {
    const { email, url } = await yup.object({
      email: yup.string()
        .transform((value) => normalizeEmail(value))
        .email()
        .required(),
      url: yup.string()
        .url()
        .required()
    }).validate(request, {
      stripUnknown: true
    })

    const existingUser = await this.adapter.getUserByEmail(email)

    if (existingUser != null) {
      this.assertUserState(existingUser)
    }

    const token = await this.signVerificationToken<ChallengePayload>({
      email,
      verificationId: randomUUID(),
      subject: randomUUID()
    })

    const urlWithToken = this.appendVerificationTokenToUrl(url, token)

    if (this.initial.sendSignInLinkToEmail != null) {
      await this.initial.sendSignInLinkToEmail({
        url: urlWithToken,
        providerOptions: this.initial
      })
    } else {
      const { origin, hostname } = new URL(this.options.origin)
      const rendererProps: RendererProps = {
        url,
        site: {
          origin,
          hostname
        }
      }

      await createTransport(this.initial.server).sendMail({
        to: email,
        from: this.initial.from ?? `Passkeys <no-reply@${hostname}>`,
        subject: `Sign in to ${hostname}`,
        text: this.renderText(rendererProps),
        html: this.renderHTML(rendererProps)
      })
    }

    return {}
  }

  private appendVerificationTokenToUrl (url: string, token: string): string {
    try {
      const urlObj = new URL(url)
      urlObj.searchParams.append('verification_token', token)
      return urlObj.href
    } catch (error) {
      throw new InvalidUrlException()
    }
  }

  protected renderText (props: RendererProps): string {
    const { site, url } = props
    return `Sign in to ${site.hostname}\n${url}\n\n`
  }

  protected renderHTML (props: RendererProps): string {
    return render(template, props)
  }

  async signIn (request: EmailLinkSignInRequest): Promise<AuthResponse> {
    const { verificationToken } = request
    const { payload } = await this.useVerificationToken<ChallengePayload>(verificationToken)
    const { email, subject } = payload

    const existingUser = await this.adapter.getUserByEmail(email)
    const user = existingUser ?? await this.createUser({ id: subject, email })

    return await this.createSession(user)
  }

  static create (emailLinkOptions: EmailLinkProviderOptions): EmailLinkProvider {
    tsyringe.container.register(EMAIL_LINK_OPTIONS, {
      useValue: optionsSchema.validateSync(emailLinkOptions)
    })

    tsyringe.container.register(EmailLinkProvider, {
      useClass: EmailLinkProvider
    })

    return tsyringe.container.resolve(EmailLinkProvider)
  }
}

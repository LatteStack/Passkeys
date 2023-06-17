import { AuthException } from './AuthException'

export class InvalidVerificationException extends AuthException {
  override name = 'invalid-verification'
  override message = 'Session may have expired or been deleted.'
}

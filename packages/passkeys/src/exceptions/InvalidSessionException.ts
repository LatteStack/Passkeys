import { AuthException } from './AuthException'

export class InvalidSessionException extends AuthException {
  override name = 'invalid-session'
  override message = 'Session may have expired or been deleted due to an attack.'
}

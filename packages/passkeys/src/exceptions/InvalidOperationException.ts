import { AuthException } from './AuthException'

export class InvalidOperationException extends AuthException {
  override name = 'invalid-operation'
  override message = 'The provider was unable to complete the expected operation.'
}

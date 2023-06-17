import { AuthException } from './AuthException'

export class InvalidUserException extends AuthException {
  override name = 'invalid-user'
  override message = 'User may have been disabled or destroyed.'
}

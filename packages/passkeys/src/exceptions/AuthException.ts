export class AuthException extends Error {
  override name = 'auth-exception'
}

export class DuplicateEmailException extends AuthException {
  override name = 'duplicate-email'
}

export class InvalidOperationException extends AuthException {
  override name = 'invalid-operation'
  override message = 'The provider was unable to complete the expected operation.'
}

export class InvalidSecretException extends AuthException {
  override name = 'invalid-secret'
  override message = 'Invalid secret.'
}

export class InvalidSessionException extends AuthException {
  override name = 'invalid-session'
  override message = 'Session may have expired or been deleted due to an attack.'
}

export class InvalidUserException extends AuthException {
  override name = 'invalid-user'
  override message = 'User may have been disabled or destroyed.'
}

export class InvalidVerificationException extends AuthException {
  override name = 'invalid-verification'
  override message = 'Session may have expired or been deleted.'
}

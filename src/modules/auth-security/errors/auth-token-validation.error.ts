import { BaseError } from '@common/base/base.error';

export class AuthTokenValidationError extends BaseError {
  static CODE = 'AUTH_TOKEN.VALIDATION_ERROR';

  constructor(message?: string) {
    super(
      message ?? 'Auth token validation error',
      AuthTokenValidationError.CODE,
    );
  }
}

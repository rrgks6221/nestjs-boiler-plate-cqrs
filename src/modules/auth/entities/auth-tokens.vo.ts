import { AuthTokenValidationError } from '@module/auth-security/errors/auth-token-validation.error';
import { AuthToken } from '@module/auth/entities/auth-token.vo';

import { BaseValueObject } from '@common/base/base.value-object';

export interface AuthTokensProps {
  accessToken: AuthToken;
  refreshToken: AuthToken;
}

export class AuthTokens extends BaseValueObject<AuthTokensProps> {
  constructor(props: AuthTokensProps) {
    super(props);
  }

  get accessToken(): AuthToken {
    return this.props.accessToken;
  }

  get refreshToken(): AuthToken {
    return this.props.refreshToken;
  }

  protected validate(props: AuthTokensProps): void {
    if (props.accessToken.type !== 'access') {
      throw new AuthTokenValidationError('Access token must be of type access');
    }
    if (props.refreshToken.type !== 'refresh') {
      throw new AuthTokenValidationError(
        'Refresh token must be of type refresh',
      );
    }
  }
}

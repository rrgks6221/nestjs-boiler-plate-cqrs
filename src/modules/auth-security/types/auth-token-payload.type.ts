import { AuthTokenType } from '@module/auth/entities/auth-token.vo';

interface BaseAuthTokenPayload {
  sub: string;
  tokenType: AuthTokenType;
}

export interface AccessTokenPayload extends BaseAuthTokenPayload {
  tokenType: 'access';
}

export interface RefreshTokenPayload extends BaseAuthTokenPayload {
  tokenType: 'refresh';
}

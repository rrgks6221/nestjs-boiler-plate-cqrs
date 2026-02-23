import {
  AccessTokenPayload,
  RefreshTokenPayload,
} from '@module/auth-security/types/auth-token-payload.type';
import { AuthTokens } from '@module/auth/entities/auth-tokens.vo';

export const AUTH_TOKEN_SERVICE = Symbol('AUTH_TOKEN_SERVICE');

export interface IAuthTokenService {
  createTokens(userId: string): AuthTokens;
  refreshTokens(refreshToken: string): Promise<AuthTokens>;
  verifyAccessToken(token: string): Promise<AccessTokenPayload>;
  verifyRefreshToken(token: string): Promise<RefreshTokenPayload>;
}

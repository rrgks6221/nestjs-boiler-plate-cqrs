import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

import { StringValue } from 'ms';

import { AuthTokenValidationError } from '@module/auth-security/errors/auth-token-validation.error';
import { IAuthTokenService } from '@module/auth-security/services/auth-token.service.interface';
import {
  AccessTokenPayload,
  RefreshTokenPayload,
} from '@module/auth-security/types/auth-token-payload.type';
import { AuthToken, AuthTokenType } from '@module/auth/entities/auth-token.vo';
import { AuthTokens } from '@module/auth/entities/auth-tokens.vo';

import { ENV_KEY } from '@common/factories/config-module.factory';

/**
 * @todo 적절한 저장소를 통해 refresh token을 관리하세요.
 * @todo logout 시 refresh token revoke(또는 rotation 체계) 처리도 함께 구현하세요.
 */
@Injectable()
export class AuthTokenService implements IAuthTokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  createTokens(userId: string): AuthTokens {
    const accessToken = this.createToken(
      'access',
      userId,
      this.configService.getOrThrow<StringValue>(
        ENV_KEY.ACCESS_TOKEN_EXPIRES_IN,
      ),
    );

    const refreshToken = this.createToken(
      'refresh',
      userId,
      this.configService.getOrThrow<StringValue>(
        ENV_KEY.REFRESH_TOKEN_EXPIRES_IN,
      ),
    );

    return new AuthTokens({ accessToken, refreshToken });
  }

  async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const payload = await this.verifyRefreshToken(refreshToken);

    return this.createTokens(payload.sub);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    const payload = await this.jwtService
      .verifyAsync<AccessTokenPayload>(token)
      .catch(() => {
        throw new AuthTokenValidationError('Invalid access token');
      });

    if (payload.tokenType !== 'access') {
      throw new AuthTokenValidationError('Access token must be of type access');
    }

    return payload;
  }

  async verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    const payload = await this.jwtService
      .verifyAsync<RefreshTokenPayload>(token)
      .catch(() => {
        throw new AuthTokenValidationError('Invalid refresh token');
      });

    if (payload.tokenType !== 'refresh') {
      throw new AuthTokenValidationError(
        'Refresh token must be of type refresh',
      );
    }

    return payload;
  }

  private createToken(
    type: AuthTokenType,
    userId: string,
    expiresIn: StringValue,
  ): AuthToken {
    const token = this.jwtService.sign(
      {
        sub: userId,
        tokenType: type,
      },
      { expiresIn },
    );
    const decoded = this.jwtService.decode<{ exp: number }>(token);

    return new AuthToken({
      token,
      type,
      expiresAt: new Date(decoded.exp * 1000),
    });
  }
}

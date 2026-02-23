import { JwtModule } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';

import { faker } from '@faker-js/faker';

import { AuthTokenValidationError } from '@module/auth-security/errors/auth-token-validation.error';
import { AuthTokenService } from '@module/auth-security/services/auth-token.service';
import {
  AUTH_TOKEN_SERVICE,
  IAuthTokenService,
} from '@module/auth-security/services/auth-token.service.interface';

import {
  ConfigModuleFactory,
  ENV_KEY,
} from '@common/factories/config-module.factory';

describe(AuthTokenService.name, () => {
  let authTokenService: IAuthTokenService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModuleFactory(),
        JwtModule.register({
          global: true,
          secret: process.env[ENV_KEY.JWT_SECRET],
          signOptions: {
            issuer: process.env[ENV_KEY.JWT_ISSUER],
            audience: process.env[ENV_KEY.JWT_AUDIENCE],
          },
          verifyOptions: {
            issuer: process.env[ENV_KEY.JWT_ISSUER],
            audience: process.env[ENV_KEY.JWT_AUDIENCE],
          },
        }),
      ],
      providers: [
        {
          provide: AUTH_TOKEN_SERVICE,
          useClass: AuthTokenService,
        },
      ],
    }).compile();

    authTokenService = module.get<IAuthTokenService>(AUTH_TOKEN_SERVICE);
  });

  describe(AuthTokenService.prototype.createTokens.name, () => {
    it('access, refresh 토큰을 생성해야 한다.', () => {
      const userId = faker.string.numeric(12);

      const tokens = authTokenService.createTokens(userId);

      expect(tokens.accessToken).toMatchObject({
        type: 'access',
        token: expect.any(String),
        expiresAt: expect.any(Date),
      });
      expect(tokens.refreshToken).toMatchObject({
        type: 'refresh',
        token: expect.any(String),
        expiresAt: expect.any(Date),
      });
    });
  });

  describe(AuthTokenService.prototype.verifyAccessToken.name, () => {
    it('유효한 access token이면 payload를 반환해야 한다.', async () => {
      const userId = faker.string.numeric(12);
      const tokens = authTokenService.createTokens(userId);

      await expect(
        authTokenService.verifyAccessToken(tokens.accessToken.token),
      ).resolves.toMatchObject({
        sub: userId,
        tokenType: 'access',
      });
    });

    it('refresh token을 넣으면 토큰이 유효하지 않다는 에러가 발생해야 한다.', async () => {
      const userId = faker.string.numeric(12);
      const tokens = authTokenService.createTokens(userId);

      await expect(
        authTokenService.verifyAccessToken(tokens.refreshToken.token),
      ).rejects.toThrow(AuthTokenValidationError);
    });
  });

  describe(AuthTokenService.prototype.verifyRefreshToken.name, () => {
    it('유효한 refresh token이면 payload를 반환해야 한다.', async () => {
      const userId = faker.string.numeric(12);
      const tokens = authTokenService.createTokens(userId);

      await expect(
        authTokenService.verifyRefreshToken(tokens.refreshToken.token),
      ).resolves.toMatchObject({
        sub: userId,
        tokenType: 'refresh',
      });
    });

    it('유효하지 않은 토큰이면 토큰이 유요하지 않다는 에러가 발생해야 한다.', async () => {
      await expect(
        authTokenService.verifyRefreshToken('invalid-token'),
      ).rejects.toThrow(AuthTokenValidationError);
    });
  });

  describe(AuthTokenService.prototype.refreshTokens.name, () => {
    it('유효한 refresh token으로 토큰을 재발급해야 한다.', async () => {
      const userId = faker.string.numeric(12);
      const original = authTokenService.createTokens(userId);

      const refreshed = await authTokenService.refreshTokens(
        original.refreshToken.token,
      );

      expect(refreshed.accessToken.type).toBe('access');
      expect(refreshed.refreshToken.type).toBe('refresh');
    });

    it('access token으로 refresh 요청 시 토큰이 유요하지 않다는 에러가 발생해야 한다.', async () => {
      const userId = faker.string.numeric(12);
      const tokens = authTokenService.createTokens(userId);

      await expect(
        authTokenService.refreshTokens(tokens.accessToken.token),
      ).rejects.toThrow(AuthTokenValidationError);
    });
  });
});

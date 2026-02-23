import {
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Res,
} from '@nestjs/common';
import { ApiNoContentResponse, ApiOperation, ApiTags } from '@nestjs/swagger';

import { Response } from 'express';

import { AuthTokenValidationError } from '@module/auth-security/errors/auth-token-validation.error';
import {
  AUTH_TOKEN_SERVICE,
  IAuthTokenService,
} from '@module/auth-security/services/auth-token.service.interface';
import {
  AUTH_COOKIE_SERVICE,
  IAuthCookieService,
} from '@module/auth/services/auth-cookie.service.interface';

import { BaseHttpException } from '@common/base/base-http-exception';
import { UnauthorizedError } from '@common/base/base.error';
import { ApiErrorResponse } from '@common/decorators/api-fail-response.decorator';
import { Cookies } from '@common/decorators/cookies.decorator';

@ApiTags('auth')
@Controller()
export class RefreshController {
  constructor(
    @Inject(AUTH_TOKEN_SERVICE)
    private readonly authTokenService: IAuthTokenService,
    @Inject(AUTH_COOKIE_SERVICE)
    private readonly authCookieService: IAuthCookieService,
  ) {}

  @ApiOperation({ summary: 'refresh token 기반 토큰 재발급' })
  @ApiNoContentResponse({
    description: '인증 쿠키(access/refresh)가 재발급됩니다.',
  })
  @ApiErrorResponse({
    [HttpStatus.UNAUTHORIZED]: [UnauthorizedError],
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('auth/refresh')
  async refresh(
    @Cookies('refresh_token') refreshToken: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    if (refreshToken === undefined) {
      throw new BaseHttpException(
        HttpStatus.UNAUTHORIZED,
        new UnauthorizedError(),
      );
    }

    try {
      const tokens = await this.authTokenService.refreshTokens(refreshToken);

      this.authCookieService.apply(res, tokens);
    } catch (error) {
      if (error instanceof AuthTokenValidationError) {
        throw new BaseHttpException(
          HttpStatus.UNAUTHORIZED,
          new UnauthorizedError(),
        );
      }

      throw error;
    }
  }
}

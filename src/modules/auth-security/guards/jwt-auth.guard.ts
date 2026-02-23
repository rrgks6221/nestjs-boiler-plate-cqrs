import {
  CanActivate,
  ExecutionContext,
  HttpStatus,
  Inject,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { Request } from 'express';
import { ClsService } from 'nestjs-cls';

import { AuthTokenValidationError } from '@module/auth-security/errors/auth-token-validation.error';
import {
  AUTH_TOKEN_SERVICE,
  IAuthTokenService,
} from '@module/auth-security/services/auth-token.service.interface';

import { BaseHttpException } from '@common/base/base-http-exception';
import { UnauthorizedError } from '@common/base/base.error';
import { CLS_STORE_KEY } from '@common/constants/cls-store-key.constant';

export const Public = () => SetMetadata('isPublic', true);

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    @Inject(AUTH_TOKEN_SERVICE)
    private readonly authTokenService: IAuthTokenService,
    private readonly reflector: Reflector,
    private readonly clsService: ClsService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.get<boolean>(
      'isPublic',
      context.getHandler(),
    );

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromCookie(request);

    if (!token) {
      throw new BaseHttpException(
        HttpStatus.UNAUTHORIZED,
        new UnauthorizedError(),
      );
    }

    try {
      const payload = await this.authTokenService.verifyAccessToken(token);

      this.clsService.set(CLS_STORE_KEY.ACTOR_ID, payload.sub);
      request['user'] = {
        id: payload.sub,
      };

      return true;
    } catch (error) {
      if (error instanceof AuthTokenValidationError) {
        throw new BaseHttpException(
          HttpStatus.UNAUTHORIZED,
          new UnauthorizedError(error.message),
        );
      }

      throw error;
    }
  }

  private extractTokenFromCookie(request: Request): string | undefined {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return request.cookies.access_token;
  }
}

import {
  BadRequestException,
  INestApplication,
  ValidationError,
  ValidationPipe,
  ValidationPipeOptions,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import cookieParser from 'cookie-parser';

import { BaseHttpExceptionFilter } from '@common/base/base-http-exception-filter';
import { RequestValidationError } from '@common/base/base.error';
import { ENV_KEY } from '@common/factories/config-module.factory';

import { LOGGER } from '@shared/logger/logger.module';

export const setCookie = (app: INestApplication) => {
  app.use(cookieParser());
};

/**
 * @todo 보일러플레이트에서는 ENV `CORS_ALLOWED_ORIGINS` 기반 allowlist만 제공합니다.
 *       운영 환경에서는 배포 도메인/스테이징 도메인을 명시적으로 관리하세요.
 *       필요 시 서브도메인 패턴/동적 검증이 필요하면 origin callback 방식으로 확장하세요.
 */
export const setCors = (app: INestApplication) => {
  const configService = app.get(ConfigService);

  app.enableCors({
    credentials: true,
    origin: configService.getOrThrow<string[]>(ENV_KEY.CORS_ALLOWED_ORIGINS),
  });
};

export const setGlobalExceptionFilter = (app: INestApplication) => {
  app.useGlobalFilters(new BaseHttpExceptionFilter());
};

export const setGlobalPipe = (app: INestApplication) => {
  const options: Omit<ValidationPipeOptions, 'exceptionFactory'> = {
    transform: true,
    whitelist: true,
  };

  const exceptionFactory = (validationErrors: ValidationError[]) => {
    function flattenValidationErrors(
      errors: ValidationError[],
      parentPath: string = '',
    ): any[] {
      return errors.flatMap(({ property, constraints, children }) => {
        const path = parentPath ? `${parentPath}.${property}` : property;
        let result: unknown[] = [];

        if (constraints) {
          result.push({
            property: path,
            constraints: Object.values(constraints).map((message) =>
              message.replace(property, path),
            ),
          });
        }

        if (children?.length) {
          result = result.concat(flattenValidationErrors(children, path));
        }

        return result;
      });
    }

    throw new BadRequestException({
      statusCode: 400,
      message: 'request input validation error',
      code: RequestValidationError.CODE,
      errors: flattenValidationErrors(validationErrors),
    });
  };

  app.useGlobalPipes(new ValidationPipe({ ...options, exceptionFactory }));
};

export const setLogger = (app: INestApplication) => {
  app.useLogger(app.get(LOGGER));
};

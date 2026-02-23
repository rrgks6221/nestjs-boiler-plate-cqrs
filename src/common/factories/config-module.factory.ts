import { ConfigModule } from '@nestjs/config';

import Joi from 'joi';

export const ENV_KEY = {
  PORT: 'PORT',
  NODE_ENV: 'NODE_ENV',

  DATABASE_URL: 'DATABASE_URL',

  SALT_ROUND: 'SALT_ROUND',
  JWT_SECRET: 'JWT_SECRET',
  JWT_ISSUER: 'JWT_ISSUER',
  JWT_AUDIENCE: 'JWT_AUDIENCE',
  ACCESS_TOKEN_EXPIRES_IN: 'ACCESS_TOKEN_EXPIRES_IN',
  REFRESH_TOKEN_EXPIRES_IN: 'REFRESH_TOKEN_EXPIRES_IN',

  LOGGER_LEVEL: 'LOGGER_LEVEL',
  CORS_ALLOWED_ORIGINS: 'CORS_ALLOWED_ORIGINS',
} as const;

const parseCommaSeparatedStringArray = (
  rawValue: string,
  helpers: Joi.CustomHelpers,
): string[] => {
  const parsedOrigins: string[] = rawValue
    .split(',')
    .map((origin: string) => origin.trim())
    .filter((origin: string) => origin.length > 0);

  if (parsedOrigins.length === 0) {
    return helpers.error('any.invalid') as never;
  }

  return parsedOrigins;
};

export const ConfigModuleFactory = () => {
  return ConfigModule.forRoot({
    isGlobal: true,
    envFilePath: process.env.NODE_ENV === 'test' ? '.env.test' : '.env',
    validationSchema: Joi.object({
      [ENV_KEY.PORT]: Joi.number().port().default(3000),
      [ENV_KEY.NODE_ENV]: Joi.string()
        .valid('development', 'production', 'test')
        .default('development'),

      [ENV_KEY.DATABASE_URL]: Joi.string().required(),

      [ENV_KEY.SALT_ROUND]: Joi.number().required(),
      [ENV_KEY.JWT_SECRET]: Joi.string().required(),
      [ENV_KEY.JWT_ISSUER]: Joi.string().required(),
      [ENV_KEY.JWT_AUDIENCE]: Joi.string().required(),
      [ENV_KEY.ACCESS_TOKEN_EXPIRES_IN]: Joi.string().required(),
      [ENV_KEY.REFRESH_TOKEN_EXPIRES_IN]: Joi.string().required(),

      [ENV_KEY.LOGGER_LEVEL]: Joi.string()
        .valid('silent', 'fatal', 'error', 'warn', 'info', 'debug', 'trace')
        .default('info'),
      [ENV_KEY.CORS_ALLOWED_ORIGINS]: Joi.string()
        .required()
        .custom(parseCommaSeparatedStringArray),
    }),
  });
};

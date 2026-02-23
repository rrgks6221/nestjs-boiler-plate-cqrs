import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

import { JwtAuthGuard } from '@module/auth-security/guards/jwt-auth.guard';
import { AuthTokenService } from '@module/auth-security/services/auth-token.service';
import { AUTH_TOKEN_SERVICE } from '@module/auth-security/services/auth-token.service.interface';

import { ENV_KEY } from '@common/factories/config-module.factory';

@Global()
@Module({
  imports: [
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => {
        return {
          secret: configService.getOrThrow(ENV_KEY.JWT_SECRET),
          signOptions: {
            issuer: configService.getOrThrow(ENV_KEY.JWT_ISSUER),
            audience: configService.getOrThrow(ENV_KEY.JWT_AUDIENCE),
          },
          verifyOptions: {
            issuer: configService.getOrThrow(ENV_KEY.JWT_ISSUER),
            audience: configService.getOrThrow(ENV_KEY.JWT_AUDIENCE),
          },
        };
      },
      inject: [ConfigService],
    }),
  ],
  providers: [
    {
      provide: AUTH_TOKEN_SERVICE,
      useClass: AuthTokenService,
    },
    JwtAuthGuard,
  ],
  exports: [AUTH_TOKEN_SERVICE, JwtAuthGuard],
})
export class AuthSecurityModule {}

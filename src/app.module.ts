import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { AuthSecurityModule } from '@module/auth-security/auth-security.module';
import { AuthModule } from '@module/auth/auth.module';
import { HealthModule } from '@module/health/health.module';
import { UserModule } from '@module/user/user.module';

import { ClsModuleFactory } from '@common/factories/cls-module.factory';
import { ConfigModuleFactory } from '@common/factories/config-module.factory';

import { LoggerModule } from '@shared/logger/logger.module';
import { PrismaModule } from '@shared/prisma/prisma.module';

@Module({
  imports: [
    ConfigModuleFactory(),
    PrismaModule,
    ClsModuleFactory(),
    CqrsModule.forRoot(),
    LoggerModule,
    HealthModule,
    AuthSecurityModule,
    AuthModule,
    UserModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}

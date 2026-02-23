import { Module } from '@nestjs/common';

import { AuthCookieService } from '@module/auth/services/auth-cookie.service';
import { AUTH_COOKIE_SERVICE } from '@module/auth/services/auth-cookie.service.interface';
import { LogoutController } from '@module/auth/use-cases/logout/logout.controller';
import { RefreshController } from '@module/auth/use-cases/refresh/refresh.controller';
import { SignInWithUsernameController } from '@module/auth/use-cases/sign-in-with-username/sign-in-with-username.controller';
import { SignInWithUsernameHandler } from '@module/auth/use-cases/sign-in-with-username/sign-in-with-username.handler';
import { SignUpWithUsernameController } from '@module/auth/use-cases/sign-up-with-username/sign-up-with-username.controller';
import { SignUpWithUsernameHandler } from '@module/auth/use-cases/sign-up-with-username/sign-up-with-username.handler';
import { UserModule } from '@module/user/user.module';

import { EventStoreModule } from '@core/event-sourcing/event-store.module';

@Module({
  imports: [EventStoreModule, UserModule],
  controllers: [
    LogoutController,
    SignUpWithUsernameController,
    SignInWithUsernameController,
    RefreshController,
  ],
  providers: [
    SignUpWithUsernameHandler,
    SignInWithUsernameHandler,
    {
      provide: AUTH_COOKIE_SERVICE,
      useClass: AuthCookieService,
    },
  ],
})
export class AuthModule {}

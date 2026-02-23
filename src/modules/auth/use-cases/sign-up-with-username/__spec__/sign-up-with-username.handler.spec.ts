import { CommandBus, CqrsModule } from '@nestjs/cqrs';
import { JwtModule } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';

import { AuthTokenService } from '@module/auth-security/services/auth-token.service';
import { AUTH_TOKEN_SERVICE } from '@module/auth-security/services/auth-token.service.interface';
import { AuthTokens } from '@module/auth/entities/auth-tokens.vo';
import { SignUpWithUsernameCommandFactory } from '@module/auth/use-cases/sign-up-with-username/__spec__/sign-up-with-username.command.factory';
import { SignUpWithUsernameCommand } from '@module/auth/use-cases/sign-up-with-username/sign-up-with-username.command';
import { SignUpWithUsernameHandler } from '@module/auth/use-cases/sign-up-with-username/sign-up-with-username.handler';
import { UserFactory } from '@module/user/domain/__spec__/user.entity.factory';

import { ClsModuleFactory } from '@common/factories/cls-module.factory';
import { ConfigModuleFactory } from '@common/factories/config-module.factory';

import { EventStoreModule } from '@core/event-sourcing/event-store.module';

describe(SignUpWithUsernameHandler.name, () => {
  let handler: SignUpWithUsernameHandler;

  let commandBus: CommandBus;

  let command: SignUpWithUsernameCommand;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ClsModuleFactory(),
        CqrsModule,
        ConfigModuleFactory(),
        JwtModule.register({ global: true, secret: 'test' }),
        EventStoreModule,
      ],
      providers: [
        SignUpWithUsernameHandler,
        {
          provide: AUTH_TOKEN_SERVICE,
          useClass: AuthTokenService,
        },
      ],
    }).compile();

    handler = module.get<SignUpWithUsernameHandler>(SignUpWithUsernameHandler);

    commandBus = module.get<CommandBus>(CommandBus);
  });

  beforeEach(() => {
    jest.spyOn(commandBus, 'execute').mockResolvedValue(UserFactory.build());
  });

  beforeEach(() => {
    command = SignUpWithUsernameCommandFactory.build();
  });

  describe('회원가입하면', () => {
    it('인증 토큰을 반환해야한다.', async () => {
      await expect(handler.execute(command)).resolves.toBeInstanceOf(
        AuthTokens,
      );
    });
  });
});

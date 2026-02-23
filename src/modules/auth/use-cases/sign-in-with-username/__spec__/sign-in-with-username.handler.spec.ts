import { CqrsModule, QueryBus } from '@nestjs/cqrs';
import { JwtModule } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';

import { faker } from '@faker-js/faker';

import { AuthTokenService } from '@module/auth-security/services/auth-token.service';
import { AUTH_TOKEN_SERVICE } from '@module/auth-security/services/auth-token.service.interface';
import { AuthTokens } from '@module/auth/entities/auth-tokens.vo';
import { SignInfoMismatchedError } from '@module/auth/errors/sign-info-mismatched.error';
import { SignInWithUsernameCommandFactory } from '@module/auth/use-cases/sign-in-with-username/__spec__/sign-in-with-username.command.factory';
import { SignInWithUsernameCommand } from '@module/auth/use-cases/sign-in-with-username/sign-in-with-username.command';
import { SignInWithUsernameHandler } from '@module/auth/use-cases/sign-in-with-username/sign-in-with-username.handler';
import { UserFactory } from '@module/user/domain/__spec__/user.entity.factory';
import { UserNotFoundError } from '@module/user/errors/user-not-found.error';
import { PasswordHasher } from '@module/user/services/password-hasher';
import {
  IPasswordHasher,
  PASSWORD_HASHER,
} from '@module/user/services/password-hasher.interface';

import { ClsModuleFactory } from '@common/factories/cls-module.factory';
import { ConfigModuleFactory } from '@common/factories/config-module.factory';

import { EventStoreModule } from '@core/event-sourcing/event-store.module';

describe(SignInWithUsernameHandler.name, () => {
  let handler: SignInWithUsernameHandler;

  let queryBus: QueryBus;
  let passwordHasher: IPasswordHasher;

  let command: SignInWithUsernameCommand;

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
        SignInWithUsernameHandler,
        {
          provide: PASSWORD_HASHER,
          useClass: PasswordHasher,
        },
        {
          provide: AUTH_TOKEN_SERVICE,
          useClass: AuthTokenService,
        },
      ],
    }).compile();

    handler = module.get<SignInWithUsernameHandler>(SignInWithUsernameHandler);
    passwordHasher = module.get<IPasswordHasher>(PASSWORD_HASHER);

    queryBus = module.get<QueryBus>(QueryBus);
  });

  beforeEach(() => {
    jest.spyOn(queryBus, 'execute');
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  beforeEach(() => {
    command = SignInWithUsernameCommandFactory.build();
  });

  describe('인증정보가 일치하는 유저가 로그인하면', () => {
    beforeEach(() => {
      jest
        .spyOn(queryBus, 'execute')
        .mockResolvedValue(
          UserFactory.build({ password: faker.internet.password() }),
        );
      jest.spyOn(passwordHasher, 'compare').mockResolvedValue(true);
    });

    it('인증 토큰을 반환해야한다.', async () => {
      await expect(handler.execute(command)).resolves.toBeInstanceOf(
        AuthTokens,
      );
    });
  });

  describe('username과 일치하는 유저가 존재하지 않는 경우', () => {
    beforeEach(() => {
      jest
        .spyOn(queryBus, 'execute')
        .mockRejectedValue(new UserNotFoundError());
    });

    it('로그인 정보가 일치하지 않는다는 에러가 발생해야한다.', async () => {
      await expect(handler.execute(command)).rejects.toThrow(
        SignInfoMismatchedError,
      );
    });
  });

  describe('password가 일치하지 않는 경우', () => {
    beforeEach(() => {
      jest.spyOn(queryBus, 'execute').mockResolvedValue(UserFactory.build());
      jest.spyOn(passwordHasher, 'compare').mockResolvedValue(false);
    });

    it('로그인 정보가 일치하지 않는다는 에러가 발생해야한다.', async () => {
      await expect(handler.execute(command)).rejects.toThrow(
        SignInfoMismatchedError,
      );
    });
  });
});

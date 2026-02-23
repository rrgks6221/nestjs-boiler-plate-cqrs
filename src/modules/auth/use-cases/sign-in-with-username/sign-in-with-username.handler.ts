import { Inject } from '@nestjs/common';
import { CommandHandler, ICommandHandler, QueryBus } from '@nestjs/cqrs';

import { Transactional } from '@nestjs-cls/transactional';

import {
  AUTH_TOKEN_SERVICE,
  IAuthTokenService,
} from '@module/auth-security/services/auth-token.service.interface';
import { AuthTokens } from '@module/auth/entities/auth-tokens.vo';
import { SignInfoMismatchedError } from '@module/auth/errors/sign-info-mismatched.error';
import { SignInWithUsernameCommand } from '@module/auth/use-cases/sign-in-with-username/sign-in-with-username.command';
import { User } from '@module/user/domain/user.entity';
import { UserNotFoundError } from '@module/user/errors/user-not-found.error';
import {
  IPasswordHasher,
  PASSWORD_HASHER,
} from '@module/user/services/password-hasher.interface';
import { GetUserByUsernameQuery } from '@module/user/use-cases/get-user-by-username/get-user-by-username.query';

import {
  EVENT_STORE,
  IEventStore,
} from '@core/event-sourcing/event-store.interface';

@CommandHandler(SignInWithUsernameCommand)
export class SignInWithUsernameHandler implements ICommandHandler<
  SignInWithUsernameCommand,
  AuthTokens
> {
  constructor(
    private readonly queryBus: QueryBus,
    @Inject(PASSWORD_HASHER)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(AUTH_TOKEN_SERVICE)
    private readonly authTokenService: IAuthTokenService,
    @Inject(EVENT_STORE)
    private readonly eventStore: IEventStore,
  ) {}

  @Transactional()
  async execute(command: SignInWithUsernameCommand): Promise<AuthTokens> {
    const user = await this.queryBus
      .execute<GetUserByUsernameQuery, User>(
        new GetUserByUsernameQuery({
          username: command.username,
        }),
      )
      .catch((e) => {
        if (e instanceof UserNotFoundError) {
          throw new SignInfoMismatchedError();
        }
        throw e;
      });

    const isPasswordMatch = await this.passwordHasher.compare(
      command.password,
      user.password,
    );

    if (isPasswordMatch === false) {
      throw new SignInfoMismatchedError();
    }

    user.signIn();
    await this.eventStore.storeAggregateEvents(user, user.id);

    const authTokens = this.authTokenService.createTokens(user.id);

    return authTokens;
  }
}

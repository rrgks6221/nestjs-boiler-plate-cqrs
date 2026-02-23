import { Inject } from '@nestjs/common';
import { CommandBus, CommandHandler, ICommandHandler } from '@nestjs/cqrs';

import { Transactional } from '@nestjs-cls/transactional';

import {
  AUTH_TOKEN_SERVICE,
  IAuthTokenService,
} from '@module/auth-security/services/auth-token.service.interface';
import { AuthTokens } from '@module/auth/entities/auth-tokens.vo';
import { SignUpWithUsernameCommand } from '@module/auth/use-cases/sign-up-with-username/sign-up-with-username.command';
import { User } from '@module/user/domain/user.entity';
import { CreateUserWithUsernameCommand } from '@module/user/use-cases/create-user-with-username/create-user-with-username.command';

import {
  EVENT_STORE,
  IEventStore,
} from '@core/event-sourcing/event-store.interface';

@CommandHandler(SignUpWithUsernameCommand)
export class SignUpWithUsernameHandler implements ICommandHandler<
  SignUpWithUsernameCommand,
  AuthTokens
> {
  constructor(
    private readonly commandBus: CommandBus,
    @Inject(AUTH_TOKEN_SERVICE)
    private readonly authTokenService: IAuthTokenService,
    @Inject(EVENT_STORE)
    private readonly eventStore: IEventStore,
  ) {}

  @Transactional()
  async execute(command: SignUpWithUsernameCommand): Promise<AuthTokens> {
    const user = await this.commandBus.execute<
      CreateUserWithUsernameCommand,
      User
    >(
      new CreateUserWithUsernameCommand({
        username: command.username,
        password: command.password,
      }),
    );

    const authTokens = this.authTokenService.createTokens(user.id);

    await this.eventStore.storeAggregateEvents(user, user.id);

    return authTokens;
  }
}

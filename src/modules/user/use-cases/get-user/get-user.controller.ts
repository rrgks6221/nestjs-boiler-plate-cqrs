import { Controller, Get, HttpStatus, UseGuards } from '@nestjs/common';
import { QueryBus } from '@nestjs/cqrs';
import {
  ApiCookieAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';

import { JwtAuthGuard } from '@module/auth-security/guards/jwt-auth.guard';
import { UserDtoAssembler } from '@module/user/assemblers/user-dto.assembler';
import { User } from '@module/user/domain/user.entity';
import { UserDto } from '@module/user/dto/user.dto';
import { GetUserQuery } from '@module/user/use-cases/get-user/get-user.query';

import { UnauthorizedError } from '@common/base/base.error';
import { ApiErrorResponse } from '@common/decorators/api-fail-response.decorator';
import {
  CurrentUser,
  ICurrentUser,
} from '@common/decorators/current-user.decorator';

@ApiTags('user')
@Controller()
export class GetUserController {
  constructor(private readonly queryBus: QueryBus) {}

  @ApiOperation({ summary: '내 정보 조회' })
  @ApiCookieAuth('cookie-auth')
  @ApiOkResponse({ type: UserDto })
  @ApiErrorResponse({
    [HttpStatus.UNAUTHORIZED]: [UnauthorizedError],
  })
  @UseGuards(JwtAuthGuard)
  @Get('users/me')
  async getMe(@CurrentUser() currentUser: ICurrentUser): Promise<UserDto> {
    const user = await this.queryBus.execute<GetUserQuery, User>(
      new GetUserQuery({ userId: currentUser.id }),
    );

    return UserDtoAssembler.convertToDto(user);
  }
}

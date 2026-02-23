import { ExecutionContext, createParamDecorator } from '@nestjs/common';

import { Request } from 'express';

export const Cookies = createParamDecorator(
  (key: string | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<Request>();

    if (!key) {
      return request.cookies;
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return request.cookies?.[key];
  },
);

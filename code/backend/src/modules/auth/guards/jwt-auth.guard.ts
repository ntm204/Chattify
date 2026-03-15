import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { AuthenticatedRequest } from '../../../common/interfaces/authenticated-request.interface';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 1. Run standard JWT validation (Passport strategy)
    // JwtStrategy.validate() already checks session in Redis + DB fallback
    const isValid = (await super.canActivate(context)) as boolean;
    if (!isValid) return false;

    // 2. Verify user and sessionId were populated by strategy
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;

    if (!user || !user.currentSessionId) {
      throw new UnauthorizedException('Phiên đăng nhập không hợp lệ!');
    }

    return true;
  }

  handleRequest<TUser>(err: unknown, user: unknown): TUser {
    if (err || !user) {
      throw new UnauthorizedException(
        'Bạn không có quyền hoặc phiên đăng nhập đã hết hạn!',
      );
    }
    return user as TUser;
  }
}

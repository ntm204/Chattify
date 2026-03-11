import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    // Gọi Guard cha để kiểm tra Token
    return super.canActivate(context);
  }

  handleRequest<TUser>(err: unknown, user: unknown): TUser {
    // Tùy chỉnh lỗi nếu Token hỏng hoặc User fake
    if (err || !user) {
      if (err) {
        throw err instanceof Error
          ? err
          : new Error(
              typeof err === 'string' ? err : 'Lỗi xác thực không rõ nguồn gốc',
            );
      }
      throw new UnauthorizedException(
        'Bạn không có quyền hoặc phiên đăng nhập đã hết hạn!',
      );
    }
    return user as TUser;
  }
}

import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RedisService } from '../../../core/redis/redis.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
    configService: ConfigService,
  ) {
    const secret = configService.get<string>('JWT_SECRET');
    if (!secret) {
      throw new Error(
        'FATAL ERROR: JWT_SECRET environment variable is not defined!',
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          if (
            request?.cookies &&
            'access_token' in (request.cookies as object)
          ) {
            return (request.cookies as Record<string, string>).access_token;
          }
          return null;
        },
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  async validate(payload: { sessionId: string; sub: string }) {
    if (!payload.sessionId) {
      throw new UnauthorizedException(
        'Token không hợp lệ: thiếu thông tin phiên đăng nhập.',
      );
    }

    // Attempt to read from Redis cache
    const userStr = await this.redisService.getCache(
      `session:${payload.sessionId}`,
    );
    let user: {
      id: string;
      email: string;
      username: string;
      displayName: string;
      avatarUrl: string | null;
    } | null = null;

    if (userStr) {
      user = JSON.parse(userStr) as typeof user;
    } else {
      // Fallback to PostgreSQL if Redis cache misses
      const session = await this.prisma.userSession.findUnique({
        where: { id: payload.sessionId },
        include: { user: true },
      });

      if (!session || session.isRevoked || !session.user) {
        throw new UnauthorizedException(
          'Phiên đăng nhập đã hết hạn hoặc bị đăng xuất từ xa bởi thiết bị khác.',
        );
      }

      user = session.user;

      // Update Redis cache missing
      const expirySecs = Math.floor(
        (session.expiresAt.getTime() - Date.now()) / 1000,
      );
      if (expirySecs > 0) {
        await this.redisService.setCache(
          `session:${session.id}`,
          JSON.stringify(user),
          expirySecs,
        );
        const redisClient = this.redisService.getClient();
        await redisClient.sadd(`user_sessions:${user.id}`, session.id);
      }
    }

    return { ...user, currentSessionId: payload.sessionId };
  }
}

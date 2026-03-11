import { Prisma, User, UserSession } from '@prisma/client';
import {
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RedisService } from '../../../core/redis/redis.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { randomBytes, createHash } from 'crypto';

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly jwt2FASecret: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
  ) {
    const secret2FA = this.configService.get<string>('JWT_2FA_SECRET');
    if (!secret2FA) {
      throw new Error(
        'FATAL ERROR: JWT_2FA_SECRET environment variable is not defined!',
      );
    }
    this.jwt2FASecret = secret2FA;
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private toSafeUserData(user: Partial<User>) {
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
    };
  }

  async createSessionForUser(
    userId: string,
    ipAddress?: string,
    deviceInfo?: string,
  ) {
    // Use Prisma transaction but execute Redis commands afterwards to ensure we don't mix tx state
    const sessionVariables = await this.prisma.$transaction(
      async (tx: Prisma.TransactionClient) => {
        const rawRefreshToken = randomBytes(32).toString('hex');
        const hashedRefreshToken = this.hashToken(rawRefreshToken);
        const sessionExpiresAt = new Date(
          Date.now() + AUTH_CONSTANTS.SESSION_EXPIRY_MS,
        );

        const session = await tx.userSession.create({
          data: {
            userId,
            refreshToken: hashedRefreshToken,
            deviceInfo,
            ipAddress,
            expiresAt: sessionExpiresAt,
          },
        });

        const user = await tx.user.findUnique({ where: { id: userId } });

        const activeSessions = await tx.userSession.findMany({
          where: { userId, isRevoked: false },
          orderBy: { createdAt: 'desc' },
        });

        let sessionsToRevokeIds: string[] = [];
        if (activeSessions.length > AUTH_CONSTANTS.MAX_SESSIONS_PER_USER) {
          sessionsToRevokeIds = activeSessions
            .slice(AUTH_CONSTANTS.MAX_SESSIONS_PER_USER)
            .map((s: UserSession) => s.id);
          await tx.userSession.updateMany({
            where: { id: { in: sessionsToRevokeIds } },
            data: { isRevoked: true },
          });
        }

        return { session, rawRefreshToken, user, sessionsToRevokeIds };
      },
    );

    // Update Redis Cache outside transaction
    const { session, rawRefreshToken, user, sessionsToRevokeIds } =
      sessionVariables;

    await this.redisService.setCache(
      `session:${session.id}`,
      JSON.stringify(this.toSafeUserData(user!)),
      AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
    );

    // Add to user_sessions set
    const redisClient = this.redisService.getClient();
    await redisClient.sadd(`user_sessions:${user?.id}`, session.id);

    // Remove revoked over-limit sessions from cache
    if (sessionsToRevokeIds.length > 0) {
      for (const revokedId of sessionsToRevokeIds) {
        await this.redisService.deleteCache(`session:${revokedId}`);
        await redisClient.srem(`user_sessions:${user?.id}`, revokedId);
      }
    }

    return { ...session, refreshToken: rawRefreshToken };
  }

  async getSessions(userId: string) {
    return this.prisma.userSession.findMany({
      where: { userId, isRevoked: false },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        deviceInfo: true,
        ipAddress: true,
        createdAt: true,
        expiresAt: true,
      },
    });
  }

  async revokeSession(userId: string, sessionId: string) {
    const session = await this.prisma.userSession.findFirst({
      where: { id: sessionId, userId },
    });

    if (!session) {
      throw new NotFoundException('Không tìm thấy phiên đăng nhập này!');
    }

    await this.prisma.userSession.update({
      where: { id: sessionId },
      data: { isRevoked: true },
    });

    await this.redisService.deleteCache(`session:${sessionId}`);
    const redisClient = this.redisService.getClient();
    await redisClient.srem(`user_sessions:${userId}`, sessionId);

    return { message: 'Đã đăng xuất thiết bị thành công!' };
  }

  async revokeAllSessions(userId: string) {
    await this.prisma.userSession.updateMany({
      where: { userId },
      data: { isRevoked: true },
    });

    const redisClient = this.redisService.getClient();
    const activeSessions = await redisClient.smembers(
      `user_sessions:${userId}`,
    );

    if (activeSessions.length > 0) {
      const pipeline = redisClient.pipeline();
      for (const sessionId of activeSessions) {
        pipeline.del(`session:${sessionId}`);
      }
      pipeline.del(`user_sessions:${userId}`);
      await pipeline.exec();
    }
  }

  async refreshTokens(refreshToken: string) {
    const hashedToken = this.hashToken(refreshToken);

    const reuseFlag = await this.redisService.getCache(
      `rotated_refresh:${hashedToken}`,
    );
    if (reuseFlag) {
      this.logger.warn(
        `🚨 Refresh token reuse detected! Revoking all sessions for userId: ${reuseFlag}`,
      );
      await this.revokeAllSessions(reuseFlag);
      throw new UnauthorizedException(
        'Phát hiện hoạt động đáng ngờ. Tất cả phiên đã bị đăng xuất vì lý do bảo mật.',
      );
    }

    const session = await this.prisma.userSession.findFirst({
      where: { refreshToken: hashedToken, isRevoked: false },
      include: { user: true },
    });

    if (!session) {
      throw new UnauthorizedException(
        'Refresh Token không hợp lệ hoặc thiết bị đã bị đăng xuất!',
      );
    }

    if (new Date() > session.expiresAt) {
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: { isRevoked: true },
      });
      await this.redisService.deleteCache(`session:${session.id}`);
      const redisClient = this.redisService.getClient();
      await redisClient.srem(`user_sessions:${session.userId}`, session.id);
      throw new UnauthorizedException(
        'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại!',
      );
    }

    const newRawRefreshToken = randomBytes(32).toString('hex');
    const newHashedRefreshToken = this.hashToken(newRawRefreshToken);
    await this.prisma.userSession.update({
      where: { id: session.id },
      data: { refreshToken: newHashedRefreshToken },
    });

    await this.redisService.setCache(
      `rotated_refresh:${hashedToken}`,
      session.userId,
      AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
    );

    await this.redisService.setCache(
      `session:${session.id}`,
      JSON.stringify(this.toSafeUserData(session.user)),
      AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
    );

    return this.generateTokens(session.user, session.id, newRawRefreshToken);
  }

  generateTokens(
    user: Partial<User>,
    sessionId: string,
    refreshToken?: string,
  ) {
    const payload: { sub: string; sessionId?: string } = {
      sub: user.id!,
    };

    if (sessionId) {
      payload.sessionId = sessionId;
    }

    const result: Record<string, unknown> = {
      access_token: this.jwtService.sign(payload),
      user: this.toSafeUserData(user),
    };

    if (refreshToken) {
      result.refresh_token = refreshToken;
    }

    return result;
  }

  generateTemp2FAToken(userId: string) {
    return this.jwtService.sign(
      { sub: userId, type: '2FA_TEMP' },
      {
        expiresIn: AUTH_CONSTANTS.TWO_FA_TEMP_TOKEN_EXPIRY,
        secret: this.jwt2FASecret,
      },
    );
  }

  verifyTemp2FAToken(token: string): string | null {
    try {
      const payload: unknown = this.jwtService.verify(token, {
        secret: this.jwt2FASecret,
      });
      if (
        typeof payload === 'object' &&
        payload !== null &&
        (payload as Record<string, unknown>).type === '2FA_TEMP'
      ) {
        return (payload as Record<string, unknown>).sub as string;
      }
      return null;
    } catch {
      return null;
    }
  }
}

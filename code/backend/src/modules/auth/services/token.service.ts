import { Prisma, User, UserSession } from '@prisma/client';
import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RedisService } from '../../../core/redis/redis.service';
import { randomBytes } from 'crypto';

@Injectable()
export class TokenService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
  ) {}

  async createSessionForUser(
    userId: string,
    ipAddress?: string,
    deviceInfo?: string,
  ) {
    // Use Prisma transaction but execute Redis commands afterwards to ensure we don't mix tx state
    const sessionVariables = await this.prisma.$transaction(
      async (tx: Prisma.TransactionClient) => {
        const pseudoRefreshToken = randomBytes(32).toString('hex');
        const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        const session = await tx.userSession.create({
          data: {
            userId,
            refreshToken: pseudoRefreshToken,
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
        if (activeSessions.length > 5) {
          sessionsToRevokeIds = activeSessions
            .slice(5)
            .map((s: UserSession) => s.id);
          await tx.userSession.updateMany({
            where: { id: { in: sessionsToRevokeIds } },
            data: { isRevoked: true },
          });
        }

        return { session, user, sessionsToRevokeIds };
      },
    );

    // Update Redis Cache outside transaction
    const { session, user, sessionsToRevokeIds } = sessionVariables;

    // Cache new session for 7 days
    await this.redisService.setCache(
      `session:${session.id}`,
      JSON.stringify(user),
      7 * 24 * 60 * 60,
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

    return session;
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
    const session = await this.prisma.userSession.findFirst({
      where: { refreshToken, isRevoked: false },
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

    const newRefreshToken = randomBytes(32).toString('hex');
    await this.prisma.userSession.update({
      where: { id: session.id },
      data: { refreshToken: newRefreshToken },
    });

    // Update TTL on Redis
    await this.redisService.setCache(
      `session:${session.id}`,
      JSON.stringify(session.user),
      7 * 24 * 60 * 60,
    );

    return this.generateTokens(session.user, session.id, newRefreshToken);
  }

  generateTokens(
    user: Partial<User>,
    sessionId: string,
    refreshToken?: string,
  ) {
    const payload: {
      sub: string;
      email: string;
      username: string;
      sessionId?: string;
    } = {
      sub: user.id!,
      email: user.email!,
      username: user.username!,
    };

    if (sessionId) {
      payload.sessionId = sessionId;
    }

    const result: Record<string, unknown> = {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
      },
    };

    if (refreshToken) {
      result.refresh_token = refreshToken;
    }

    return result;
  }

  generateTemp2FAToken(userId: string) {
    return this.jwtService.sign(
      { sub: userId, type: '2FA_TEMP' },
      { expiresIn: '5m' },
    );
  }

  verifyTemp2FAToken(token: string): string | null {
    try {
      const payload: unknown = this.jwtService.verify(token);
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

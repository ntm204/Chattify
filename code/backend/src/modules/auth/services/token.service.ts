import { User } from '@prisma/client';
import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, createHash } from 'crypto';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RedisService } from '../../../core/redis/redis.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';

interface JwtPayload {
  sub: string;
  sessionId?: string;
  type?: string;
}

@Injectable()
export class TokenService {
  private readonly jwt2FASecret: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
  ) {
    this.jwt2FASecret = this.configService.getOrThrow<string>('JWT_2FA_SECRET');
  }

  private hashToken = (t: string) =>
    createHash('sha256').update(t).digest('hex');

  /**
   * Generates a device fingerprint based on User-Agent and IP portion.
   * This binds the session to a specific device/context.
   */
  private generateFingerprint(ip?: string, deviceInfo?: string): string {
    if (!ip && !deviceInfo) {
      throw new UnauthorizedException(
        'Không thể xác thực danh tính thiết bị. Vui lòng thử lại.',
      );
    }
    const data = `${deviceInfo || 'no-ua'}-${ip || 'no-ip'}`;
    return createHash('sha256').update(data).digest('hex');
  }

  private toSafeUserData = (u: Partial<User>) => ({
    id: u.id!,
    email: u.email ?? null,
    username: u.username!,
    displayName: u.displayName!,
    avatarUrl: u.avatarUrl ?? null,
  });

  async createSessionForUser(
    userId: string,
    ipAddress?: string,
    deviceInfo?: string,
    location?: string | null,
  ) {
    const fingerprint = this.generateFingerprint(ipAddress, deviceInfo);

    const { session, rawRefreshToken, user, sessionsToRevokeIds } =
      await this.prisma.$transaction(async (tx) => {
        const rawRefreshToken = randomBytes(32).toString('hex');
        const session = await tx.userSession.create({
          data: {
            userId,
            refreshToken: this.hashToken(rawRefreshToken),
            fingerprint,
            deviceInfo,
            ipAddress,
            location,
            expiresAt: new Date(Date.now() + AUTH_CONSTANTS.SESSION_EXPIRY_MS),
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
            .map((s) => s.id);
          await tx.userSession.updateMany({
            where: { id: { in: sessionsToRevokeIds } },
            data: { isRevoked: true },
          });
        }
        return { session, rawRefreshToken, user, sessionsToRevokeIds };
      });

    const redis = this.redisService.getClient();
    const pipeline = redis.pipeline();
    const safeUser = this.toSafeUserData(user!);

    pipeline.setex(
      `session:${session.id}`,
      AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
      JSON.stringify(safeUser),
    );
    pipeline.sadd(`user_sessions:${userId}`, session.id);
    sessionsToRevokeIds.forEach((id) => {
      pipeline.del(`session:${id}`);
      pipeline.srem(`user_sessions:${userId}`, id);
    });
    await pipeline.exec();

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
    if (!session) throw new NotFoundException(AUTH_MESSAGES.SESSION_NOT_FOUND);

    await this.prisma.userSession.update({
      where: { id: sessionId },
      data: { isRevoked: true },
    });
    const redis = this.redisService.getClient();
    await redis
      .pipeline()
      .del(`session:${sessionId}`)
      .srem(`user_sessions:${userId}`, sessionId)
      .exec();

    return { message: AUTH_MESSAGES.SESSION_REVOKE_SUCCESS };
  }

  async revokeAllSessions(userId: string) {
    await this.prisma.userSession.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true },
    });
    const dbSessions = await this.prisma.userSession.findMany({
      where: { userId },
      select: { id: true },
    });
    const redis = this.redisService.getClient();
    const activeRedisSessions = await redis.smembers(`user_sessions:${userId}`);
    const allIds = new Set([
      ...(activeRedisSessions || []),
      ...dbSessions.map((s) => s.id),
    ]);

    if (allIds.size === 0) return;
    const pipeline = redis.pipeline();
    allIds.forEach((id) => pipeline.del(`session:${id}`));
    pipeline.del(`user_sessions:${userId}`);
    await pipeline.exec();
  }

  async refreshTokens(
    refreshToken: string,
    ipAddress?: string,
    deviceInfo?: string,
  ): Promise<{ access_token: string; refresh_token: string; user: any }> {
    const hashedToken = this.hashToken(refreshToken);

    const reuseFlag = await this.redisService.getCache(
      `rotated_refresh:${hashedToken}`,
    );
    if (reuseFlag) {
      await this.revokeAllSessions(reuseFlag);
      throw new UnauthorizedException(
        AUTH_MESSAGES.REFRESH_TOKEN_REUSE_DETECTED,
      );
    }

    const session = await this.prisma.userSession.findFirst({
      where: { refreshToken: hashedToken, isRevoked: false },
      include: { user: true },
    });
    if (!session)
      throw new UnauthorizedException(AUTH_MESSAGES.REFRESH_TOKEN_INVALID);

    // Token Binding Check (Fingerprint) MUST be first to prevent Grace Period bypass
    const currentFingerprint = this.generateFingerprint(ipAddress, deviceInfo);
    if (session.fingerprint && session.fingerprint !== currentFingerprint) {
      await this.revokeSession(session.userId, session.id);
      throw new UnauthorizedException(
        'Phiên làm việc không hợp lệ (Phát hiện thay đổi thiết bị bất thường). Vui lòng đăng nhập lại.',
      );
    }

    // Grace Period Check
    const graceData = await this.redisService.getCache(
      `refresh_grace:${hashedToken}`,
    );
    if (graceData)
      return JSON.parse(graceData) as {
        access_token: string;
        refresh_token: string;
        user: any;
      };

    if (new Date() > session.expiresAt) {
      await this.revokeSession(session.userId, session.id);
      throw new UnauthorizedException(AUTH_MESSAGES.SESSION_EXPIRED);
    }

    const newRaw = randomBytes(32).toString('hex');
    await this.prisma.userSession.update({
      where: { id: session.id },
      data: { refreshToken: this.hashToken(newRaw) },
    });

    const tokens = this.generateTokens(session.user, session.id, newRaw);
    const redis = this.redisService.getClient();
    await redis
      .pipeline()
      .setex(
        `rotated_refresh:${hashedToken}`,
        AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
        session.userId,
      )
      .setex(
        `refresh_grace:${hashedToken}`,
        AUTH_CONSTANTS.REFRESH_TOKEN_GRACE_PERIOD_SECONDS,
        JSON.stringify(tokens),
      )
      .setex(
        `session:${session.id}`,
        AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
        JSON.stringify(this.toSafeUserData(session.user)),
      )
      .exec();

    return tokens;
  }

  generateTokens(
    user: Partial<User>,
    sessionId: string,
    refreshToken?: string,
  ) {
    return {
      access_token: this.jwtService.sign({ sub: user.id, sessionId }),
      refresh_token: refreshToken || '',
      user: this.toSafeUserData(user),
    };
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
      if (this.isJwtPayload(payload) && payload.type === '2FA_TEMP') {
        return payload.sub;
      }
      return null;
    } catch {
      return null;
    }
  }

  private isJwtPayload(payload: unknown): payload is JwtPayload {
    if (!payload || typeof payload !== 'object') return false;
    const p = payload as Record<string, unknown>;
    return (
      typeof p.sub === 'string' &&
      (!('type' in p) || typeof p.type === 'string')
    );
  }
}

import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { RedisService } from '../../../core/redis/redis.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { LogUtils } from '../../../core/utils/log.util';

/**
 * LockoutService
 * Manages dual-layer rate limiting and brute-force protection (Identifier + IP) via Redis.
 */
@Injectable()
export class LockoutService {
  private readonly logger = new Logger(LockoutService.name);

  constructor(private readonly redisService: RedisService) {}

  async checkAccountLockout(identifier: string): Promise<void> {
    const lockoutKey = `login_lockout:${identifier}`;
    const isLocked = await this.redisService.getCache(lockoutKey);
    if (isLocked) {
      const redisClient = this.redisService.getClient();
      const ttl = await redisClient.ttl(lockoutKey);
      const minutes = Math.ceil(ttl / 60);
      throw new UnauthorizedException({
        message: AUTH_MESSAGES.ACCOUNT_LOCKED(`${minutes} phút`),
        action: 'ACCOUNT_LOCKED',
        suggestion:
          'Nếu bạn quên mật khẩu, hãy sử dụng chức năng "Quên mật khẩu" để đặt lại.',
      });
    }
  }

  async checkIpLockout(ipAddress?: string): Promise<void> {
    if (!ipAddress) return;
    const ipLockoutKey = `login_lockout_ip:${ipAddress}`;
    const isLocked = await this.redisService.getCache(ipLockoutKey);
    if (isLocked) {
      const redisClient = this.redisService.getClient();
      const ttl = await redisClient.ttl(ipLockoutKey);
      const minutes = Math.ceil(ttl / 60);
      this.logger.warn(`Blocked login attempt from locked IP: ${ipAddress}`);
      throw new UnauthorizedException(
        AUTH_MESSAGES.IP_LOCKED(`${minutes} phút`),
      );
    }
  }

  async incrementLoginAttempts(
    identifier: string,
    ipAddress?: string,
  ): Promise<{ attempts: number; shouldWarn: boolean }> {
    const redisClient = this.redisService.getClient();

    const attemptsKey = `login_attempts:${identifier}`;
    const lockoutKey = `login_lockout:${identifier}`;

    const attempts = await redisClient.incr(attemptsKey);
    if (attempts === 1) {
      await redisClient.expire(
        attemptsKey,
        AUTH_CONSTANTS.LOCKOUT_DURATION_SECONDS,
      );
    }

    if (attempts >= AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS) {
      await this.redisService.setCache(
        lockoutKey,
        '1',
        AUTH_CONSTANTS.LOCKOUT_DURATION_SECONDS,
      );
      await this.redisService.deleteCache(attemptsKey);
      this.logger.warn(
        `Account lockout triggered for identifier: ${LogUtils.maskIdentifier(identifier)}`,
      );
    }

    if (ipAddress) {
      const ipAttemptsKey = `login_attempts_ip:${ipAddress}`;
      const ipLockoutKey = `login_lockout_ip:${ipAddress}`;

      const ipAttempts = await redisClient.incr(ipAttemptsKey);
      if (ipAttempts === 1) {
        await redisClient.expire(
          ipAttemptsKey,
          AUTH_CONSTANTS.IP_LOCKOUT_DURATION_SECONDS,
        );
      }

      if (ipAttempts >= AUTH_CONSTANTS.MAX_IP_ATTEMPTS) {
        await this.redisService.setCache(
          ipLockoutKey,
          '1',
          AUTH_CONSTANTS.IP_LOCKOUT_DURATION_SECONDS,
        );
        await this.redisService.deleteCache(ipAttemptsKey);
        this.logger.warn(`IP lockout triggered for IP (masked)`);
      }
    }

    const remaining = AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS - attempts;
    const shouldWarn =
      remaining > 0 && remaining <= AUTH_CONSTANTS.LOCKOUT_WARNING_THRESHOLD;

    return { attempts, shouldWarn };
  }

  async resetLoginAttempts(identifier: string): Promise<void> {
    await this.redisService.deleteCache(`login_attempts:${identifier}`);
    await this.redisService.deleteCache(`login_lockout:${identifier}`);
  }
}

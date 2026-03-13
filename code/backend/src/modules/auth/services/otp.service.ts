import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { MailService } from '../../../core/mail/mail.service';
import { randomInt, createHash } from 'crypto';
import { RedisService } from '../../../core/redis/redis.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);

  constructor(
    private readonly mailService: MailService,
    private readonly redisService: RedisService,
  ) {}

  async generateAndSendOtp(email: string, type: string = 'EMAIL_VERIFICATION') {
    const redisKey = `otp:${type}:${email}`;
    const cooldownKey = `otp_cooldown:${type}:${email}`;
    const attemptsKey = `otp_attempts:${type}:${email}`;

    // 1. Check cooldown FIRST to prevent racing the daily limits
    const isOnCooldown = await this.redisService.getCache(cooldownKey);
    if (isOnCooldown) {
      const redisClient = this.redisService.getClient();
      const ttl = await redisClient.ttl(cooldownKey);
      throw new BadRequestException(AUTH_MESSAGES.OTP_COOLDOWN(ttl));
    }

    // 2. Increment daily limit AFTER verifying not on cooldown
    const dailyLimitKey = `otp_daily:${type}:${email}`;
    const redisClient = this.redisService.getClient();
    const dailyCount = await redisClient.incr(dailyLimitKey);
    if (dailyCount === 1) {
      await redisClient.expire(dailyLimitKey, 86400);
    }
    if (dailyCount > AUTH_CONSTANTS.OTP_DAILY_LIMIT) {
      throw new BadRequestException(
        AUTH_MESSAGES.OTP_DAILY_LIMIT(AUTH_CONSTANTS.OTP_DAILY_LIMIT),
      );
    }

    const otp = randomInt(100000, 999999).toString();
    const otpHash = createHash('sha256').update(otp).digest('hex');
    await this.redisService.setCache(
      redisKey,
      otpHash,
      AUTH_CONSTANTS.OTP_TTL_SECONDS,
    );
    await this.redisService.setCache(
      cooldownKey,
      '1',
      AUTH_CONSTANTS.OTP_COOLDOWN_SECONDS,
    );
    await this.redisService.deleteCache(attemptsKey);

    try {
      if (type === 'PASSWORD_RESET') {
        await this.mailService.sendPasswordResetOtpEmail(email, otp);
      } else {
        await this.mailService.sendOtpEmail(email, otp);
      }
    } catch (error) {
      await this.redisService.deleteCache(redisKey);
      await this.redisService.deleteCache(cooldownKey);
      this.logger.error(
        `Mail send failed for ${email}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new BadRequestException(
        'Lỗi hệ thống Email. Vui lòng thử lại sau vài phút.',
      );
    }

    return { message: AUTH_MESSAGES.OTP_SENT_GENERIC };
  }

  async verifyOtp(
    email: string,
    otp: string,
    type: string = 'EMAIL_VERIFICATION',
  ) {
    const redisKey = `otp:${type}:${email}`;
    const attemptsKey = `otp_attempts:${type}:${email}`;

    const storedHash = await this.redisService.getCache(redisKey);

    if (!storedHash) {
      throw new BadRequestException(AUTH_MESSAGES.OTP_INVALID_OR_EXPIRED);
    }

    const inputHash = createHash('sha256').update(otp).digest('hex');
    if (storedHash !== inputHash) {
      const redisClient = this.redisService.getClient();
      const attempts = await redisClient.incr(attemptsKey);
      if (attempts === 1) {
        await redisClient.expire(attemptsKey, AUTH_CONSTANTS.OTP_TTL_SECONDS);
      }

      if (attempts >= AUTH_CONSTANTS.OTP_MAX_ATTEMPTS) {
        await this.redisService.deleteCache(redisKey);
        await this.redisService.deleteCache(attemptsKey);
        throw new BadRequestException(AUTH_MESSAGES.OTP_MAX_ATTEMPTS);
      }

      throw new BadRequestException(
        `Mã OTP không chính xác! Bạn còn ${AUTH_CONSTANTS.OTP_MAX_ATTEMPTS - attempts} lần thử.`,
      );
    }
    await this.redisService.deleteCache(redisKey);
    await this.redisService.deleteCache(attemptsKey);

    return true;
  }
}

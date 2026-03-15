import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { MailService } from '../../../core/mail/mail.service';
import { SmsService } from '../../../core/sms/sms.service';
import { randomInt, createHash } from 'crypto';
import { RedisService } from '../../../core/redis/redis.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { AuthUtils } from '../../../core/utils/auth.util';
import { LogUtils } from '../../../core/utils/log.util';
import {
  OtpPurpose,
  OTP_PURPOSE,
} from '../domain/constants/otp-purpose.constants';

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);

  constructor(
    private readonly mailService: MailService,
    private readonly smsService: SmsService,
    private readonly redisService: RedisService,
  ) {}

  async generateAndSendOtp(
    identifier: string,
    type: OtpPurpose = OTP_PURPOSE.VERIFICATION,
  ) {
    const normalizedIdentifier = AuthUtils.normalizeIdentifier(identifier);
    const identifierType = AuthUtils.getIdentifierType(normalizedIdentifier);

    if (identifierType === 'UNKNOWN') {
      throw new BadRequestException(
        'Định dạng Email hoặc Số điện thoại không hợp lệ.',
      );
    }

    const redisKey = `otp:${type}:${normalizedIdentifier}`;
    const cooldownKey = `otp_cooldown:${type}:${normalizedIdentifier}`;
    const attemptsKey = `otp_attempts:${type}:${normalizedIdentifier}`;

    // 1. Check cooldown FIRST
    const isOnCooldown = await this.redisService.getCache(cooldownKey);
    if (isOnCooldown) {
      const redisClient = this.redisService.getClient();
      const ttl = await redisClient.ttl(cooldownKey);
      throw new BadRequestException(AUTH_MESSAGES.OTP_COOLDOWN(ttl));
    }

    // 2. Increment daily limit
    const dailyLimitKey = `otp_daily:${type}:${normalizedIdentifier}`;
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
      if (identifierType === 'EMAIL') {
        if (type === 'PASSWORD_RESET') {
          await this.mailService.sendPasswordResetOtpEmail(
            normalizedIdentifier,
            otp,
          );
        } else {
          await this.mailService.sendOtpEmail(normalizedIdentifier, otp);
        }
      } else {
        // PHONE
        await this.smsService.sendOtp(normalizedIdentifier, otp);
      }
    } catch (error) {
      await this.redisService.deleteCache(redisKey);
      await this.redisService.deleteCache(cooldownKey);
      this.logger.error(
        `OTP send failed for ${LogUtils.maskIdentifier(normalizedIdentifier)}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new BadRequestException(
        `Lỗi hệ thống gửi mã xác thực. Vui lòng thử lại sau vài phút.`,
      );
    }

    return { message: AUTH_MESSAGES.OTP_SENT_GENERIC };
  }

  async verifyOtp(
    identifier: string,
    otp: string,
    type: OtpPurpose = OTP_PURPOSE.VERIFICATION,
  ) {
    const normalizedIdentifier = AuthUtils.normalizeIdentifier(identifier);
    const redisKey = `otp:${type}:${normalizedIdentifier}`;
    const attemptsKey = `otp_attempts:${type}:${normalizedIdentifier}`;

    // Use GET instead of GETDEL to allow retries on incorrect OTP
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
        // If max attempts reached or exceeded, set the attempts key to reflect this and prevent further attempts
        await this.redisService.setCache(
          attemptsKey,
          String(attempts), // Store the current attempt count
          AUTH_CONSTANTS.OTP_TTL_SECONDS,
        );
        throw new BadRequestException(AUTH_MESSAGES.OTP_MAX_ATTEMPTS);
      }

      const remaining = AUTH_CONSTANTS.OTP_MAX_ATTEMPTS - attempts;
      throw new BadRequestException(
        `Mã xác thực không chính xác! Bạn còn ${remaining} lần thử.`,
      );
    }

    // OTP verified successfully
    // Atomic check to prevent race condition (double verify)
    const redisClient = this.redisService.getClient();
    const deletedCount = await redisClient.del(redisKey);
    if (deletedCount === 0) {
      throw new BadRequestException(AUTH_MESSAGES.OTP_INVALID_OR_EXPIRED);
    }

    // Clear attempt counter upon success
    await this.redisService.deleteCache(attemptsKey);

    return true;
  }
}

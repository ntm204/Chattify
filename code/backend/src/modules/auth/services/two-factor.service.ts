import {
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RedisService } from '../../../core/redis/redis.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'crypto';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);
  private readonly encryptionKey: Buffer;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
  ) {
    const rawKey = this.configService.get<string>('TWO_FACTOR_ENCRYPTION_KEY');
    if (!rawKey) {
      throw new Error(
        'FATAL ERROR: TWO_FACTOR_ENCRYPTION_KEY environment variable is not defined!',
      );
    }
    const salt = this.configService.get<string>('TWO_FACTOR_SALT');
    if (!salt) {
      throw new Error(
        'FATAL ERROR: TWO_FACTOR_SALT environment variable is not defined!',
      );
    }
    this.encryptionKey = scryptSync(rawKey, salt, 32);
  }

  private encryptSecret(plaintext: string): string {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  private decryptSecret(ciphertext: string): string {
    try {
      const parts = ciphertext.split(':');
      if (parts.length !== 3) {
        throw new Error('Invalid encrypted format');
      }
      const [ivHex, authTagHex, encryptedHex] = parts;
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const encrypted = Buffer.from(encryptedHex, 'hex');

      const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ]);
      return decrypted.toString('utf8');
    } catch {
      this.logger.error('Failed to decrypt 2FA secret');
      throw new InternalServerErrorException(
        'Lỗi giải mã dữ liệu 2FA. Vui lòng liên hệ quản trị viên.',
      );
    }
  }

  async generateTwoFactorAuthSecret(userId: string, email: string) {
    const appName = AUTH_CONSTANTS.APP_NAME;
    const secretData = speakeasy.generateSecret({
      name: `${appName} (${email})`,
    });
    const secret = secretData.base32;
    const otpauthUrl = secretData.otpauth_url || '';
    const encryptedSecret = this.encryptSecret(secret);
    await this.prisma.twoFactorAuth.upsert({
      where: { userId },
      update: { secret: encryptedSecret, isEnabled: false },
      create: { userId, secret: encryptedSecret, isEnabled: false },
    });
    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);
    return {
      qrCodeDataUrl,
      message:
        'Quét mã QR bằng Google Authenticator, sau đó nhập mã 6 số để xác nhận.',
    };
  }

  async turnOnTwoFactorAuth(userId: string, code: string) {
    return this.verifyAndToggle2FA(userId, code, true);
  }

  async turnOffTwoFactorAuth(userId: string, code: string) {
    return this.verifyAndToggle2FA(userId, code, false);
  }

  /**
   * Shared brute-force check for all 2FA verification paths.
   * Increments attempts on failure, throws after MAX_ATTEMPTS.
   */
  private async check2FABruteForce(
    userId: string,
    isCodeValid: boolean,
  ): Promise<void> {
    const attemptsKey = `2fa_attempts:${userId}`;

    if (!isCodeValid) {
      const redisClient = this.redisService.getClient();
      const attempts = await redisClient.incr(attemptsKey);

      if (attempts === 1) {
        await redisClient.expire(
          attemptsKey,
          AUTH_CONSTANTS.TWO_FA_LOCKOUT_SECONDS,
        );
      }

      if (attempts >= AUTH_CONSTANTS.TWO_FA_MAX_ATTEMPTS) {
        throw new BadRequestException(
          `Bạn đã nhập sai mã 2FA quá ${AUTH_CONSTANTS.TWO_FA_MAX_ATTEMPTS} lần. Vui lòng thử lại sau 5 phút!`,
        );
      }

      throw new UnauthorizedException(
        `Mã 2FA không chính xác! Bạn còn ${AUTH_CONSTANTS.TWO_FA_MAX_ATTEMPTS - attempts} lần thử.`,
      );
    }

    await this.redisService.deleteCache(attemptsKey);
  }

  private async verifyAndToggle2FA(
    userId: string,
    code: string,
    enable: boolean,
  ) {
    const twoFactor = await this.prisma.twoFactorAuth.findUnique({
      where: { userId },
    });

    if (!twoFactor) throw new BadRequestException('Chưa tạo mã QR 2FA!');
    if (!enable && !twoFactor.isEnabled)
      throw new BadRequestException('2FA đang không được bật!');

    const decryptedSecret = this.decryptSecret(twoFactor.secret);
    const isCodeValid = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token: code,
    });

    await this.check2FABruteForce(userId, isCodeValid);

    await this.prisma.twoFactorAuth.update({
      where: { userId },
      data: { isEnabled: enable },
    });

    return {
      message: enable
        ? 'Xác minh và Bật 2FA thành công!'
        : 'Đã tắt 2FA thành công!',
    };
  }

  async verifyCode(userId: string, code: string, isEnabling: boolean = false) {
    const twoFactor = await this.prisma.twoFactorAuth.findUnique({
      where: { userId },
    });

    if (!twoFactor) return false;
    if (!isEnabling && !twoFactor.isEnabled) return false;
    const decryptedSecret = this.decryptSecret(twoFactor.secret);
    const isCodeValid = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token: code,
    });

    await this.check2FABruteForce(userId, isCodeValid);

    return true;
  }
}

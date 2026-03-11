import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RedisService } from '../../../core/redis/redis.service';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

@Injectable()
export class TwoFactorService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
  ) {}

  async generateTwoFactorAuthSecret(userId: string, email: string) {
    // Sinh 1 khoá bí mật
    const appName = 'Chatiffy Enterprise';
    const secretData = speakeasy.generateSecret({
      name: `${appName} (${email})`,
    });
    const secret = secretData.base32;
    const otpauthUrl = secretData.otpauth_url || '';

    // Lưu hoặc Ghi đè vào Database (trạng thái isEnabled = false chờ xác nhận)
    await this.prisma.twoFactorAuth.upsert({
      where: { userId },
      update: { secret, isEnabled: false },
      create: { userId, secret, isEnabled: false },
    });

    // Chuyển URI thành mã QR dạng Base64 Image
    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);
    return {
      secret,
      qrCodeDataUrl,
    };
  }

  async turnOnTwoFactorAuth(userId: string, code: string) {
    const twoFactor = await this.prisma.twoFactorAuth.findUnique({
      where: { userId },
    });

    if (!twoFactor) throw new BadRequestException('Chưa tạo mã QR 2FA!');

    const isCodeValid = speakeasy.totp.verify({
      secret: twoFactor.secret,
      encoding: 'base32',
      token: code,
    });

    if (!isCodeValid)
      throw new UnauthorizedException('Mã 2FA không chính xác!');

    // Bật 2FA
    await this.prisma.twoFactorAuth.update({
      where: { userId },
      data: { isEnabled: true },
    });

    return { message: 'Xác minh và Bật 2FA thành công!' };
  }

  async turnOffTwoFactorAuth(userId: string, code: string) {
    const twoFactor = await this.prisma.twoFactorAuth.findUnique({
      where: { userId },
    });

    if (!twoFactor || !twoFactor.isEnabled)
      throw new BadRequestException('2FA đang không được bật!');

    const isCodeValid = speakeasy.totp.verify({
      secret: twoFactor.secret,
      encoding: 'base32',
      token: code,
    });

    if (!isCodeValid)
      throw new UnauthorizedException('Mã 2FA không chính xác!');

    // Tắt 2FA
    await this.prisma.twoFactorAuth.update({
      where: { userId },
      data: { isEnabled: false },
    });

    return { message: 'Đã tắt 2FA thành công!' };
  }

  async verifyCode(userId: string, code: string, isEnabling: boolean = false) {
    const attemptsKey = `2fa_attempts:${userId}`;

    const twoFactor = await this.prisma.twoFactorAuth.findUnique({
      where: { userId },
    });

    if (!twoFactor) return false;
    if (!isEnabling && !twoFactor.isEnabled) return false;

    const isCodeValid = speakeasy.totp.verify({
      secret: twoFactor.secret,
      encoding: 'base32',
      token: code,
    });

    if (!isCodeValid) {
      const redisClient = this.redisService.getClient();
      const attempts = await redisClient.incr(attemptsKey);

      if (attempts === 1) {
        await redisClient.expire(attemptsKey, 300); // Khoá 5 phút
      }

      if (attempts >= 5) {
        throw new BadRequestException(
          'Bạn đã nhập sai mã 2FA quá 5 lần. Vui lòng thử lại sau 5 phút!',
        );
      }

      throw new UnauthorizedException(
        `Mã 2FA không chính xác! Bạn còn ${5 - attempts} lần thử.`,
      );
    }

    // Nếu đúng thì xoá bộ đếm
    await this.redisService.deleteCache(attemptsKey);

    return true;
  }
}

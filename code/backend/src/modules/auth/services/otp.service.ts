import { Injectable, BadRequestException } from '@nestjs/common';
import { MailService } from '../../../core/mail/mail.service';
import { randomInt } from 'crypto';
import { RedisService } from '../../../core/redis/redis.service';

@Injectable()
export class OtpService {
  constructor(
    private readonly mailService: MailService,
    private readonly redisService: RedisService,
  ) {}

  async generateAndSendOtp(email: string, type: string = 'EMAIL_VERIFICATION') {
    const redisKey = `otp:${type}:${email}`;
    const cooldownKey = `otp_cooldown:${type}:${email}`;
    const attemptsKey = `otp_attempts:${type}:${email}`;

    // 1. Kiểm tra Cooldown 60s
    const isOnCooldown = await this.redisService.getCache(cooldownKey);
    if (isOnCooldown) {
      const redisClient = this.redisService.getClient();
      const ttl = await redisClient.ttl(cooldownKey);
      throw new BadRequestException(
        `Vui lòng đợi ${ttl} giây trước khi yêu cầu gửi lại OTP.`,
      );
    }

    const otp = randomInt(100000, 999999).toString();

    // 2. Lưu OTP vào Redis với TTL 5 phút (300 giây)
    await this.redisService.setCache(redisKey, otp, 300);

    // 3. Đặt Cooldown 60 giây
    await this.redisService.setCache(cooldownKey, '1', 60);

    // Xoá bộ đếm số lần nhập sai cũ nếu có
    await this.redisService.deleteCache(attemptsKey);

    try {
      // await để đảm bảo catch được lỗi, tránh trường hợp SMTP sập người dùng bị khoá 60s vô cớ
      if (type === 'PASSWORD_RESET') {
        await this.mailService.sendPasswordResetOtpEmail(email, otp);
      } else {
        await this.mailService.sendOtpEmail(email, otp);
      }
    } catch (error) {
      // Revert state nếu mail lỗi
      await this.redisService.deleteCache(redisKey);
      await this.redisService.deleteCache(cooldownKey);
      console.error('Mail Send Error:', error);
      throw new BadRequestException(
        'Lỗi hệ thống Email. Vui lòng thử lại sau vài phút.',
      );
    }

    return { message: 'Mã OTP đã được gửi đến email của bạn.' };
  }

  async verifyOtp(
    email: string,
    otp: string,
    type: string = 'EMAIL_VERIFICATION',
  ) {
    const redisKey = `otp:${type}:${email}`;
    const attemptsKey = `otp_attempts:${type}:${email}`;

    const storedOtp = await this.redisService.getCache(redisKey);

    if (!storedOtp) {
      throw new BadRequestException('Mã OTP không chính xác hoặc đã hết hạn!');
    }

    if (storedOtp !== otp) {
      const redisClient = this.redisService.getClient();
      const attempts = await redisClient.incr(attemptsKey);

      // Nếu lần đầu sai, set expire cho key đếm này cùng thời gian tồn tại của OTP
      if (attempts === 1) {
        await redisClient.expire(attemptsKey, 300);
      }

      if (attempts >= 5) {
        // Xóa OTP khỏi Redis và xóa luôn bộ đếm để ép user phải xin gửi lại
        await this.redisService.deleteCache(redisKey);
        await this.redisService.deleteCache(attemptsKey);
        throw new BadRequestException(
          'Bạn đã nhập sai quá 5 lần. Mã OTP đã bị huỷ vì lý do bảo mật, vui lòng yêu cầu mã mới!',
        );
      }

      throw new BadRequestException(
        `Mã OTP không chính xác! Bạn còn ${5 - attempts} lần thử.`,
      );
    }

    // Xoá OTP sau khi verify thành công
    await this.redisService.deleteCache(redisKey);
    await this.redisService.deleteCache(attemptsKey);

    return true;
  }
}

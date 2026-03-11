import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { UsersService } from '../../users/users.service';
import { TokenService } from './token.service';
import { OtpService } from './otp.service';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import * as bcrypt from 'bcrypt';

/**
 * PasswordService
 * Handles password-related operations (Forgot, Reset, Change) independently of AuthService.
 */
@Injectable()
export class PasswordService {
  private readonly logger = new Logger(PasswordService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
  ) {}

  async forgotPassword(data: ForgotPasswordDto) {
    const genericResponse = {
      message: 'Nếu email hợp lệ, hệ thống sẽ gửi mã OTP đến cho bạn.',
    };

    const user = await this.usersService.findByEmail(data.email);
    if (!user) {
      await new Promise((resolve) =>
        setTimeout(resolve, AUTH_CONSTANTS.TIMING_DELAY_MS),
      );
      return genericResponse;
    }

    await this.otpService.generateAndSendOtp(user.email, 'PASSWORD_RESET');
    return genericResponse;
  }

  async resetPassword(data: ResetPasswordDto) {
    await this.otpService.verifyOtp(data.email, data.otp, 'PASSWORD_RESET');

    const passwordHash = await bcrypt.hash(
      data.newPassword,
      AUTH_CONSTANTS.SALT_ROUNDS,
    );

    const user = await this.prisma.user.update({
      where: { email: data.email },
      data: { passwordHash },
    });

    await this.prisma.authLog.create({
      data: {
        userId: user.id,
        action: 'PASSWORD_RESET',
        status: 'SUCCESS',
      },
    });

    await this.tokenService.revokeAllSessions(user.id);

    this.logger.log(`Password reset successful for userId: ${user.id}`);

    return {
      message:
        'Đổi mật khẩu thành công! Vui lòng sử dụng mật khẩu mới để đăng nhập.',
    };
  }

  async changePassword(userId: string, data: ChangePasswordDto) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('Người dùng không tồn tại');

    const isMatch = await bcrypt.compare(data.oldPassword, user.passwordHash);
    if (!isMatch) {
      throw new BadRequestException('Mật khẩu cũ không chính xác');
    }

    if (data.oldPassword === data.newPassword) {
      throw new BadRequestException('Mật khẩu mới phải khác mật khẩu cũ!');
    }

    const passwordHash = await bcrypt.hash(
      data.newPassword,
      AUTH_CONSTANTS.SALT_ROUNDS,
    );

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    await this.prisma.authLog.create({
      data: {
        userId,
        action: 'PASSWORD_CHANGE',
        status: 'SUCCESS',
      },
    });

    await this.tokenService.revokeAllSessions(userId);

    this.logger.log(`Password changed successfully for userId: ${userId}`);

    return {
      message: 'Đã thay đổi mật khẩu thành công. Vui lòng đăng nhập lại!',
    };
  }
}

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
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { getLocationFromIp } from '../../../core/utils/geo.util';
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
      message: AUTH_MESSAGES.FORGOT_PASSWORD_GENERIC,
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

  async resetPassword(
    data: ResetPasswordDto,
    context?: { ipAddress?: string; deviceInfo?: string },
  ) {
    await this.otpService.verifyOtp(data.email, data.otp, 'PASSWORD_RESET');

    const passwordHash = await bcrypt.hash(
      data.newPassword,
      AUTH_CONSTANTS.SALT_ROUNDS,
    );

    const user = await this.prisma.user.update({
      where: { email: data.email },
      data: { passwordHash },
    });

    const location = getLocationFromIp(context?.ipAddress);

    await this.prisma.authLog.create({
      data: {
        userId: user.id,
        action: 'PASSWORD_RESET',
        status: 'SUCCESS',
        ipAddress: context?.ipAddress,
        location,
        deviceInfo: context?.deviceInfo,
      },
    });

    await this.tokenService.revokeAllSessions(user.id);

    this.logger.log(`Password reset successful for userId: ${user.id}`);

    return {
      message: AUTH_MESSAGES.CHANGE_PASSWORD_SUCCESS,
    };
  }

  async changePassword(
    userId: string,
    data: ChangePasswordDto,
    context?: { ipAddress?: string; deviceInfo?: string },
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException(AUTH_MESSAGES.USER_NOT_FOUND);

    const isMatch = await bcrypt.compare(data.oldPassword, user.passwordHash);
    if (!isMatch) {
      throw new BadRequestException(AUTH_MESSAGES.OLD_PASSWORD_INCORRECT);
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

    const location = getLocationFromIp(context?.ipAddress);

    await this.prisma.authLog.create({
      data: {
        userId,
        action: 'PASSWORD_CHANGE',
        status: 'SUCCESS',
        ipAddress: context?.ipAddress,
        location,
        deviceInfo: context?.deviceInfo,
      },
    });

    await this.tokenService.revokeAllSessions(userId);

    this.logger.log(`Password changed successfully for userId: ${userId}`);

    return {
      message: AUTH_MESSAGES.CHANGE_PASSWORD_SUCCESS,
    };
  }
}

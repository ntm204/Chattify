import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { OtpService } from './otp.service';
import { TokenService } from './token.service';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { AuthUtils } from '../../../core/utils/auth.util';
import { getLocationFromIp } from '../../../core/utils/geo.util';
import { AuthAuditService } from './auth-audit.service';
import {
  AUTH_EVENT_ACTIONS,
  AUTH_EVENT_STATUS,
} from '../constants/auth-events.constants';
import { OTP_PURPOSE } from '../domain/constants/otp-purpose.constants';
import { AuthRequestContext } from '../domain/types/auth-context.type';
import { MailService } from '../../../core/mail/mail.service';

@Injectable()
export class PasswordService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly otpService: OtpService,
    private readonly tokenService: TokenService,
    private readonly authAuditService: AuthAuditService,
    private readonly mailService: MailService,
  ) {}

  async forgotPassword(dto: ForgotPasswordDto) {
    const identifier = AuthUtils.normalizeIdentifier(dto.identifier);
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: identifier }, { phone: identifier }],
      },
    });

    // Anti-enumeration: always return success even if user not found
    if (user) {
      await this.otpService.generateAndSendOtp(
        identifier,
        OTP_PURPOSE.PASSWORD_RESET,
      );
    } else {
      // Small delay to simulate work and mitigate timing attacks
      await AuthUtils.applyTimingDelay();
    }

    return { message: AUTH_MESSAGES.FORGOT_PASSWORD_GENERIC };
  }

  async resetPassword(dto: ResetPasswordDto, context: AuthRequestContext) {
    const identifier = AuthUtils.normalizeIdentifier(dto.identifier);
    await this.otpService.verifyOtp(
      identifier,
      dto.otp,
      OTP_PURPOSE.PASSWORD_RESET,
    );

    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: identifier }, { phone: identifier }],
      },
    });

    if (!user) {
      throw new BadRequestException(AUTH_MESSAGES.ACCOUNT_NOT_FOUND_OR_DELETED);
    }

    // Security Check: HIBP
    if (await AuthUtils.isPasswordPwned(dto.newPassword)) {
      throw new BadRequestException(AUTH_MESSAGES.PASSWORD_PWNED_ERROR);
    }

    const passwordHash = await AuthUtils.hashPassword(dto.newPassword);

    await this.prisma.$transaction(async (tx) => {
      // Manage Password History (Limit to 5)
      const histories = await tx.passwordHistory.findMany({
        where: { userId: user.id },
        orderBy: { createdAt: 'desc' },
      });

      // Check reuse against current password
      if (
        user.passwordHash &&
        (await AuthUtils.verifyPassword(user.passwordHash, dto.newPassword))
      ) {
        throw new BadRequestException(AUTH_MESSAGES.PASSWORD_REUSE_ERROR);
      }

      // Check reuse against history
      for (const history of histories) {
        if (
          await AuthUtils.verifyPassword(history.passwordHash, dto.newPassword)
        ) {
          throw new BadRequestException(AUTH_MESSAGES.PASSWORD_REUSE_ERROR);
        }
      }

      await tx.user.update({
        where: { id: user.id },
        data: { passwordHash, isVerified: true },
      });

      await tx.passwordHistory.create({
        data: { userId: user.id, passwordHash },
      });

      if (histories.length >= 5) {
        const oldestIds = histories.slice(4).map((h) => h.id);
        await tx.passwordHistory.deleteMany({
          where: { id: { in: oldestIds } },
        });
      }

      await this.authAuditService.log(
        {
          userId: user.id,
          action: AUTH_EVENT_ACTIONS.PASSWORD_RESET_SUCCESS,
          status: AUTH_EVENT_STATUS.SUCCESS,
          ipAddress: context.ipAddress,
          deviceInfo: context.deviceInfo,
          location: getLocationFromIp(context.ipAddress),
        },
        tx,
      );
    });

    await this.tokenService.revokeAllSessions(user.id);

    // Async notify (Don't wait for email to return success to user)
    if (user.email) {
      void this.mailService
        .sendSecurityAlertEmail(user.email, 'Mật khẩu đã được đặt lại', {
          ip: context.ipAddress || 'Không rõ',
          device: context.deviceInfo || 'Thiết bị lạ',
          location: getLocationFromIp(context.ipAddress) || 'Không rõ',
        })
        .catch(() => {});
    }

    return { message: AUTH_MESSAGES.RESET_PASSWORD_SUCCESS };
  }

  async changePassword(
    userId: string,
    dto: ChangePasswordDto,
    context: AuthRequestContext,
  ) {
    // Security Check: HIBP
    if (await AuthUtils.isPasswordPwned(dto.newPassword)) {
      throw new BadRequestException(AUTH_MESSAGES.PASSWORD_PWNED_ERROR);
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.passwordHash) {
      throw new UnauthorizedException(AUTH_MESSAGES.USER_NOT_FOUND);
    }

    const isOldPasswordValid = await AuthUtils.verifyPassword(
      user.passwordHash,
      dto.oldPassword,
    );

    if (!isOldPasswordValid) {
      throw new BadRequestException(AUTH_MESSAGES.OLD_PASSWORD_INCORRECT);
    }

    const newPasswordHash = await AuthUtils.hashPassword(dto.newPassword);

    await this.prisma.$transaction(async (tx) => {
      // Manage Password History (Limit to 5)
      const histories = await tx.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });

      // Check reuse against current password
      if (
        user.passwordHash &&
        (await AuthUtils.verifyPassword(user.passwordHash, dto.newPassword))
      ) {
        throw new BadRequestException(AUTH_MESSAGES.PASSWORD_REUSE_ERROR);
      }

      // Check reuse against history
      for (const history of histories) {
        if (
          await AuthUtils.verifyPassword(history.passwordHash, dto.newPassword)
        ) {
          throw new BadRequestException(AUTH_MESSAGES.PASSWORD_REUSE_ERROR);
        }
      }

      await tx.user.update({
        where: { id: userId },
        data: { passwordHash: newPasswordHash },
      });

      await tx.passwordHistory.create({
        data: { userId, passwordHash: newPasswordHash },
      });

      if (histories.length >= 5) {
        const oldestIds = histories.slice(4).map((h) => h.id);
        await tx.passwordHistory.deleteMany({
          where: { id: { in: oldestIds } },
        });
      }

      await this.authAuditService.log(
        {
          userId,
          action: AUTH_EVENT_ACTIONS.PASSWORD_CHANGE_SUCCESS,
          status: AUTH_EVENT_STATUS.SUCCESS,
          ipAddress: context.ipAddress,
          deviceInfo: context.deviceInfo,
          location: getLocationFromIp(context.ipAddress),
        },
        tx,
      );
    });

    await this.tokenService.revokeAllSessions(userId);

    // Async notify
    if (user.email) {
      void this.mailService
        .sendSecurityAlertEmail(user.email, 'Mật khẩu đã được thay đổi', {
          ip: context.ipAddress || 'Không rõ',
          device: context.deviceInfo || 'Thiết bị lạ',
          location: getLocationFromIp(context.ipAddress) || 'Không rõ',
        })
        .catch(() => {});
    }

    return { message: AUTH_MESSAGES.CHANGE_PASSWORD_SUCCESS };
  }
}

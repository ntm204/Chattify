import { BadRequestException } from '@nestjs/common';
import { AUTH_MESSAGES } from '../../../../core/config/auth.messages';
import { AuthUtils } from '../../../../core/utils/auth.util';
import { UsersService } from '../../../users/users.service';
import { OtpService } from '../../services/otp.service';

interface ResendOtpUseCaseDeps {
  usersService: UsersService;
  otpService: OtpService;
}

export async function executeResendOtp(
  deps: ResendOtpUseCaseDeps,
  identifier: string,
): Promise<{ message: string }> {
  if (!identifier) {
    throw new BadRequestException(AUTH_MESSAGES.IDENTIFIER_REQUIRED);
  }

  const user = await deps.usersService.findByIdentifier(identifier);

  if (!user || user.isVerified) {
    await AuthUtils.applyTimingDelay();
    return { message: AUTH_MESSAGES.OTP_SENT_GENERIC };
  }

  await deps.otpService.generateAndSendOtp(identifier);

  return { message: AUTH_MESSAGES.OTP_SENT_GENERIC };
}

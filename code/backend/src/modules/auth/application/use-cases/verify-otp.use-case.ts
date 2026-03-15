import { BadRequestException } from '@nestjs/common';
import { AUTH_MESSAGES } from '../../../../core/config/auth.messages';
import { AuthResponse } from '../../domain/contracts/auth.contract';
import { VerifyOtpPayload } from '../../dto/verify-otp.dto';
import { UsersService } from '../../../users/users.service';
import { OtpService } from '../../services/otp.service';
import { AUTH_EVENT_ACTIONS } from '../../constants/auth-events.constants';
import { FinalizeLoginFn } from './use-case.types';

interface VerifyOtpUseCaseDeps {
  otpService: OtpService;
  usersService: UsersService;
  finalizeLogin: FinalizeLoginFn<
    VerifyOtpPayload,
    typeof AUTH_EVENT_ACTIONS.LOGIN_SUCCESS
  >;
}

export async function executeVerifyOtp(
  deps: VerifyOtpUseCaseDeps,
  data: VerifyOtpPayload,
): Promise<AuthResponse> {
  await deps.otpService.verifyOtp(data.identifier, data.otp);
  const user = await deps.usersService.findByIdentifier(data.identifier);

  if (!user) {
    throw new BadRequestException(AUTH_MESSAGES.ACCOUNT_NOT_FOUND_OR_DELETED);
  }

  await deps.usersService.markIdentifierVerified(data.identifier);

  return deps.finalizeLogin({
    user,
    context: data,
    action: AUTH_EVENT_ACTIONS.LOGIN_SUCCESS,
    message: AUTH_MESSAGES.LOGIN_SUCCESS,
  });
}

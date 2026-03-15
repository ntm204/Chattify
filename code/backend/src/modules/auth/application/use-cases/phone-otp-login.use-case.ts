import { InternalServerErrorException } from '@nestjs/common';
import { AUTH_MESSAGES } from '../../../../core/config/auth.messages';
import { AuthResponse } from '../../domain/contracts/auth.contract';
import { VerifyPhoneOtpDto } from '../../dto/phone-auth.dto';
import { OTP_PURPOSE } from '../../domain/constants/otp-purpose.constants';
import { UsersService } from '../../../users/users.service';
import { OtpService } from '../../services/otp.service';
import { AUTH_EVENT_ACTIONS } from '../../constants/auth-events.constants';
import { FinalizeLoginFn } from './use-case.types';

interface PhoneOtpLoginUseCaseDeps {
  otpService: OtpService;
  usersService: UsersService;
  finalizeLogin: FinalizeLoginFn<
    VerifyPhoneOtpDto,
    | typeof AUTH_EVENT_ACTIONS.REGISTER_PHONE_SUCCESS
    | typeof AUTH_EVENT_ACTIONS.LOGIN_PHONE_SUCCESS
  >;
}

export async function executePhoneOtpLogin(
  deps: PhoneOtpLoginUseCaseDeps,
  data: VerifyPhoneOtpDto,
): Promise<AuthResponse> {
  await deps.otpService.verifyOtp(
    data.phoneNumber,
    data.otp,
    OTP_PURPOSE.PHONE_LOGIN,
  );

  let user = await deps.usersService.findByIdentifier(data.phoneNumber);
  const isNewUser = !user;

  if (isNewUser) {
    user = await deps.usersService.createPhoneUser(data.phoneNumber);
  }

  if (!user) {
    throw new InternalServerErrorException('User creation/lookup failed');
  }

  const action = isNewUser
    ? AUTH_EVENT_ACTIONS.REGISTER_PHONE_SUCCESS
    : AUTH_EVENT_ACTIONS.LOGIN_PHONE_SUCCESS;

  return deps.finalizeLogin({
    user,
    context: data,
    action,
    message: isNewUser
      ? AUTH_MESSAGES.REGISTER_PHONE_SUCCESS
      : AUTH_MESSAGES.LOGIN_PHONE_SUCCESS,
    isNewUser,
  });
}

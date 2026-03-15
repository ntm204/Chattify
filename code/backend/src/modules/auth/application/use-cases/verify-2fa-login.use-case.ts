import { UnauthorizedException } from '@nestjs/common';
import { AUTH_MESSAGES } from '../../../../core/config/auth.messages';
import { AuthResponse } from '../../domain/contracts/auth.contract';
import { AuthRequestContext } from '../../domain/types/auth-context.type';
import { UsersService } from '../../../users/users.service';
import { TokenService } from '../../services/token.service';
import { TwoFactorService } from '../../services/two-factor.service';
import { AUTH_EVENT_ACTIONS } from '../../constants/auth-events.constants';
import { FinalizeLoginFn } from './use-case.types';

interface Verify2FALoginUseCaseDeps {
  tokenService: TokenService;
  twoFactorService: TwoFactorService;
  usersService: UsersService;
  finalizeLogin: FinalizeLoginFn<
    AuthRequestContext,
    typeof AUTH_EVENT_ACTIONS.LOGIN_SUCCESS_2FA
  >;
}

export async function executeVerify2FALogin(
  deps: Verify2FALoginUseCaseDeps,
  tempToken: string,
  code: string,
  context: AuthRequestContext,
): Promise<AuthResponse> {
  const userId = deps.tokenService.verifyTemp2FAToken(tempToken);
  if (!userId) {
    throw new UnauthorizedException(AUTH_MESSAGES.TFA_TEMP_TOKEN_INVALID);
  }

  if (!(await deps.twoFactorService.verifyCode(userId, code))) {
    throw new UnauthorizedException(AUTH_MESSAGES.TFA_NOT_ENABLED);
  }

  const user = await deps.usersService.findById(userId);
  if (!user) {
    throw new UnauthorizedException(AUTH_MESSAGES.USER_NOT_FOUND);
  }

  return deps.finalizeLogin({
    user,
    context,
    action: AUTH_EVENT_ACTIONS.LOGIN_SUCCESS_2FA,
    message: AUTH_MESSAGES.LOGIN_SUCCESS,
  });
}

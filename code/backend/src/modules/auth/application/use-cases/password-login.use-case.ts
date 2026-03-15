import { UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../../../core/prisma/prisma.service';
import { AUTH_MESSAGES } from '../../../../core/config/auth.messages';
import { AuthUtils } from '../../../../core/utils/auth.util';
import {
  Auth2FAChallenge,
  AuthResponse,
} from '../../domain/contracts/auth.contract';
import { LoginPayload } from '../../dto/login.dto';
import { UsersService } from '../../../users/users.service';
import { LockoutService } from '../../services/lockout.service';
import { TokenService } from '../../services/token.service';
import { AuthAuditService } from '../../services/auth-audit.service';
import { FinalizeLoginFn } from './use-case.types';
import {
  AUTH_EVENT_ACTIONS,
  AUTH_EVENT_STATUS,
} from '../../constants/auth-events.constants';

interface PasswordLoginUseCaseDeps {
  usersService: UsersService;
  lockoutService: LockoutService;
  prisma: PrismaService;
  tokenService: TokenService;
  authAuditService: AuthAuditService;
  finalizeLogin: FinalizeLoginFn<
    { ipAddress?: string; deviceInfo?: string },
    typeof AUTH_EVENT_ACTIONS.LOGIN_SUCCESS
  >;
}

export async function executePasswordLogin(
  deps: PasswordLoginUseCaseDeps,
  data: LoginPayload,
): Promise<AuthResponse | Auth2FAChallenge> {
  const identifier = AuthUtils.normalizeIdentifier(data.identifier);

  await deps.lockoutService.checkIpLockout(data.ipAddress);
  await deps.lockoutService.checkAccountLockout(identifier);

  const user = await deps.usersService.findByIdentifierWithPassword(identifier);

  if (user && !user.passwordHash) {
    await AuthUtils.applyTimingDelay();
    await deps.lockoutService.incrementLoginAttempts(
      identifier,
      data.ipAddress,
    );
    throw new UnauthorizedException(AUTH_MESSAGES.PHONE_LOGIN_REQUIRED);
  }

  const isValid = await AuthUtils.verifyPasswordOrDelay(
    user?.passwordHash,
    data.password,
  );

  if (!user || !isValid) {
    const { shouldWarn } = await deps.lockoutService.incrementLoginAttempts(
      identifier,
      data.ipAddress,
    );

    await deps.authAuditService.log({
      userId: user?.id,
      action: AUTH_EVENT_ACTIONS.LOGIN_FAILED,
      status: AUTH_EVENT_STATUS.FAILED,
      ipAddress: data.ipAddress,
      deviceInfo: data.deviceInfo,
      failureReason: AUTH_MESSAGES.INVALID_CREDENTIALS,
    });

    throw new UnauthorizedException(
      shouldWarn
        ? AUTH_MESSAGES.INVALID_CREDENTIALS_WARNING
        : AUTH_MESSAGES.INVALID_CREDENTIALS,
    );
  }

  await deps.lockoutService.resetLoginAttempts(identifier);

  if (!user.isVerified) {
    throw new UnauthorizedException({
      message: AuthUtils.isEmail(identifier)
        ? AUTH_MESSAGES.VERIFY_EMAIL_REQUIRED
        : AUTH_MESSAGES.VERIFY_PHONE_REQUIRED,
      action: AuthUtils.isEmail(identifier)
        ? 'VERIFY_EMAIL_REQUIRED'
        : 'VERIFY_PHONE_REQUIRED',
      identifier,
    });
  }

  const twoFactor = await deps.prisma.twoFactorAuth.findUnique({
    where: { userId: user.id },
  });

  if (twoFactor?.isEnabled) {
    return {
      requires2FA: true,
      message: AUTH_MESSAGES.TFA_REQUIRED,
      tempToken: deps.tokenService.generateTemp2FAToken(user.id),
    };
  }

  return deps.finalizeLogin({
    user,
    context: data,
    action: AUTH_EVENT_ACTIONS.LOGIN_SUCCESS,
    message: AUTH_MESSAGES.LOGIN_SUCCESS,
  });
}

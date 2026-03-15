import { User } from '@prisma/client';
import { getLocationFromIp } from '../../../../core/utils/geo.util';
import { mapAuthResponse } from '../../domain/mappers/auth-response.mapper';
import {
  AuthEventAction,
  AUTH_EVENT_STATUS,
} from '../../constants/auth-events.constants';
import { AuthRequestContext } from '../../domain/types/auth-context.type';
import { AuthResponse } from '../../domain/contracts/auth.contract';
import { TokenService } from '../../services/token.service';
import { AuthAuditService } from '../../services/auth-audit.service';
import { MailService } from '../../../../core/mail/mail.service';

interface FinalizeLoginUseCaseDeps {
  tokenService: TokenService;
  authAuditService: AuthAuditService;
  mailService: MailService;
}

interface FinalizeLoginInput {
  user: Partial<User> & { id: string };
  context: AuthRequestContext;
  action: AuthEventAction;
  message: string;
  isNewUser?: boolean;
}

export async function executeFinalizeLogin(
  deps: FinalizeLoginUseCaseDeps,
  input: FinalizeLoginInput,
): Promise<AuthResponse> {
  const location = getLocationFromIp(input.context.ipAddress);

  // Security Check: New Device Detection
  const isNewDevice = await deps.authAuditService.isNewDevice(
    input.user.id,
    input.context.deviceInfo,
  );

  const session = await deps.tokenService.createSessionForUser(
    input.user.id,
    input.context.ipAddress,
    input.context.deviceInfo,
    location,
  );

  await deps.authAuditService.log({
    userId: input.user.id,
    action: input.action,
    status: AUTH_EVENT_STATUS.SUCCESS,
    ipAddress: input.context.ipAddress,
    deviceInfo: input.context.deviceInfo,
    location,
  });

  if (isNewDevice && input.user.email) {
    void deps.mailService
      .sendSecurityAlertEmail(input.user.email, 'Đăng nhập từ thiết bị mới', {
        ip: input.context.ipAddress || 'Không rõ',
        device: input.context.deviceInfo || 'Thiết bị lạ',
        location: location || 'Không rõ',
      })
      .catch(() => {});
  }

  const tokens = deps.tokenService.generateTokens(
    input.user,
    session.id,
    session.refreshToken,
  );

  return mapAuthResponse(
    tokens,
    input.user,
    input.message,
    input.isNewUser ?? false,
  );
}

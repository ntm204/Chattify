import {
  Injectable,
  Logger,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { User } from '@prisma/client';
import { UsersService } from '../../users/users.service';
import { CreateUserStatus } from '../../users/interfaces/user.interface';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginPayload } from '../dto/login.dto';
import { VerifyOtpPayload } from '../dto/verify-otp.dto';
import { SendPhoneOtpDto, VerifyPhoneOtpDto } from '../dto/phone-auth.dto';
import { TokenService } from './token.service';
import { OtpService } from './otp.service';
import { TwoFactorService } from './two-factor.service';
import { LockoutService } from './lockout.service';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { AuthUtils } from '../../../core/utils/auth.util';
import { AuthEventAction } from '../constants/auth-events.constants';
import { AuthAuditService } from './auth-audit.service';
import {
  AUTH_EVENT_ACTIONS,
  AUTH_EVENT_STATUS,
} from '../constants/auth-events.constants';
import { OTP_PURPOSE } from '../domain/constants/otp-purpose.constants';
import { AuthRequestContext } from '../domain/types/auth-context.type';
import {
  Auth2FAChallenge,
  AuthResponse,
} from '../domain/contracts/auth.contract';
import { randomBytes } from 'crypto';
import { executeFinalizeLogin } from '../application/use-cases/finalize-login.use-case';
import { executePasswordLogin } from '../application/use-cases/password-login.use-case';
import { executeVerify2FALogin } from '../application/use-cases/verify-2fa-login.use-case';
import { executeVerifyOtp } from '../application/use-cases/verify-otp.use-case';
import { executePhoneOtpLogin } from '../application/use-cases/phone-otp-login.use-case';
import { executeResendOtp } from '../application/use-cases/resend-otp.use-case';
import { MailService } from '../../../core/mail/mail.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
    private readonly twoFactorService: TwoFactorService,
    private readonly lockoutService: LockoutService,
    private readonly authAuditService: AuthAuditService,
    private readonly mailService: MailService,
  ) {}

  private buildUsername(email: string, preferred?: string): string {
    if (preferred) return preferred;

    const localPart = email.split('@')[0] || 'user';
    const sanitizedLocalPart = localPart
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_+|_+$/g, '');

    const fallbackBase =
      sanitizedLocalPart.length >= 3 ? sanitizedLocalPart : 'user';
    const suffix = randomBytes(3).toString('hex');
    const maxBaseLength = 20 - suffix.length - 1;
    const trimmedBase = fallbackBase.slice(0, Math.max(3, maxBaseLength));

    return `${trimmedBase}_${suffix}`;
  }

  async register(data: RegisterDto) {
    if (await AuthUtils.isPasswordPwned(data.password)) {
      throw new BadRequestException(AUTH_MESSAGES.PASSWORD_PWNED_ERROR);
    }

    const username = this.buildUsername(data.email, data.username);
    const passwordHash = await AuthUtils.hashPassword(data.password);
    const { user, status } = await this.usersService.createUser(
      {
        ...data,
        username,
      },
      passwordHash,
    );

    if (status === CreateUserStatus.EXISTS_VERIFIED) {
      // Anti-enumeration: same response time & message as new registration
      await AuthUtils.applyTimingDelay();
      return { message: AUTH_MESSAGES.REGISTER_SUCCESS };
    }

    if (
      (status === CreateUserStatus.CREATED ||
        status === CreateUserStatus.EXISTS_UNVERIFIED) &&
      user.email
    ) {
      try {
        await this.otpService.generateAndSendOtp(user.email);
      } catch (error) {
        if (status === CreateUserStatus.EXISTS_UNVERIFIED) {
          this.logger.log(`Skip OTP for existing unverified: ${user.email}`);
        } else throw error;
      }
    }

    return { message: AUTH_MESSAGES.REGISTER_SUCCESS };
  }

  async verifyOtp(data: VerifyOtpPayload): Promise<AuthResponse> {
    return executeVerifyOtp(
      {
        otpService: this.otpService,
        usersService: this.usersService,
        finalizeLogin: (args) =>
          this.finalizeLogin(
            args.user,
            args.context,
            args.action,
            args.message,
            args.isNewUser,
          ),
      },
      data,
    );
  }

  async sendPhoneOtp(data: SendPhoneOtpDto) {
    return this.otpService.generateAndSendOtp(
      data.phoneNumber,
      OTP_PURPOSE.PHONE_LOGIN,
    );
  }

  async loginWithPhoneOtp(data: VerifyPhoneOtpDto): Promise<AuthResponse> {
    return executePhoneOtpLogin(
      {
        otpService: this.otpService,
        usersService: this.usersService,
        finalizeLogin: (args) =>
          this.finalizeLogin(
            args.user,
            args.context,
            args.action,
            args.message,
            args.isNewUser,
          ),
      },
      data,
    );
  }

  async login(data: LoginPayload): Promise<AuthResponse | Auth2FAChallenge> {
    return executePasswordLogin(
      {
        usersService: this.usersService,
        lockoutService: this.lockoutService,
        prisma: this.prisma,
        tokenService: this.tokenService,
        authAuditService: this.authAuditService,
        finalizeLogin: (args) =>
          this.finalizeLogin(
            args.user,
            args.context,
            args.action,
            args.message,
            args.isNewUser,
          ),
      },
      data,
    );
  }

  async verify2FALogin(
    tempToken: string,
    code: string,
    context: AuthRequestContext,
  ): Promise<AuthResponse> {
    return executeVerify2FALogin(
      {
        tokenService: this.tokenService,
        twoFactorService: this.twoFactorService,
        usersService: this.usersService,
        finalizeLogin: (args) =>
          this.finalizeLogin(
            args.user,
            args.context,
            args.action,
            args.message,
            args.isNewUser,
          ),
      },
      tempToken,
      code,
      context,
    );
  }

  private async finalizeLogin(
    user: Partial<User> & { id: string },
    ctx: AuthRequestContext,
    action: AuthEventAction,
    message: string,
    isNewUser = false,
  ): Promise<AuthResponse> {
    return executeFinalizeLogin(
      {
        tokenService: this.tokenService,
        authAuditService: this.authAuditService,
        mailService: this.mailService,
      },
      {
        user,
        context: ctx,
        action,
        message,
        isNewUser,
      },
    );
  }

  async resendOtp(identifier: string) {
    return executeResendOtp(
      {
        usersService: this.usersService,
        otpService: this.otpService,
      },
      identifier,
    );
  }

  async requestChangeEmail(userId: string, newEmail: string) {
    const normalizedEmail = AuthUtils.normalizeIdentifier(newEmail);
    if (await this.prisma.user.findFirst({ where: { email: normalizedEmail } }))
      throw new ConflictException('Email already in use');

    await this.otpService.generateAndSendOtp(
      normalizedEmail,
      OTP_PURPOSE.CHANGE_EMAIL,
    );
    return { message: AUTH_MESSAGES.CHANGE_EMAIL_OTP_SENT };
  }

  async verifyChangeEmail(userId: string, email: string, otp: string) {
    const normalizedEmail = AuthUtils.normalizeIdentifier(email);
    await this.otpService.verifyOtp(
      normalizedEmail,
      otp,
      OTP_PURPOSE.CHANGE_EMAIL,
    );

    try {
      await this.prisma.user.update({
        where: { id: userId },
        data: { email: normalizedEmail },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException(
          'Email này đã được sử dụng bởi tài khoản khác.',
        );
      }
      throw error;
    }

    void this.authAuditService
      .log({
        userId,
        action: AUTH_EVENT_ACTIONS.EMAIL_CHANGED,
        status: AUTH_EVENT_STATUS.SUCCESS,
      })
      .catch(() => {});

    return { message: AUTH_MESSAGES.CHANGE_EMAIL_SUCCESS };
  }

  async requestChangePhone(userId: string, newPhone: string) {
    if (await this.prisma.user.findFirst({ where: { phone: newPhone } }))
      throw new ConflictException('Phone already in use');

    await this.otpService.generateAndSendOtp(
      newPhone,
      OTP_PURPOSE.CHANGE_PHONE,
    );
    return { message: AUTH_MESSAGES.CHANGE_PHONE_OTP_SENT };
  }

  async verifyChangePhone(userId: string, phone: string, otp: string) {
    await this.otpService.verifyOtp(phone, otp, OTP_PURPOSE.CHANGE_PHONE);

    try {
      await this.prisma.user.update({
        where: { id: userId },
        data: { phone },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException(
          'Số điện thoại này đã được sử dụng bởi tài khoản khác.',
        );
      }
      throw error;
    }

    void this.authAuditService
      .log({
        userId,
        action: AUTH_EVENT_ACTIONS.PHONE_CHANGED,
        status: AUTH_EVENT_STATUS.SUCCESS,
      })
      .catch(() => {});

    return { message: AUTH_MESSAGES.CHANGE_PHONE_SUCCESS };
  }

  async refreshTokens(
    refreshToken: string,
    ipAddress?: string,
    deviceInfo?: string,
  ) {
    return this.tokenService.refreshTokens(refreshToken, ipAddress, deviceInfo);
  }
  async getSessions(userId: string) {
    return this.tokenService.getSessions(userId);
  }
  async revokeSession(userId: string, sId: string) {
    return this.tokenService.revokeSession(userId, sId);
  }
  async revokeAllSessions(userId: string) {
    return this.tokenService.revokeAllSessions(userId);
  }
}

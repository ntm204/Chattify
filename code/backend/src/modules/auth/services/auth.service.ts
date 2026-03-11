import {
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { UsersService } from '../../users/users.service';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';
import { TokenService } from './token.service';
import { OtpService } from './otp.service';
import { TwoFactorService } from './two-factor.service';
import { LockoutService } from './lockout.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import * as bcrypt from 'bcrypt';

/**
 * Core Authentication Service
 * Handles user registration, login, email verification, and 2FA authentication.
 * Delegates specialized tasks to PasswordService and LockoutService.
 */
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
  ) {}

  async register(data: RegisterDto) {
    const passwordHash = await bcrypt.hash(
      data.password,
      AUTH_CONSTANTS.SALT_ROUNDS,
    );

    const user = await this.usersService.createUser(data, passwordHash);
    await this.otpService.generateAndSendOtp(user.email);

    return {
      message:
        'Đăng ký thành công! Vui lòng kiểm tra Email để nhận mã OTP 6 số.',
    };
  }

  async verifyEmailOtp(data: VerifyOtpDto) {
    await this.otpService.verifyOtp(data.email, data.otp);

    // Ensure user exists before updating
    const existingUser = await this.usersService.findByEmail(data.email);
    if (!existingUser) {
      throw new BadRequestException('Tài khoản không tồn tại hoặc đã bị xoá.');
    }

    // Mark email as verified via UsersService
    const user = await this.usersService.markEmailVerified(data.email);

    // Create authenticated session
    const session = await this.tokenService.createSessionForUser(
      user.id,
      data.ipAddress,
      data.deviceInfo,
    );
    await this.prisma.authLog.create({
      data: {
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        status: 'SUCCESS',
        ipAddress: data.ipAddress,
        deviceInfo: data.deviceInfo,
      },
    });

    // Return tokens including sessionId
    return this.tokenService.generateTokens(
      user,
      session.id,
      session.refreshToken,
    );
  }

  async login(data: LoginDto) {
    await this.lockoutService.checkIpLockout(data.ipAddress);
    await this.lockoutService.checkAccountLockout(data.email);

    const user = await this.usersService.findByEmailWithPassword(data.email);

    const dummyHash =
      '$2b$10$DUMMYHASHDUMMYHASHDUMMYHASHDUMMYHASHDUMMYHASHDUMMYHA';
    const validHash = user?.passwordHash ? user.passwordHash : dummyHash;

    // Constant-time comparison to prevent timing attacks
    const isPasswordValid = await bcrypt.compare(data.password, validHash);

    if (!user || !isPasswordValid) {
      const { shouldWarn } = await this.lockoutService.incrementLoginAttempts(
        data.email,
        data.ipAddress,
      );

      await this.prisma.authLog.create({
        data: {
          userId: user?.id || null,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          failureReason: 'Invalid credentials',
          ipAddress: data.ipAddress,
          deviceInfo: data.deviceInfo,
        },
      });

      if (shouldWarn) {
        throw new UnauthorizedException(
          'Email hoặc mật khẩu không chính xác. Cảnh báo: Bạn sắp bị khóa tài khoản tạm thời nếu tiếp tục nhập sai!',
        );
      }

      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác');
    }

    // Reset login attempts upon successful authentication
    await this.lockoutService.resetLoginAttempts(data.email);

    if (!user.isVerified) {
      throw new UnauthorizedException({
        message: 'Vui lòng xác thực Email trước khi đăng nhập!',
        action: 'VERIFY_EMAIL_REQUIRED',
        email: data.email,
      });
    }

    // Check 2FA requirement
    const twoFactor = await this.prisma.twoFactorAuth.findUnique({
      where: { userId: user.id },
    });
    if (twoFactor?.isEnabled) {
      const tempToken = this.tokenService.generateTemp2FAToken(user.id);
      return {
        requires2FA: true,
        message: 'Vui lòng nhập mã Google Authenticator',
        tempToken,
      };
    }

    const session = await this.tokenService.createSessionForUser(
      user.id,
      data.ipAddress,
      data.deviceInfo,
    );

    await this.prisma.authLog.create({
      data: {
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        status: 'SUCCESS',
        ipAddress: data.ipAddress,
        deviceInfo: data.deviceInfo,
      },
    });

    return this.tokenService.generateTokens(
      user,
      session.id,
      session.refreshToken,
    );
  }

  async verify2FALogin(
    tempToken: string,
    code: string,
    context: { ipAddress?: string; deviceInfo?: string },
  ) {
    const userId = this.tokenService.verifyTemp2FAToken(tempToken);
    if (!userId) {
      throw new UnauthorizedException(
        'Phiên đăng nhập thời gian thực (2FA) không hợp lệ hoặc đã hết hạn.',
      );
    }

    const isValid = await this.twoFactorService.verifyCode(userId, code);
    if (!isValid) {
      throw new UnauthorizedException(
        'Chưa kích hoạt 2FA hoặc người dùng không có 2FA.',
      );
    }

    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('Người dùng không tồn tại');
    }

    const session = await this.tokenService.createSessionForUser(
      userId,
      context.ipAddress,
      context.deviceInfo,
    );

    await this.prisma.authLog.create({
      data: {
        userId,
        action: 'LOGIN_SUCCESS_2FA',
        status: 'SUCCESS',
        ipAddress: context.ipAddress,
        deviceInfo: context.deviceInfo,
      },
    });

    return this.tokenService.generateTokens(
      user,
      session.id,
      session.refreshToken,
    );
  }

  async resendOtp(email: string) {
    if (!email) throw new BadRequestException('Vui lòng cung cấp email');

    const genericResponse = {
      message:
        'Nếu email hợp lệ và chưa xác thực, mã OTP sẽ được gửi đến email của bạn.',
    };

    const user = await this.usersService.findByEmail(email);

    if (!user || user.isVerified) {
      // Delay to mitigate timing attacks
      await new Promise((resolve) =>
        setTimeout(resolve, AUTH_CONSTANTS.TIMING_DELAY_MS),
      );
      return genericResponse;
    }

    await this.otpService.generateAndSendOtp(email);
    return genericResponse;
  }

  async refreshTokens(refreshToken: string) {
    return this.tokenService.refreshTokens(refreshToken);
  }

  async getSessions(userId: string) {
    return this.tokenService.getSessions(userId);
  }

  async revokeSession(userId: string, sessionId: string) {
    return this.tokenService.revokeSession(userId, sessionId);
  }
}

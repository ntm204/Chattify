import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { UsersService } from '../../users/users.service';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { TokenService } from './token.service';
import { OtpService } from './otp.service';
import { TwoFactorService } from './two-factor.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
    private readonly twoFactorService: TwoFactorService,
  ) {}

  async register(data: RegisterDto) {
    // 1. Mã hóa mật khẩu (Bcrypt)
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(data.password, saltRounds);

    // 2. Tạo User trong database (Mặc định isVerified = false)
    const user = await this.usersService.createUser(data, passwordHash);

    // 3. Sinh và gửi mã OTP
    await this.otpService.generateAndSendOtp(user.email);

    // 4. Trả về thông báo yêu cầu xác nhận
    return {
      message:
        'Đăng ký thành công! Vui lòng kiểm tra Email để nhận mã OTP 6 số.',
      userId: user.id,
    };
  }

  async verifyEmailOtp(data: VerifyOtpDto) {
    // 1. Kiểm tra OTP
    await this.otpService.verifyOtp(data.email, data.otp);

    // 2. Xác nhận User
    const user = await this.prisma.user.update({
      where: { email: data.email },
      data: { isVerified: true },
    });

    // 3. FIX LỖ HỔNG ZOMBIE TOKEN: Sinh Session chuẩn chỉnh cho người dùng vừa verify thành công
    const session = await this.tokenService.createSessionForUser(
      user.id,
      data.ipAddress,
      data.deviceInfo,
    );

    // Ghi Log thành công (khi đã đăng ký & verify xong cũng tương đương Login)
    await this.prisma.authLog.create({
      data: {
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        status: 'SUCCESS',
        ipAddress: data.ipAddress,
        deviceInfo: data.deviceInfo,
      },
    });

    // 4. Trả về Token với sessionId đàng hoàng
    return this.tokenService.generateTokens(
      user,
      session.id,
      session.refreshToken,
    );
  }

  async login(data: LoginDto) {
    // 1. Tìm user bằng email
    const user = await this.usersService.findByEmail(data.email);

    const dummyHash =
      '$2b$10$DUMMYHASHDUMMYHASHDUMMYHASHDUMMYHASHDUMMYHASHDUMMYHA';
    const validHash = user?.passwordHash ? user.passwordHash : dummyHash;

    // Luôn luôn chạy hàm Compare để cân bằng thời gian Request (Bảo mật Timing Attack 100%)
    const isPasswordValid = await bcrypt.compare(data.password, validHash);

    if (!user || !isPasswordValid) {
      await this.prisma.authLog.create({
        data: {
          userId: user?.id || null, // Vẫn log null nếu user không tồn tại để giám sát IP
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          failureReason: 'Invalid credentials', // Chống User Enumeration
          ipAddress: data.ipAddress,
          deviceInfo: data.deviceInfo,
        },
      });
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác');
    }

    // BẢO MẬT: Phải kiểm tra isVerified SAU KHI xác thực mật khẩu.
    // Nếu kiểm tra trước, hacker có thể nhập bừa mật khẩu và dò xem email nào chưa verify (Lộ lọt thông tin)
    if (!user.isVerified) {
      throw new UnauthorizedException(
        'Vui lòng xác thực Email trước khi đăng nhập!',
      );
    }

    // 3. ĐĂNG NHẬP THÀNH CÔNG -> Kiểm tra 2FA
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

    // Nếu User không dùng 2FA -> Tiếp tục quy trình bình thường
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

    // 4. Trả về thông tin User (Token được gán ở Controller bằng Cookie nên Payload trả về k cần access_token nữa, hoặc trả về để Controller tự gọi)
    // Lưu ý: Controller của chúng ta đang cần result.access_token nên ta vẫn trả về đầy đủ
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

    // Cấp Session ngay sau khi qua ải 2FA
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

    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('Tài khoản không tồn tại!');
    }
    if (user.isVerified) {
      throw new BadRequestException(
        'Tài khoản này đã được xác thực, vui lòng đăng nhập!',
      );
    }

    return this.otpService.generateAndSendOtp(email);
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

  async forgotPassword(data: ForgotPasswordDto) {
    const user = await this.usersService.findByEmail(data.email);

    if (!user) {
      // BẢO MẬT: Cân bằng thời gian chờ (Timing Attack delay) bằng với thời gian gửi email thật SMTP (trung bình ~600ms)
      // Ngăn chặn Hacker gửi list 10k email để xem API nào phản hồi 2ms (Không tồn tại) hay 600ms (Có tồn tại)
      await new Promise((resolve) => setTimeout(resolve, 600));
      return {
        message: 'Nếu email hợp lệ, hệ thống sẽ gửi mã OTP đến cho bạn.',
      };
    }

    await this.otpService.generateAndSendOtp(user.email, 'PASSWORD_RESET');
    return { message: 'Nếu email hợp lệ, hệ thống sẽ gửi mã OTP đến cho bạn.' };
  }

  async resetPassword(data: ResetPasswordDto) {
    // Kiểm tra OTP loại PASSWORD_RESET
    await this.otpService.verifyOtp(data.email, data.otp, 'PASSWORD_RESET');

    // Băm mật khẩu mới
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(data.newPassword, saltRounds);

    // Lưu vào DB
    const user = await this.prisma.user.update({
      where: { email: data.email },
      data: { passwordHash },
    });

    // Ghi Log Audit
    await this.prisma.authLog.create({
      data: {
        userId: user.id,
        action: 'PASSWORD_CHANGE',
        status: 'SUCCESS',
      },
    });

    // BẢO MẬT: Xoá lịch sử cookie của mọi thiết bị trên DB và cả Redis
    await this.tokenService.revokeAllSessions(user.id);

    return {
      message:
        'Đổi mật khẩu thành công! Vui lòng sử dụng mật khẩu mới để đăng nhập.',
    };
  }

  async changePassword(userId: string, data: ChangePasswordDto) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('Người dùng không tồn tại');

    const isMatch = await bcrypt.compare(data.oldPassword, user.passwordHash);
    if (!isMatch) {
      throw new BadRequestException('Mật khẩu cũ không chính xác');
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(data.newPassword, saltRounds);

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    await this.prisma.authLog.create({
      data: {
        userId,
        action: 'PASSWORD_CHANGE',
        status: 'SUCCESS',
      },
    });

    await this.tokenService.revokeAllSessions(userId);

    return {
      message: 'Đã thay đổi mật khẩu thành công. Vui lòng đăng nhập lại!',
    };
  }
}

import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Delete,
  Param,
  Req,
  Res,
  Ip,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Throttle } from '@nestjs/throttler';
import * as express from 'express';
import { AuthService } from '../services/auth.service';
import { PasswordService } from '../services/password.service';
import { TwoFactorService } from '../services/two-factor.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';
import { ResendOtpDto } from '../dto/resend-otp.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { Verify2FADto } from '../dto/verify-2fa.dto';
import { Toggle2FACodeDto } from '../dto/toggle-2fa-code.dto';
import { SendPhoneOtpDto, VerifyPhoneOtpDto } from '../dto/phone-auth.dto';
import {
  RequestChangeEmailDto,
  VerifyChangeEmailDto,
  RequestChangePhoneDto,
  VerifyChangePhoneDto,
} from '../../users/dto/change-identifier.dto';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { AuthenticatedRequest } from '../../../common/interfaces/authenticated-request.interface';
import { AuthRequestContext } from '../domain/types/auth-context.type';
import { AuthAuditService } from '../services/auth-audit.service';
import {
  AUTH_EVENT_ACTIONS,
  AUTH_EVENT_STATUS,
} from '../constants/auth-events.constants';

@Controller('auth')
export class AuthController {
  private readonly cookieOptions: express.CookieOptions;

  constructor(
    private readonly authService: AuthService,
    private readonly passwordService: PasswordService,
    private readonly twoFactorService: TwoFactorService,
    private readonly configService: ConfigService,
    private readonly authAuditService: AuthAuditService,
  ) {
    this.cookieOptions = {
      httpOnly: true,
      secure: this.configService.get<string>('NODE_ENV') !== 'development',
      sameSite: 'lax',
      path: '/',
    };
  }

  private setCookies(res: express.Response, at: string, rt: string) {
    res.cookie('access_token', at, {
      ...this.cookieOptions,
      maxAge: AUTH_CONSTANTS.COOKIE_ACCESS_TOKEN_MAX_AGE,
    });
    res.cookie('refresh_token', rt, {
      ...this.cookieOptions,
      path: '/api/v1/auth',
      sameSite: 'strict', // Stricter for refresh token
      maxAge: AUTH_CONSTANTS.COOKIE_REFRESH_TOKEN_MAX_AGE,
    });
  }

  private clearAuthCookies(res: express.Response) {
    res.clearCookie('access_token', this.cookieOptions);
    res.clearCookie('refresh_token', {
      ...this.cookieOptions,
      path: '/api/v1/auth',
      sameSite: 'strict',
    });
  }

  private extractRequestContext(
    ipAddress: string,
    req: express.Request,
  ): AuthRequestContext {
    return {
      ipAddress,
      deviceInfo: (req.headers['user-agent'] as string) || 'Unknown',
    };
  }

  private getAuthenticatedUser(req: express.Request) {
    return (req as AuthenticatedRequest).user;
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('resend-otp')
  resendOtp(@Body() { identifier }: ResendOtpDto) {
    return this.authService.resendOtp(identifier);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('verify-otp')
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const result = await this.authService.verifyOtp({
      ...dto,
      ...this.extractRequestContext(ipAddress, req),
    });
    this.setCookies(res, result.access_token, result.refresh_token);
    return { message: AUTH_MESSAGES.VERIFY_EMAIL_SUCCESS, user: result.user };
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('verify-email')
  async verifyEmail(
    @Body() dto: VerifyOtpDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    return this.verifyOtp(dto, ipAddress, req, res);
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const context = this.extractRequestContext(ipAddress, req);
    const result = await this.authService.login({
      ...dto,
      ...context,
    });
    if ('requires2FA' in result) return result;
    this.setCookies(res, result.access_token, result.refresh_token);
    return { message: AUTH_MESSAGES.LOGIN_SUCCESS, user: result.user };
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('phone/send-otp')
  sendPhoneOtp(@Body() dto: SendPhoneOtpDto) {
    return this.authService.sendPhoneOtp(dto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('phone/login')
  async loginPhone(
    @Body() dto: VerifyPhoneOtpDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const result = await this.authService.loginWithPhoneOtp({
      ...dto,
      ...this.extractRequestContext(ipAddress, req),
    });
    this.setCookies(res, result.access_token, result.refresh_token);
    return result;
  }

  @Throttle({ default: { limit: 20, ttl: 60000 } })
  @Post('refresh')
  async refresh(
    @Req() req: express.Request,
    @Ip() ipAddress: string,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const rt = req.cookies['refresh_token'] as string;
    if (!rt)
      throw new UnauthorizedException(AUTH_MESSAGES.REFRESH_TOKEN_NOT_FOUND);

    const { deviceInfo } = this.extractRequestContext(ipAddress, req);
    const result = await this.authService.refreshTokens(
      rt,
      ipAddress,
      deviceInfo,
    );
    this.setCookies(res, result.access_token, result.refresh_token);
    return { message: AUTH_MESSAGES.REFRESH_TOKEN_SUCCESS };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @Req() req: express.Request,
    @Ip() ipAddress: string,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const user = this.getAuthenticatedUser(req);
    if (user.currentSessionId)
      await this.authService.revokeSession(user.id, user.currentSessionId);
    this.clearAuthCookies(res);

    void this.authAuditService
      .log({
        userId: user.id,
        action: AUTH_EVENT_ACTIONS.LOGOUT,
        status: AUTH_EVENT_STATUS.SUCCESS,
        ipAddress,
        deviceInfo: (req.headers['user-agent'] as string) || 'Unknown',
      })
      .catch(() => {});

    return { message: AUTH_MESSAGES.LOGOUT_SUCCESS };
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  getSessions(@Req() req: express.Request) {
    const user = this.getAuthenticatedUser(req);
    return this.authService.getSessions(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Delete('sessions/:id')
  async revokeSession(@Req() req: express.Request, @Param('id') sId: string) {
    const user = this.getAuthenticatedUser(req);
    const result = await this.authService.revokeSession(user.id, sId);

    void this.authAuditService
      .log({
        userId: user.id,
        action: AUTH_EVENT_ACTIONS.SESSION_REVOKED,
        status: AUTH_EVENT_STATUS.SUCCESS,
      })
      .catch(() => {});

    return result;
  }

  @UseGuards(JwtAuthGuard)
  @Post('sessions/revoke-all')
  async revokeAll(
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const user = this.getAuthenticatedUser(req);
    await this.authService.revokeAllSessions(user.id);
    this.clearAuthCookies(res);
    return { message: 'Logged out from all devices' };
  }

  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('2fa/generate')
  gen2FA(@Req() req: express.Request) {
    const user = this.getAuthenticatedUser(req);
    return this.twoFactorService.generateTwoFactorAuthSecret(
      user.id,
      user.email || '',
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/turn-on')
  async turnOn2FA(@Req() req: express.Request, @Body() { code }: Toggle2FACodeDto) {
    const user = this.getAuthenticatedUser(req);
    const result = await this.twoFactorService.turnOnTwoFactorAuth(user.id, code);

    void this.authAuditService
      .log({
        userId: user.id,
        action: AUTH_EVENT_ACTIONS.TWO_FA_ENABLED,
        status: AUTH_EVENT_STATUS.SUCCESS,
      })
      .catch(() => {});

    return result;
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/turn-off')
  async turnOff2FA(@Req() req: express.Request, @Body() { code }: Toggle2FACodeDto) {
    const user = this.getAuthenticatedUser(req);
    const result = await this.twoFactorService.turnOffTwoFactorAuth(user.id, code);

    void this.authAuditService
      .log({
        userId: user.id,
        action: AUTH_EVENT_ACTIONS.TWO_FA_DISABLED,
        status: AUTH_EVENT_STATUS.SUCCESS,
      })
      .catch(() => {});

    return result;
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('2fa/verify')
  async verify2FA(
    @Body() dto: Verify2FADto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const result = await this.authService.verify2FALogin(
      dto.tempToken,
      dto.code,
      this.extractRequestContext(ipAddress, req),
    );
    this.setCookies(res, result.access_token, result.refresh_token);
    return { message: AUTH_MESSAGES.LOGIN_SUCCESS, user: result.user };
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('forgot-password')
  forgotPw(@Body() dto: ForgotPasswordDto) {
    return this.passwordService.forgotPassword(dto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('reset-password')
  resetPw(
    @Body() dto: ResetPasswordDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
  ) {
    return this.passwordService.resetPassword(dto, {
      ...this.extractRequestContext(ipAddress, req),
    });
  }

  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('change-password')
  async changePw(
    @Req() req: express.Request,
    @Body() dto: ChangePasswordDto,
    @Ip() ipAddress: string,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const user = this.getAuthenticatedUser(req);
    const result = await this.passwordService.changePassword(user.id, dto, {
      ...this.extractRequestContext(ipAddress, req),
    });
    this.clearAuthCookies(res);
    return result;
  }

  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('change-email/request')
  reqEmail(
    @Req() req: express.Request,
    @Body() { newEmail }: RequestChangeEmailDto,
  ) {
    const user = this.getAuthenticatedUser(req);
    return this.authService.requestChangeEmail(user.id, newEmail);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-email/verify')
  verEmail(
    @Req() req: express.Request,
    @Body() { email, otp }: VerifyChangeEmailDto,
  ) {
    const user = this.getAuthenticatedUser(req);
    return this.authService.verifyChangeEmail(user.id, email, otp);
  }

  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('change-phone/request')
  reqPhone(
    @Req() req: express.Request,
    @Body() { newPhone }: RequestChangePhoneDto,
  ) {
    const user = this.getAuthenticatedUser(req);
    return this.authService.requestChangePhone(user.id, newPhone);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-phone/verify')
  verPhone(
    @Req() req: express.Request,
    @Body() { phone, otp }: VerifyChangePhoneDto,
  ) {
    const user = this.getAuthenticatedUser(req);
    return this.authService.verifyChangePhone(user.id, phone, otp);
  }
}

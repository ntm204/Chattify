import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Get,
  Delete,
  Param,
  Req,
  Res,
  Ip,
  UnauthorizedException,
} from '@nestjs/common';
import * as express from 'express';
import type { AuthenticatedRequest } from '../../../common/interfaces/authenticated-request.interface';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { AuthService } from '../services/auth.service';
import { PasswordService } from '../services/password.service';
import { TwoFactorService } from '../services/two-factor.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';
import { ResendOtpDto } from '../dto/resend-otp.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { Verify2FADto } from '../dto/verify-2fa.dto';
import { Toggle2FACodeDto } from '../dto/toggle-2fa-code.dto';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';

@Controller('api/v1/auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly passwordService: PasswordService,
    private readonly twoFactorService: TwoFactorService,
  ) {}

  private readonly cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    sameSite: 'strict' as const,
    path: '/',
  };

  private setAuthCookies(
    res: express.Response,
    access_token: string,
    refresh_token: string,
  ) {
    res.cookie('access_token', access_token, {
      ...this.cookieOptions,
      maxAge: AUTH_CONSTANTS.COOKIE_ACCESS_TOKEN_MAX_AGE,
    });

    // Restrict Refresh Token to auth path
    res.cookie('refresh_token', refresh_token, {
      ...this.cookieOptions,
      path: '/api/v1/auth',
      maxAge: AUTH_CONSTANTS.COOKIE_REFRESH_TOKEN_MAX_AGE,
    });
  }

  private clearAuthCookies(res: express.Response) {
    res.clearCookie('access_token', this.cookieOptions);
    res.clearCookie('refresh_token', {
      ...this.cookieOptions,
      path: '/api/v1/auth',
    });
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } }) // Rate limit: 3 requests / minute
  @HttpCode(HttpStatus.OK)
  @Post('resend-otp')
  async resendOtp(@Body() dto: ResendOtpDto) {
    return this.authService.resendOtp(dto.email);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('verify-email')
  async verifyEmail(
    @Body() verifyOtpDto: VerifyOtpDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    const result = await this.authService.verifyEmailOtp({
      ...verifyOtpDto,
      ipAddress,
      deviceInfo,
    });
    this.setAuthCookies(
      res,
      result.access_token as string,
      result.refresh_token as string,
    );
    return { message: AUTH_MESSAGES.VERIFY_EMAIL_SUCCESS, user: result.user };
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    const result = await this.authService.login({
      ...loginDto,
      ipAddress,
      deviceInfo,
    });

    // Return tempToken if 2FA is required, do not set cookies yet
    if (result.requires2FA) {
      return {
        requires2FA: true,
        message: result.message,
        tempToken: result.tempToken,
      };
    }

    this.setAuthCookies(
      res,
      result.access_token as string,
      result.refresh_token as string,
    );
    return { message: AUTH_MESSAGES.LOGIN_SUCCESS, user: result.user };
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refreshTokens(
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const refreshToken = req.cookies['refresh_token'] as string | undefined;
    if (!refreshToken) {
      throw new UnauthorizedException(AUTH_MESSAGES.REFRESH_TOKEN_NOT_FOUND);
    }
    const result = await this.authService.refreshTokens(refreshToken);
    this.setAuthCookies(
      res,
      result.access_token as string,
      result.refresh_token as string,
    );
    return { message: AUTH_MESSAGES.REFRESH_TOKEN_SUCCESS };
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    if (req.user.currentSessionId) {
      await this.authService.revokeSession(
        req.user.id,
        req.user.currentSessionId,
      );
    }
    this.clearAuthCookies(res);
    return { message: AUTH_MESSAGES.LOGOUT_SUCCESS };
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  async getSessions(@Req() req: AuthenticatedRequest) {
    return this.authService.getSessions(req.user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('sessions/:id')
  async revokeSession(
    @Req() req: AuthenticatedRequest,
    @Param('id') sessionId: string,
  ) {
    return this.authService.revokeSession(req.user.id, sessionId);
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('2fa/generate')
  @UseGuards(JwtAuthGuard)
  async generate2FA(@Req() req: AuthenticatedRequest) {
    return this.twoFactorService.generateTwoFactorAuthSecret(
      req.user.id,
      req.user.email,
    );
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('2fa/turn-on')
  @UseGuards(JwtAuthGuard)
  async turnOn2FA(
    @Req() req: AuthenticatedRequest,
    @Body() dto: Toggle2FACodeDto,
  ) {
    return this.twoFactorService.turnOnTwoFactorAuth(req.user.id, dto.code);
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post('2fa/turn-off')
  @UseGuards(JwtAuthGuard)
  async turnOff2FA(
    @Req() req: AuthenticatedRequest,
    @Body() dto: Toggle2FACodeDto,
  ) {
    return this.twoFactorService.turnOffTwoFactorAuth(req.user.id, dto.code);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('2fa/verify')
  async verify2FALogin(
    @Body() body: Verify2FADto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    const result = await this.authService.verify2FALogin(
      body.tempToken,
      body.code,
      { ipAddress, deviceInfo },
    );
    this.setAuthCookies(
      res,
      result.access_token as string,
      result.refresh_token as string,
    );
    return { message: AUTH_MESSAGES.LOGIN_SUCCESS, user: result.user };
  }

  // ==========================================
  // Password Management
  // ==========================================

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  async forgotPassword(@Body() forgotPwDto: ForgotPasswordDto) {
    return this.passwordService.forgotPassword(forgotPwDto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('reset-password')
  async resetPassword(
    @Body() resetPwDto: ResetPasswordDto,
    @Ip() ipAddress: string,
    @Req() req: express.Request,
  ) {
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    return this.passwordService.resetPassword(resetPwDto, {
      ipAddress,
      deviceInfo,
    });
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('change-password')
  async changePassword(
    @Req() req: AuthenticatedRequest,
    @Body() changePasswordDto: ChangePasswordDto,
    @Ip() ipAddress: string,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    const result = await this.passwordService.changePassword(
      req.user.id,
      changePasswordDto,
      { ipAddress, deviceInfo },
    );
    this.clearAuthCookies(res);
    return result;
  }
}

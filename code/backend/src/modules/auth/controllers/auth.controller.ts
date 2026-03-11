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
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { TwoFactorService } from '../services/two-factor.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { Verify2FADto } from '../dto/verify-2fa.dto';

@Controller('api/v1/auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly twoFactorService: TwoFactorService,
  ) {}

  private readonly cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' as const,
  };

  private setAuthCookies(
    res: express.Response,
    access_token: string,
    refresh_token: string,
  ) {
    res.cookie('access_token', access_token, {
      ...this.cookieOptions,
      maxAge: 15 * 60 * 1000, // 15 phút
    });

    res.cookie('refresh_token', refresh_token, {
      ...this.cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
    });
  }

  private clearAuthCookies(res: express.Response) {
    res.clearCookie('access_token', this.cookieOptions);
    res.clearCookie('refresh_token', this.cookieOptions);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } }) // Rate limit: 3 requests / minute
  @HttpCode(HttpStatus.OK)
  @Post('resend-otp')
  async resendOtp(@Body('email') email: string) {
    return this.authService.resendOtp(email);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Anti-Brute Force OTP
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
    return { message: 'Xác thực thành công', user: result.user };
  }

  @UseGuards(ThrottlerGuard)
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

    // Nếu user bật 2FA → trả tempToken, KHÔNG set cookie
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
    return { message: 'Đăng nhập thành công', user: result.user };
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
      throw new UnauthorizedException(
        'Không tìm thấy Refresh Token trong Cookie',
      );
    }
    const result = await this.authService.refreshTokens(refreshToken);
    this.setAuthCookies(
      res,
      result.access_token as string,
      result.refresh_token as string,
    );
    return { message: 'Làm mới Token thành công' };
  }

  @UseGuards(AuthGuard('jwt'))
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
    return { message: 'Đăng xuất thành công' };
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('sessions')
  async getSessions(@Req() req: AuthenticatedRequest) {
    return this.authService.getSessions(req.user.id);
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('sessions/:id')
  async revokeSession(
    @Req() req: AuthenticatedRequest,
    @Param('id') sessionId: string,
  ) {
    return this.authService.revokeSession(req.user.id, sessionId);
  }

  @Post('2fa/generate')
  @UseGuards(AuthGuard('jwt'))
  async generate2FA(@Req() req: AuthenticatedRequest) {
    return this.twoFactorService.generateTwoFactorAuthSecret(
      req.user.id,
      req.user.email,
    );
  }

  @Post('2fa/turn-on')
  @UseGuards(AuthGuard('jwt'))
  async turnOn2FA(
    @Req() req: AuthenticatedRequest,
    @Body('code') code: string,
  ) {
    return this.twoFactorService.turnOnTwoFactorAuth(req.user.id, code);
  }

  @Post('2fa/turn-off')
  @UseGuards(AuthGuard('jwt'))
  async turnOff2FA(
    @Req() req: AuthenticatedRequest,
    @Body('code') code: string,
  ) {
    return this.twoFactorService.turnOffTwoFactorAuth(req.user.id, code);
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
    return { message: 'Đăng nhập thành công', user: result.user };
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  async forgotPassword(@Body() forgotPwDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPwDto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @Post('reset-password')
  async resetPassword(@Body() resetPwDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPwDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @Post('change-password')
  async changePassword(
    @Req() req: AuthenticatedRequest,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(req.user.id, changePasswordDto);
  }
}

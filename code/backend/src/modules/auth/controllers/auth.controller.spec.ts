/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from '../services/auth.service';
import { PasswordService } from '../services/password.service';
import { TwoFactorService } from '../services/two-factor.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { UnauthorizedException } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthenticatedRequest } from '../../../common/interfaces/authenticated-request.interface';

// Mock Services
const mockAuthService = {
  register: jest.fn(),
  resendOtp: jest.fn(),
  verifyEmailOtp: jest.fn(),
  login: jest.fn(),
  refreshTokens: jest.fn(),
  revokeSession: jest.fn(),
  getSessions: jest.fn(),
  verify2FALogin: jest.fn(),
};

const mockPasswordService = {
  forgotPassword: jest.fn(),
  resetPassword: jest.fn(),
  changePassword: jest.fn(),
};

const mockTwoFactorService = {
  generateTwoFactorAuthSecret: jest.fn(),
  turnOnTwoFactorAuth: jest.fn(),
  turnOffTwoFactorAuth: jest.fn(),
};

describe('AuthController', () => {
  let controller: AuthController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: TwoFactorService, useValue: mockTwoFactorService },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AuthController>(AuthController);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('should successfully register a user', async () => {
      const dto = {
        email: 'test@example.com',
        password: 'Password123!',
        username: 'testuser',
        displayName: 'Test',
      };
      mockAuthService.register.mockResolvedValue({ message: 'Success' });
      const result = await controller.register(dto);
      expect(result).toEqual({ message: 'Success' });
      expect(mockAuthService.register).toHaveBeenCalledWith(dto);
    });
  });

  describe('login', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;

    beforeEach(() => {
      mockReq = { headers: { 'user-agent': 'Test Agent' } };
      mockRes = { cookie: jest.fn(), clearCookie: jest.fn() };
    });

    it('should authenticate user and set cookies', async () => {
      const dto = { email: 'test@example.com', password: 'Password123!' };
      const ip = '127.0.0.1';
      const authResult = {
        access_token: 'acc-token',
        refresh_token: 'ref-token',
        user: { id: 'u1' },
      };

      mockAuthService.login.mockResolvedValue(authResult);

      const result = await controller.login(
        dto,
        ip,
        mockReq as Request,
        mockRes as Response,
      );

      expect(mockAuthService.login).toHaveBeenCalledWith({
        ...dto,
        ipAddress: ip,
        deviceInfo: 'Test Agent',
      });
      expect(mockRes.cookie).toHaveBeenCalledTimes(2); // access & refresh tokens
      expect(result).toEqual({
        message: 'Đăng nhập thành công',
        user: { id: 'u1' },
      });
    });

    it('should return requires2FA if 2FA is needed without setting cookies', async () => {
      const dto = { email: 'test@example.com', password: 'Password123!' };
      const ip = '127.0.0.1';
      const authResult = {
        requires2FA: true,
        message: 'Need 2FA',
        tempToken: 'temp-token',
      };

      mockAuthService.login.mockResolvedValue(authResult);

      const result = await controller.login(
        dto,
        ip,
        mockReq as Request,
        mockRes as Response,
      );

      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(result).toEqual(authResult);
    });
  });

  describe('verifyEmail', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;

    beforeEach(() => {
      mockReq = { headers: { 'user-agent': 'Test Agent' } };
      mockRes = { cookie: jest.fn() };
    });

    it('should verify email and return tokens', async () => {
      const dto = { email: 'test@example.com', otp: '123456' };
      const ip = '127.0.0.1';
      const authResult = {
        access_token: 'acc-token',
        refresh_token: 'ref-token',
        user: { id: 'u1' },
      };

      mockAuthService.verifyEmailOtp.mockResolvedValue(authResult);

      const result = await controller.verifyEmail(
        dto,
        ip,
        mockReq as Request,
        mockRes as Response,
      );

      expect(mockAuthService.verifyEmailOtp).toHaveBeenCalledWith({
        ...dto,
        ipAddress: ip,
        deviceInfo: 'Test Agent',
      });
      expect(mockRes.cookie).toHaveBeenCalledTimes(2);
      expect(result).toEqual({
        message: 'Xác thực thành công',
        user: { id: 'u1' },
      });
    });
  });

  describe('refreshTokens', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;

    beforeEach(() => {
      mockRes = { cookie: jest.fn() };
    });

    it('should refresh tokens properly', async () => {
      mockReq = { cookies: { refresh_token: 'old-ref-token' } };
      const authResult = {
        access_token: 'new-acc-token',
        refresh_token: 'new-ref-token',
      };

      mockAuthService.refreshTokens.mockResolvedValue(authResult);

      const result = await controller.refreshTokens(
        mockReq as Request,
        mockRes as Response,
      );

      expect(mockAuthService.refreshTokens).toHaveBeenCalledWith(
        'old-ref-token',
      );
      expect(mockRes.cookie).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ message: 'Làm mới Token thành công' });
    });

    it('should throw UnauthorizedException if no cookie is present', async () => {
      mockReq = { cookies: {} };

      await expect(
        controller.refreshTokens(mockReq as Request, mockRes as Response),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logout', () => {
    let mockReq: Partial<AuthenticatedRequest>;
    let mockRes: Partial<Response>;

    beforeEach(() => {
      mockReq = { user: { id: 'u1', currentSessionId: 's1' } } as any;
      mockRes = { clearCookie: jest.fn() };
    });

    it('should logout and clear cookies', async () => {
      mockAuthService.revokeSession.mockResolvedValue(true);

      const result = await controller.logout(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
      );

      expect(mockAuthService.revokeSession).toHaveBeenCalledWith('u1', 's1');
      expect(mockRes.clearCookie).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ message: 'Đăng xuất thành công' });
    });
  });

  describe('changePassword', () => {
    let mockReq: Partial<AuthenticatedRequest>;
    let mockRes: Partial<Response>;

    beforeEach(() => {
      mockReq = {
        user: { id: 'u1' },
        headers: { 'user-agent': 'Test Agent' },
      } as any;
      mockRes = { clearCookie: jest.fn() };
    });

    it('should change password successfully', async () => {
      const dto = {
        oldPassword: '1',
        newPassword: '2',
        confirmNewPassword: '2',
      };
      mockPasswordService.changePassword.mockResolvedValue({
        message: 'Success',
      });

      const result = await controller.changePassword(
        mockReq as AuthenticatedRequest,
        dto,
        '127.0.0.1',
        mockRes as Response,
      );

      expect(result).toEqual({ message: 'Success' });
      expect(mockRes.clearCookie).toHaveBeenCalledTimes(2);
    });
  });
});

/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument, @typescript-eslint/unbound-method */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from '../services/auth.service';
import { PasswordService } from '../services/password.service';
import { TwoFactorService } from '../services/two-factor.service';
import { ConfigService } from '@nestjs/config';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { AuthAuditService } from '../services/auth-audit.service';
import { Response } from 'express';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;

  const mockResponse = (): Partial<Response> => {
    const res: any = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    res.cookie = jest.fn().mockReturnValue(res);
    res.clearCookie = jest.fn().mockReturnValue(res);
    return res as Response;
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            register: jest.fn(),
            login: jest.fn(),
            verifyOtp: jest.fn(),
            refreshTokens: jest.fn(),
            revokeSession: jest.fn(),
            revokeAllSessions: jest.fn(),
            getSessions: jest.fn(),
            resendOtp: jest.fn(),
            verify2FALogin: jest.fn(),
            requestChangeEmail: jest.fn(),
            verifyChangeEmail: jest.fn(),
            requestChangePhone: jest.fn(),
            verifyChangePhone: jest.fn(),
            loginWithPhoneOtp: jest.fn(),
            sendPhoneOtp: jest.fn(),
          },
        },
        {
          provide: PasswordService,
          useValue: {
            forgotPassword: jest.fn(),
            resetPassword: jest.fn(),
            changePassword: jest.fn(),
          },
        },
        {
          provide: TwoFactorService,
          useValue: {
            generateTwoFactorAuthSecret: jest.fn(),
            turnOnTwoFactorAuth: jest.fn(),
            turnOffTwoFactorAuth: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('development'),
          },
        },
        {
          provide: AuthAuditService,
          useValue: {
            log: jest.fn(),
            isNewDevice: jest.fn().mockResolvedValue(false),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('should call authService.register', async () => {
      const dto = {
        email: 'test@test.com',
        password: 'Password123!',
        username: 'testuser',
        displayName: 'Test User',
      };
      const expectedResult = { message: AUTH_MESSAGES.REGISTER_SUCCESS };
      jest.spyOn(authService, 'register').mockResolvedValue(expectedResult);

      const result = await controller.register(dto);
      expect(result).toBe(expectedResult);
      expect(authService.register).toHaveBeenCalledWith(dto);
    });
  });

  describe('login', () => {
    it('should set cookies on successful login', async () => {
      const dto = { identifier: 'test@test.com', password: 'Password123!' };
      const loginResult = {
        access_token: 'at',
        refresh_token: 'rt',
        user: { id: '1' },
      };
      jest.spyOn(authService, 'login').mockResolvedValue(loginResult as any);

      const res = mockResponse();
      const req: any = { headers: {} };

      const result = await controller.login(
        dto,
        '1.2.3.4',
        req,
        res as Response,
      );

      expect(res.cookie).toHaveBeenCalled();
      expect(result).toEqual({
        message: AUTH_MESSAGES.LOGIN_SUCCESS,
        user: loginResult.user,
      });
    });

    it('should return tempToken if 2FA is required', async () => {
      const dto = { identifier: 'test@test.com', password: 'Password123!' };
      const loginResult = {
        requires2FA: true,
        message: AUTH_MESSAGES.TFA_REQUIRED,
        tempToken: 'temp',
      };
      jest.spyOn(authService, 'login').mockResolvedValue(loginResult as any);

      const res = mockResponse();
      const req: any = { headers: {} };

      const result = await controller.login(
        dto,
        '1.2.3.4',
        req,
        res as Response,
      );

      expect(res.cookie).not.toHaveBeenCalled();
      expect(result).toEqual(loginResult);
    });
  });

  describe('verifyEmail', () => {
    it('should delegate to verifyOtp flow and set cookies', async () => {
      const dto = { identifier: 'test@test.com', otp: '123456' };
      const verifyResult = {
        access_token: 'at',
        refresh_token: 'rt',
        user: { id: '1' },
      };
      jest
        .spyOn(authService, 'verifyOtp')
        .mockResolvedValue(verifyResult as any);

      const res = mockResponse();
      const req: any = { headers: {} };

      const result = await controller.verifyEmail(
        dto as any,
        '1.2.3.4',
        req,
        res as Response,
      );

      expect(authService.verifyOtp).toHaveBeenCalled();
      expect(res.cookie).toHaveBeenCalledTimes(2);
      expect(result).toEqual({
        message: AUTH_MESSAGES.VERIFY_EMAIL_SUCCESS,
        user: verifyResult.user,
      });
    });
  });
});

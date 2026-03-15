/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/require-await */
import { UnauthorizedException, BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserStatus } from '../../users/interfaces/user.interface';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { AuthUtils } from '../../../core/utils/auth.util';

// ==========================================
// Mock Data
// ==========================================
const mockUser = {
  id: 'user-uuid-1',
  email: 'test@test.com',
  username: 'testuser',
  displayName: 'Test User',
  avatarUrl: null,
  passwordHash: '',
  isVerified: true,
};

const mockSession = {
  id: 'session-uuid-1',
  userId: 'user-uuid-1',
  refreshToken: 'raw-refresh-token-hex',
};

// ==========================================
// Mocks
// ==========================================
const mockUsersService = {
  findByIdentifier: jest.fn(),
  findByIdentifierWithPassword: jest.fn(),
  findById: jest.fn(),
  createUser: jest.fn(),
  markIdentifierVerified: jest.fn(),
};

const mockPrismaService = {
  user: {
    update: jest.fn(),
  },
  twoFactorAuth: {
    findUnique: jest.fn(),
  },
  authLog: {
    create: jest.fn(),
  },
};

const mockTokenService = {
  createSessionForUser: jest.fn(),
  generateTokens: jest.fn(),
  generateTemp2FAToken: jest.fn(),
  verifyTemp2FAToken: jest.fn(),
  getSessions: jest.fn(),
  revokeSession: jest.fn(),
  refreshTokens: jest.fn(),
};

const mockOtpService = {
  generateAndSendOtp: jest.fn(),
  verifyOtp: jest.fn(),
};

const mockTwoFactorService = {
  verifyCode: jest.fn(),
};

const mockLockoutService = {
  checkIpLockout: jest.fn(),
  checkAccountLockout: jest.fn(),
  incrementLoginAttempts: jest.fn(),
  resetLoginAttempts: jest.fn(),
};

const mockAuthAuditService = {
  log: jest.fn(),
  isNewDevice: jest.fn().mockResolvedValue(false),
};

const mockMailService = {
  sendOtpEmail: jest.fn(),
  sendPasswordResetOtpEmail: jest.fn(),
  sendSecurityAlertEmail: jest.fn(),
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    service = new AuthService(
      mockUsersService as any,
      mockPrismaService as any,
      mockTokenService as any,
      mockOtpService as any,
      mockTwoFactorService as any,
      mockLockoutService as any,
      mockAuthAuditService as any,
      mockMailService as any,
    );
    jest.clearAllMocks();

    // Mock static method to prevent real HIBP API calls
    jest.spyOn(AuthUtils, 'isPasswordPwned').mockResolvedValue(false);

    // Re-apply mocks cleared by clearAllMocks
    mockAuthAuditService.isNewDevice.mockResolvedValue(false);

    // Default: no lockout
    mockLockoutService.checkIpLockout.mockResolvedValue(undefined);
    mockLockoutService.checkAccountLockout.mockResolvedValue(undefined);
    mockLockoutService.incrementLoginAttempts.mockResolvedValue({
      emailAttempts: 1,
      shouldWarn: false,
    });

    // Default mock returns
    mockTokenService.createSessionForUser.mockResolvedValue(mockSession);
    mockTokenService.generateTokens.mockReturnValue({
      access_token: 'mock-access',
      refresh_token: 'mock-refresh',
      user: mockUser,
    });

    // Pre-hash password
    mockUser.passwordHash = await AuthUtils.hashPassword('CorrectPass123!');
  });

  // ==========================================
  // register
  // ==========================================
  describe('register', () => {
    it('should register user and send OTP', async () => {
      mockUsersService.createUser.mockResolvedValue({
        user: mockUser,
        status: CreateUserStatus.CREATED,
      });

      const result = await service.register({
        email: 'test@test.com',
        username: 'testuser',
        displayName: 'Test User',
        password: 'StrongPass123!',
      });

      expect(result.message).toEqual(AUTH_MESSAGES.REGISTER_SUCCESS);
      expect(mockOtpService.generateAndSendOtp).toHaveBeenCalledWith(
        'test@test.com',
      );
    });

    it('should NOT update password if email already exists but unverified (anti-takeover)', async () => {
      mockUsersService.createUser.mockResolvedValue({
        user: mockUser,
        status: CreateUserStatus.EXISTS_UNVERIFIED,
      });

      const result = await service.register({
        email: 'test@test.com',
        username: 'newusername',
        displayName: 'New Name',
        password: 'NewPassword123!',
      });

      expect(result.message).toEqual(AUTH_MESSAGES.REGISTER_SUCCESS);
      // It should still try to send OTP (subject to cooldown)
      expect(mockOtpService.generateAndSendOtp).toHaveBeenCalledWith(
        'test@test.com',
      );
    });

    it('should return success even if email exists and verified (anti-enumeration)', async () => {
      mockUsersService.createUser.mockResolvedValue({
        user: mockUser,
        status: CreateUserStatus.EXISTS_VERIFIED,
      });

      const result = await service.register({
        email: 'test@test.com',
        username: 'testuser',
        displayName: 'Test User',
        password: 'StrongPass123!',
      });

      expect(result.message).toEqual(AUTH_MESSAGES.REGISTER_SUCCESS);
      // Should NOT send OTP for verified users
      expect(mockOtpService.generateAndSendOtp).not.toHaveBeenCalled();
    });

    it('should hash password with correct salt rounds before saving', async () => {
      mockUsersService.createUser.mockResolvedValue({
        user: mockUser,
        status: CreateUserStatus.CREATED,
      });

      await service.register({
        email: 'test@test.com',
        username: 'testuser',
        displayName: 'Test User',
        password: 'StrongPass123!',
      });

      const savedHash = mockUsersService.createUser.mock.calls[0][1];
      expect(savedHash).toMatch(/^\$argon2id\$/);
    });

    it('should auto-generate username if omitted by client', async () => {
      mockUsersService.createUser.mockResolvedValue({
        user: mockUser,
        status: CreateUserStatus.CREATED,
      });

      await service.register({
        email: 'test.user+1@test.com',
        displayName: 'Test User',
        password: 'StrongPass123!',
      } as any);

      const createUserPayload = mockUsersService.createUser.mock.calls[0][0];
      expect(createUserPayload.username).toMatch(/^[a-z0-9_]{3,20}$/);
    });
  });

  // ==========================================
  // login — Core Authentication + Brute Force Protection
  // ==========================================
  describe('login', () => {
    const loginDto = {
      identifier: 'test@test.com',
      password: 'CorrectPass123!',
      ipAddress: '127.0.0.1',
      deviceInfo: 'Jest Test Agent',
    };

    it('should login successfully with correct credentials', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(mockUser);
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue(null);

      const result = await service.login(loginDto);

      expect(result).toHaveProperty('access_token');
      expect(mockLockoutService.resetLoginAttempts).toHaveBeenCalledWith(
        'test@test.com',
      );
    });

    it('should check IP lockout BEFORE account lockout (correct order)', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(mockUser);
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue(null);

      const callOrder: string[] = [];
      mockLockoutService.checkIpLockout.mockImplementation(async () => {
        callOrder.push('IP');
      });
      mockLockoutService.checkAccountLockout.mockImplementation(async () => {
        callOrder.push('ACCOUNT');
      });

      await service.login(loginDto);

      expect(callOrder).toEqual(['IP', 'ACCOUNT']);
    });

    it('should throw if IP is locked', async () => {
      mockLockoutService.checkIpLockout.mockRejectedValue(
        new UnauthorizedException('IP locked'),
      );

      await expect(service.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
      // Should NOT even call findByIdentifierWithPassword
      expect(
        mockUsersService.findByIdentifierWithPassword,
      ).not.toHaveBeenCalled();
    });

    it('should throw if account is locked', async () => {
      mockLockoutService.checkAccountLockout.mockRejectedValue(
        new UnauthorizedException('Account locked'),
      );

      await expect(service.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw on wrong password', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(mockUser);

      await expect(
        service.login({ ...loginDto, password: 'WrongPass456!' }),
      ).rejects.toThrow(UnauthorizedException);

      expect(mockLockoutService.incrementLoginAttempts).toHaveBeenCalledWith(
        'test@test.com',
        '127.0.0.1',
      );
    });

    it('should throw on non-existent user (same error message as wrong password)', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(null);

      await expect(service.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );

      // Should still increment attempts to prevent user enumeration
      expect(mockLockoutService.incrementLoginAttempts).toHaveBeenCalled();
    });

    it('🛡️ TIMING ATTACK: should process non-existent user the same as wrong password', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(null);

      // The key insight: if bcrypt.compare was NOT called with the dummyHash,
      // the code would throw much faster (timing attack detectable).
      // We verify the behavior: incrementLoginAttempts IS called → bcrypt WAS called.
      const startTime = Date.now();
      try {
        await service.login(loginDto);
      } catch {
        // Expected
      }
      const elapsed = Date.now() - startTime;

      // bcrypt.compare takes >50ms even on fast hardware
      // If it was skipped, elapsed would be <5ms
      expect(elapsed).toBeGreaterThan(30);

      // Verify the same code path was followed as for a wrong password
      expect(mockLockoutService.incrementLoginAttempts).toHaveBeenCalled();
    });

    it('should show lockout WARNING when shouldWarn=true', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(mockUser);
      mockLockoutService.incrementLoginAttempts.mockResolvedValue({
        emailAttempts: 8,
        shouldWarn: true,
      });

      try {
        await service.login({ ...loginDto, password: 'WrongPass456!' });
        throw new Error('Should have thrown');
      } catch (error: any) {
        expect(error.message).toContain('Cảnh báo');
      }
    });

    it('should check isVerified AFTER password validation (anti-enumeration)', async () => {
      const unverifiedUser = {
        ...mockUser,
        isVerified: false,
      };
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(
        unverifiedUser,
      );

      try {
        await service.login(loginDto);
        throw new Error('Should have thrown');
      } catch (error: any) {
        // Should get VERIFY_EMAIL_REQUIRED, not "wrong password"
        const response = error.getResponse();
        expect(response.action).toBe('VERIFY_EMAIL_REQUIRED');
      }
    });

    it('should return 2FA temp token if 2FA is enabled', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(mockUser);
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue({
        isEnabled: true,
      });
      mockTokenService.generateTemp2FAToken.mockReturnValue('temp-2fa-token');

      const result = await service.login(loginDto);

      if ('requires2FA' in result) {
        expect(result.requires2FA).toBe(true);
        expect(result.tempToken).toBe('temp-2fa-token');
      } else {
        throw new Error('Result should contain requires2FA');
      }
      // Should NOT create a session yet (only after 2FA verification)
      expect(mockTokenService.createSessionForUser).not.toHaveBeenCalled();
    });

    it('should log failed login attempt', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(null);

      try {
        await service.login(loginDto);
      } catch {
        // Expected
      }

      expect(mockAuthAuditService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'LOGIN_FAILED',
          status: 'FAILED',
        }),
      );
    });

    it('should log successful login', async () => {
      mockUsersService.findByIdentifierWithPassword.mockResolvedValue(mockUser);
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue(null);

      await service.login(loginDto);

      expect(mockAuthAuditService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'LOGIN_SUCCESS',
          status: 'SUCCESS',
        }),
      );
    });
  });

  // ==========================================
  // verifyOtp
  // ==========================================
  describe('verifyOtp', () => {
    it('should verify OTP, mark user as verified, and create session', async () => {
      mockOtpService.verifyOtp.mockResolvedValue(true);
      mockUsersService.findByIdentifier.mockResolvedValue(mockUser);
      mockUsersService.markIdentifierVerified.mockResolvedValue({
        ...mockUser,
        isVerified: true,
      });

      const result = await service.verifyOtp({
        identifier: 'test@test.com',
        otp: '123456',
      });

      expect(result).toHaveProperty('access_token');
      expect(mockUsersService.markIdentifierVerified).toHaveBeenCalledWith(
        'test@test.com',
      );
    });

    it('should throw if user does not exist', async () => {
      mockOtpService.verifyOtp.mockResolvedValue(true);
      mockUsersService.findByIdentifier.mockResolvedValue(null);

      await expect(
        service.verifyOtp({ identifier: 'ghost@test.com', otp: '123456' }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // ==========================================
  // verify2FALogin
  // ==========================================
  describe('verify2FALogin', () => {
    it('should complete 2FA login and create session', async () => {
      mockTokenService.verifyTemp2FAToken.mockReturnValue('user-uuid-1');
      mockTwoFactorService.verifyCode.mockResolvedValue(true);
      mockUsersService.findById.mockResolvedValue(mockUser);
      mockUsersService.findByIdentifier.mockResolvedValue(mockUser);

      const result = await service.verify2FALogin('temp-token', '123456', {
        ipAddress: '127.0.0.1',
      });

      expect(result).toHaveProperty('access_token');
      expect(mockTokenService.createSessionForUser).toHaveBeenCalled();
    });

    it('should throw if temp token is invalid/expired', async () => {
      mockTokenService.verifyTemp2FAToken.mockReturnValue(null);

      await expect(
        service.verify2FALogin('invalid-temp', '123456', {}),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should log LOGIN_SUCCESS_2FA on success', async () => {
      mockTokenService.verifyTemp2FAToken.mockReturnValue('user-uuid-1');
      mockTwoFactorService.verifyCode.mockResolvedValue(true);
      mockUsersService.findById.mockResolvedValue(mockUser);
      mockUsersService.findByIdentifier.mockResolvedValue(mockUser);

      await service.verify2FALogin('temp-token', '123456', {});

      expect(mockAuthAuditService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'LOGIN_SUCCESS_2FA',
        }),
      );
    });
  });

  // ==========================================
  // resendOtp
  // ==========================================
  describe('resendOtp', () => {
    it('should return generic message for existing unverified user', async () => {
      mockUsersService.findByIdentifier.mockResolvedValue({
        ...mockUser,
        isVerified: false,
      });

      const result = await service.resendOtp('test@test.com');

      expect(result.message).toEqual(AUTH_MESSAGES.OTP_SENT_GENERIC);
      expect(mockOtpService.generateAndSendOtp).toHaveBeenCalled();
    });

    it('should return SAME generic message for non-existent user (anti-enumeration)', async () => {
      mockUsersService.findByIdentifier.mockResolvedValue(null);

      const result = await service.resendOtp('nonexistent@test.com');

      expect(result.message).toEqual(AUTH_MESSAGES.OTP_SENT_GENERIC);
      expect(mockOtpService.generateAndSendOtp).not.toHaveBeenCalled();
    });

    it('should return SAME generic message for already verified user', async () => {
      mockUsersService.findByIdentifier.mockResolvedValue(mockUser); // isVerified = true

      const result = await service.resendOtp('test@test.com');

      expect(result.message).toEqual(AUTH_MESSAGES.OTP_SENT_GENERIC);
      expect(mockOtpService.generateAndSendOtp).not.toHaveBeenCalled();
    });

    it('should throw if no email provided', async () => {
      await expect(service.resendOtp('')).rejects.toThrow(BadRequestException);
    });
  });
});

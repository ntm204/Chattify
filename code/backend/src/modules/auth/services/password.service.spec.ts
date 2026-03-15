/* eslint-disable @typescript-eslint/no-unsafe-argument */
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { PasswordService } from './password.service';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';
import { AuthUtils } from '../../../core/utils/auth.util';

// ==========================================
// Mock Data
// ==========================================
const mockUser = {
  id: 'user-uuid-1',
  email: 'test@test.com',
  phone: '0987654321',
  passwordHash: '',
  isVerified: true,
};

// ==========================================
// Mocks
// ==========================================
const mockPrismaService = {
  user: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  passwordHistory: {
    findMany: jest.fn().mockResolvedValue([]),
    deleteMany: jest.fn(),
    create: jest.fn(),
  },
  authLog: {
    create: jest.fn(),
  },
  $transaction: jest.fn(),
};

const mockOtpService = {
  generateAndSendOtp: jest.fn(),
  verifyOtp: jest.fn(),
};

const mockTokenService = {
  revokeAllSessions: jest.fn(),
};

const mockAuthAuditService = {
  log: jest.fn(),
};

const mockMailService = {
  sendSecurityAlertEmail: jest.fn(),
};

describe('PasswordService', () => {
  let service: PasswordService;

  beforeEach(async () => {
    service = new PasswordService(
      mockPrismaService as any,
      mockOtpService as any,
      mockTokenService as any,
      mockAuthAuditService as any,
      mockMailService as any,
    );
    jest.clearAllMocks();

    // Mock static method to prevent real HIBP API calls
    jest.spyOn(AuthUtils, 'isPasswordPwned').mockResolvedValue(false);

    // Re-apply mocks cleared by clearAllMocks
    mockAuthAuditService.log.mockResolvedValue(undefined);
    mockMailService.sendSecurityAlertEmail.mockResolvedValue(undefined);
    mockPrismaService.passwordHistory.findMany.mockResolvedValue([]);

    // Default mock for $transaction to execute the callback immediately
    mockPrismaService.$transaction.mockImplementation(
      async (callback: (tx: any) => Promise<unknown>) => {
        return callback(mockPrismaService);
      },
    );

    // Pre-hash password
    mockUser.passwordHash = await AuthUtils.hashPassword('OldPass123!');
  });

  // ==========================================
  // forgotPassword
  // ==========================================
  describe('forgotPassword', () => {
    it('should return generic message when user exists', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue(mockUser);

      const result = await service.forgotPassword({
        identifier: 'test@test.com',
      });

      expect(result.message).toEqual(AUTH_MESSAGES.FORGOT_PASSWORD_GENERIC);
      expect(mockOtpService.generateAndSendOtp).toHaveBeenCalledWith(
        'test@test.com',
        'PASSWORD_RESET',
      );
    });

    it('should return SAME generic message when user does NOT exist (anti-enumeration)', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue(null);

      const result = await service.forgotPassword({
        identifier: 'ghost@test.com',
      });

      expect(result.message).toEqual(AUTH_MESSAGES.FORGOT_PASSWORD_GENERIC);
      expect(mockOtpService.generateAndSendOtp).not.toHaveBeenCalled();
    });
  });

  // ==========================================
  // resetPassword
  // ==========================================
  describe('resetPassword', () => {
    const resetDto = {
      identifier: 'test@test.com',
      otp: '123456',
      newPassword: 'NewPass456!',
    };

    it('should reset password and revoke all sessions', async () => {
      mockOtpService.verifyOtp.mockResolvedValue(true);
      mockPrismaService.user.findFirst.mockResolvedValue(mockUser);

      const result = await service.resetPassword(resetDto, {
        ipAddress: '1.2.3.4',
      });

      expect(result.message).toContain('thành công');
      expect(mockTokenService.revokeAllSessions).toHaveBeenCalledWith(
        mockUser.id,
      );
      expect(mockPrismaService.user.update).toHaveBeenCalled();
    });

    it('should throw if user not found during reset', async () => {
      mockOtpService.verifyOtp.mockResolvedValue(true);
      mockPrismaService.user.findFirst.mockResolvedValue(null);

      await expect(service.resetPassword(resetDto, {})).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // ==========================================
  // changePassword
  // ==========================================
  describe('changePassword', () => {
    const changeDto = {
      oldPassword: 'OldPass123!',
      newPassword: 'NewPass456!',
    };

    it('should change password successfully', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      const result = await service.changePassword(mockUser.id, changeDto, {});

      expect(result.message).toEqual(AUTH_MESSAGES.CHANGE_PASSWORD_SUCCESS);
      expect(mockPrismaService.user.update).toHaveBeenCalled();
    });

    it('should throw if old password is wrong', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await expect(
        service.changePassword(
          mockUser.id,
          {
            ...changeDto,
            oldPassword: 'WrongPassword!',
          },
          {},
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if user not found', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.changePassword('ghost-id', changeDto, {}),
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});

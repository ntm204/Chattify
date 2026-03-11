/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access */
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { PasswordService } from './password.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import * as bcrypt from 'bcrypt';

// ==========================================
// Mocks
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

const mockPrismaService = {
  user: {
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  authLog: {
    create: jest.fn(),
  },
};

const mockUsersService = {
  findByEmail: jest.fn(),
};

const mockTokenService = {
  revokeAllSessions: jest.fn(),
};

const mockOtpService = {
  generateAndSendOtp: jest.fn(),
  verifyOtp: jest.fn(),
};

describe('PasswordService', () => {
  let service: PasswordService;

  beforeEach(async () => {
    service = new PasswordService(
      mockPrismaService as any,
      mockUsersService as any,
      mockTokenService as any,
      mockOtpService as any,
    );
    jest.clearAllMocks();

    // Pre-hash a password for reuse
    mockUser.passwordHash = await bcrypt.hash(
      'OldPass123!',
      AUTH_CONSTANTS.SALT_ROUNDS,
    );
  });

  // ==========================================
  // forgotPassword
  // ==========================================
  describe('forgotPassword', () => {
    it('should return generic message when user exists', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);

      const result = await service.forgotPassword({ email: 'test@test.com' });

      expect(result.message).toContain('Nếu email hợp lệ');
      expect(mockOtpService.generateAndSendOtp).toHaveBeenCalledWith(
        'test@test.com',
        'PASSWORD_RESET',
      );
    });

    it('should return SAME generic message when user does NOT exist (anti-enumeration)', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);

      const result = await service.forgotPassword({
        email: 'nonexistent@test.com',
      });

      expect(result.message).toContain('Nếu email hợp lệ');
      expect(mockOtpService.generateAndSendOtp).not.toHaveBeenCalled();
    });
  });

  // ==========================================
  // resetPassword
  // ==========================================
  describe('resetPassword', () => {
    it('should reset password and revoke all sessions', async () => {
      mockOtpService.verifyOtp.mockResolvedValue(true);
      mockPrismaService.user.update.mockResolvedValue(mockUser);

      const result = await service.resetPassword(
        {
          email: 'test@test.com',
          otp: '123456',
          newPassword: 'NewPass123!',
        },
        { ipAddress: '127.0.0.1', deviceInfo: 'Jest Agent' },
      );

      expect(result.message).toContain('Đổi mật khẩu thành công');
      expect(mockTokenService.revokeAllSessions).toHaveBeenCalledWith(
        mockUser.id,
      );
      expect(mockPrismaService.authLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          action: 'PASSWORD_RESET',
          status: 'SUCCESS',
          ipAddress: '127.0.0.1',
          deviceInfo: 'Jest Agent',
        }),
      });
    });

    it('should verify OTP with PASSWORD_RESET type', async () => {
      mockOtpService.verifyOtp.mockResolvedValue(true);
      mockPrismaService.user.update.mockResolvedValue(mockUser);

      await service.resetPassword(
        {
          email: 'test@test.com',
          otp: '123456',
          newPassword: 'NewPass123!',
        },
        { ipAddress: '127.0.0.1', deviceInfo: 'Jest Agent' },
      );

      expect(mockOtpService.verifyOtp).toHaveBeenCalledWith(
        'test@test.com',
        '123456',
        'PASSWORD_RESET',
      );
    });

    it('should hash the new password before saving', async () => {
      mockOtpService.verifyOtp.mockResolvedValue(true);
      mockPrismaService.user.update.mockResolvedValue(mockUser);

      await service.resetPassword(
        {
          email: 'test@test.com',
          otp: '123456',
          newPassword: 'NewPass123!',
        },
        { ipAddress: '127.0.0.1', deviceInfo: 'Jest Agent' },
      );

      const savedHash =
        mockPrismaService.user.update.mock.calls[0][0].data.passwordHash;
      // Verify it's a bcrypt hash, not plaintext
      expect(savedHash).toMatch(/^\$2[aby]\$\d+\$/);
      // Verify the hash matches the new password
      expect(await bcrypt.compare('NewPass123!', savedHash)).toBe(true);
    });
  });

  // ==========================================
  // changePassword
  // ==========================================
  describe('changePassword', () => {
    it('should change password successfully', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      const result = await service.changePassword(
        'user-uuid-1',
        {
          oldPassword: 'OldPass123!',
          newPassword: 'NewPass456!',
        },
        { ipAddress: '127.0.0.1', deviceInfo: 'Jest Agent' },
      );

      expect(result.message).toContain('thay đổi mật khẩu thành công');
    });

    it('should revoke all sessions after password change', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await service.changePassword(
        'user-uuid-1',
        {
          oldPassword: 'OldPass123!',
          newPassword: 'NewPass456!',
        },
        { ipAddress: '127.0.0.1', deviceInfo: 'Jest Agent' },
      );

      expect(mockTokenService.revokeAllSessions).toHaveBeenCalledWith(
        'user-uuid-1',
      );
    });

    it('should throw if user not found', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.changePassword('nonexistent', {
          oldPassword: 'OldPass123!',
          newPassword: 'NewPass456!',
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw if old password is wrong', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await expect(
        service.changePassword('user-uuid-1', {
          oldPassword: 'WrongPass123!',
          newPassword: 'NewPass456!',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if new password equals old password', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await expect(
        service.changePassword('user-uuid-1', {
          oldPassword: 'OldPass123!',
          newPassword: 'OldPass123!',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should log PASSWORD_CHANGE action with IP and device info', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await service.changePassword(
        'user-uuid-1',
        {
          oldPassword: 'OldPass123!',
          newPassword: 'NewPass456!',
        },
        { ipAddress: '127.0.0.1', deviceInfo: 'Jest Agent' },
      );

      expect(mockPrismaService.authLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          action: 'PASSWORD_CHANGE',
          status: 'SUCCESS',
          ipAddress: '127.0.0.1',
          deviceInfo: 'Jest Agent',
        }),
      });
    });
  });
});

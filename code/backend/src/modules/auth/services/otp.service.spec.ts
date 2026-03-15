/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access */
import { BadRequestException } from '@nestjs/common';
import { createHash } from 'crypto';
import { OtpService } from './otp.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';
import { AUTH_MESSAGES } from '../../../core/config/auth.messages';

const hashOtp = (otp: string) => createHash('sha256').update(otp).digest('hex');

// ==========================================
// Mocks
// ==========================================
const mockRedisClient = {
  incr: jest.fn(),
  expire: jest.fn(),
  ttl: jest.fn(),
  del: jest.fn(),
  getdel: jest.fn(),
};

const mockRedisService = {
  getCache: jest.fn(),
  setCache: jest.fn(),
  deleteCache: jest.fn(),
  getClient: jest.fn().mockReturnValue(mockRedisClient),
};

const mockMailService = {
  sendOtpEmail: jest.fn().mockResolvedValue(undefined),
  sendPasswordResetOtpEmail: jest.fn().mockResolvedValue(undefined),
};

const mockSmsService = {
  sendOtp: jest.fn().mockResolvedValue(undefined),
};

describe('OtpService', () => {
  let service: OtpService;

  beforeEach(() => {
    service = new OtpService(
      mockMailService as any,
      mockSmsService as any,
      mockRedisService as any,
    );
    jest.clearAllMocks();
    mockRedisService.getClient.mockReturnValue(mockRedisClient);
    mockMailService.sendOtpEmail.mockResolvedValue(undefined);
    mockMailService.sendPasswordResetOtpEmail.mockResolvedValue(undefined);
    mockSmsService.sendOtp.mockResolvedValue(undefined);
  });

  // ==========================================
  // generateAndSendOtp
  // ==========================================
  describe('generateAndSendOtp', () => {
    it('should generate and send OTP successfully', async () => {
      mockRedisClient.incr.mockResolvedValue(1); // daily count
      mockRedisService.getCache.mockResolvedValue(null); // no cooldown

      const result = await service.generateAndSendOtp('test@test.com');

      expect(result.message).toEqual(AUTH_MESSAGES.OTP_SENT_GENERIC);
      expect(mockMailService.sendOtpEmail).toHaveBeenCalledWith(
        'test@test.com',
        expect.any(String),
      );
    });

    it('should send password reset email when type is PASSWORD_RESET', async () => {
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisService.getCache.mockResolvedValue(null);

      await service.generateAndSendOtp('test@test.com', 'PASSWORD_RESET');

      expect(mockMailService.sendPasswordResetOtpEmail).toHaveBeenCalled();
      expect(mockMailService.sendOtpEmail).not.toHaveBeenCalled();
    });

    it('should set OTP in Redis with correct TTL', async () => {
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisService.getCache.mockResolvedValue(null);

      await service.generateAndSendOtp('test@test.com');

      expect(mockRedisService.setCache).toHaveBeenCalledWith(
        expect.stringContaining('otp:VERIFICATION:test@test.com'),
        expect.any(String),
        AUTH_CONSTANTS.OTP_TTL_SECONDS,
      );
    });

    it('should set cooldown after sending OTP', async () => {
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisService.getCache.mockResolvedValue(null);

      await service.generateAndSendOtp('test@test.com');

      expect(mockRedisService.setCache).toHaveBeenCalledWith(
        expect.stringContaining('otp_cooldown:'),
        '1',
        AUTH_CONSTANTS.OTP_COOLDOWN_SECONDS,
      );
    });

    it('should reject if daily limit exceeded', async () => {
      mockRedisClient.incr.mockResolvedValue(
        AUTH_CONSTANTS.OTP_DAILY_LIMIT + 1,
      );

      await expect(service.generateAndSendOtp('test@test.com')).rejects.toThrow(
        BadRequestException,
      );
      expect(mockMailService.sendOtpEmail).not.toHaveBeenCalled();
    });

    it('should reject if on cooldown', async () => {
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisService.getCache.mockResolvedValue('1'); // cooldown active
      mockRedisClient.ttl.mockResolvedValue(45);

      await expect(service.generateAndSendOtp('test@test.com')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should revert Redis state if mail sending fails', async () => {
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisService.getCache.mockResolvedValue(null);
      mockMailService.sendOtpEmail.mockRejectedValue(
        new Error('SMTP connection failed'),
      );

      await expect(service.generateAndSendOtp('test@test.com')).rejects.toThrow(
        BadRequestException,
      );

      // Verify Redis state was reverted (OTP and cooldown deleted)
      expect(mockRedisService.deleteCache).toHaveBeenCalledWith(
        expect.stringContaining('otp:VERIFICATION:'),
      );
      expect(mockRedisService.deleteCache).toHaveBeenCalledWith(
        expect.stringContaining('otp_cooldown:'),
      );
    });

    it('should set 24h expire on first daily count', async () => {
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisService.getCache.mockResolvedValue(null);

      await service.generateAndSendOtp('test@test.com');

      expect(mockRedisClient.expire).toHaveBeenCalledWith(
        expect.stringContaining('otp_daily:'),
        86400,
      );
    });

    it('should generate a 6-digit OTP', async () => {
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisService.getCache.mockResolvedValue(null);

      await service.generateAndSendOtp('test@test.com');

      const otpArg = mockMailService.sendOtpEmail.mock.calls[0][1];
      expect(otpArg).toMatch(/^\d{6}$/);
    });
  });

  // ==========================================
  // verifyOtp
  // ==========================================
  describe('verifyOtp', () => {
    it('should verify OTP successfully', async () => {
      mockRedisService.getCache.mockResolvedValue(hashOtp('123456'));
      mockRedisClient.del.mockResolvedValue(1);

      const result = await service.verifyOtp('test@test.com', '123456');

      expect(result).toBe(true);
      // Should delete OTP and attempts after success
      expect(mockRedisClient.del).toHaveBeenCalledWith(
        expect.stringContaining('otp:VERIFICATION:'),
      );
      expect(mockRedisService.deleteCache).toHaveBeenCalledWith(
        expect.stringContaining('otp_attempts:'),
      );
    });

    it('should throw if OTP expired (not found in Redis)', async () => {
      mockRedisService.getCache.mockResolvedValue(null);

      await expect(
        service.verifyOtp('test@test.com', '123456'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw with remaining attempts on wrong OTP', async () => {
      mockRedisService.getCache.mockResolvedValue(hashOtp('123456'));
      mockRedisClient.incr.mockResolvedValue(1);

      try {
        await service.verifyOtp('test@test.com', 'wrong1');
        fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).toContain(
          `${AUTH_CONSTANTS.OTP_MAX_ATTEMPTS - 1}`,
        );
      }
    });

    it('should destroy OTP after MAX_ATTEMPTS wrong tries', async () => {
      mockRedisService.getCache.mockResolvedValue(hashOtp('123456'));
      mockRedisClient.incr.mockResolvedValue(AUTH_CONSTANTS.OTP_MAX_ATTEMPTS);

      await expect(
        service.verifyOtp('test@test.com', 'wrong1'),
      ).rejects.toThrow(BadRequestException);

      // Attempt counter should be updated
      expect(mockRedisService.setCache).toHaveBeenCalledWith(
        expect.stringContaining('otp_attempts:'),
        expect.any(String),
        expect.any(Number),
      );
    });

    it('should set expire on attempts counter on first wrong try', async () => {
      mockRedisService.getCache.mockResolvedValue(hashOtp('123456'));
      mockRedisClient.incr.mockResolvedValue(1);

      try {
        await service.verifyOtp('test@test.com', 'wrong1');
      } catch {
        // Expected
      }

      expect(mockRedisClient.expire).toHaveBeenCalledWith(
        expect.stringContaining('otp_attempts:'),
        AUTH_CONSTANTS.OTP_TTL_SECONDS,
      );
    });

    it('should work with PASSWORD_RESET type', async () => {
      mockRedisService.getCache.mockResolvedValue(hashOtp('654321'));
      mockRedisClient.del.mockResolvedValue(1);

      const result = await service.verifyOtp(
        'test@test.com',
        '654321',
        'PASSWORD_RESET',
      );

      expect(result).toBe(true);
    });
  });
});

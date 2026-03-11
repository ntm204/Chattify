/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call */
import { UnauthorizedException } from '@nestjs/common';
import { LockoutService } from './lockout.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';

// ==========================================
// Mock RedisService
// ==========================================
const mockRedisClient = {
  incr: jest.fn(),
  expire: jest.fn(),
  ttl: jest.fn(),
};

const mockRedisService = {
  getCache: jest.fn(),
  setCache: jest.fn(),
  deleteCache: jest.fn(),
  getClient: jest.fn().mockReturnValue(mockRedisClient),
};

describe('LockoutService', () => {
  let service: LockoutService;

  beforeEach(() => {
    service = new LockoutService(mockRedisService as any);
    jest.clearAllMocks();
    mockRedisService.getClient.mockReturnValue(mockRedisClient);
  });

  // ==========================================
  // checkAccountLockout
  // ==========================================
  describe('checkAccountLockout', () => {
    it('should pass if account is not locked', async () => {
      mockRedisService.getCache.mockResolvedValue(null);
      await expect(
        service.checkAccountLockout('test@test.com'),
      ).resolves.toBeUndefined();
    });

    it('should throw UnauthorizedException if account is locked', async () => {
      mockRedisService.getCache.mockResolvedValue('1');
      mockRedisClient.ttl.mockResolvedValue(600); // 10 phút còn lại

      await expect(
        service.checkAccountLockout('test@test.com'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should include action and suggestion in lockout response', async () => {
      mockRedisService.getCache.mockResolvedValue('1');
      mockRedisClient.ttl.mockResolvedValue(300);

      try {
        await service.checkAccountLockout('test@test.com');
        fail('Should have thrown');
      } catch (error: any) {
        const response = error.getResponse();
        expect(response.action).toBe('ACCOUNT_LOCKED');
        expect(response.suggestion).toContain('Quên mật khẩu');
      }
    });

    it('should calculate remaining minutes correctly', async () => {
      mockRedisService.getCache.mockResolvedValue('1');
      mockRedisClient.ttl.mockResolvedValue(90); // 1.5 phút → ceil = 2

      try {
        await service.checkAccountLockout('test@test.com');
        fail('Should have thrown');
      } catch (error: any) {
        expect(error.getResponse().message).toContain('2 phút');
      }
    });
  });

  // ==========================================
  // checkIpLockout
  // ==========================================
  describe('checkIpLockout', () => {
    it('should skip check if no ipAddress provided', async () => {
      await expect(service.checkIpLockout(undefined)).resolves.toBeUndefined();
      expect(mockRedisService.getCache).not.toHaveBeenCalled();
    });

    it('should pass if IP is not locked', async () => {
      mockRedisService.getCache.mockResolvedValue(null);
      await expect(
        service.checkIpLockout('192.168.1.1'),
      ).resolves.toBeUndefined();
    });

    it('should throw if IP is locked', async () => {
      mockRedisService.getCache.mockResolvedValue('1');
      mockRedisClient.ttl.mockResolvedValue(600);
      await expect(service.checkIpLockout('192.168.1.1')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should include remaining minutes in IP lockout message', async () => {
      mockRedisService.getCache.mockResolvedValue('1');
      mockRedisClient.ttl.mockResolvedValue(120); // 2 phút

      try {
        await service.checkIpLockout('192.168.1.1');
        fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).toContain('2 phút');
      }
    });
  });

  // ==========================================
  // incrementLoginAttempts
  // ==========================================
  describe('incrementLoginAttempts', () => {
    it('should set expire on first failed attempt', async () => {
      mockRedisClient.incr.mockResolvedValue(1);

      await service.incrementLoginAttempts('test@test.com');

      expect(mockRedisClient.expire).toHaveBeenCalledWith(
        'login_attempts:test@test.com',
        AUTH_CONSTANTS.LOCKOUT_DURATION_SECONDS,
      );
    });

    it('should NOT set expire on subsequent attempts', async () => {
      mockRedisClient.incr.mockResolvedValue(3);

      await service.incrementLoginAttempts('test@test.com');

      expect(mockRedisClient.expire).not.toHaveBeenCalledWith(
        'login_attempts:test@test.com',
        expect.anything(),
      );
    });

    it('should trigger account lockout at MAX_LOGIN_ATTEMPTS', async () => {
      mockRedisClient.incr.mockResolvedValue(AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS);

      await service.incrementLoginAttempts('test@test.com');

      expect(mockRedisService.setCache).toHaveBeenCalledWith(
        'login_lockout:test@test.com',
        '1',
        AUTH_CONSTANTS.LOCKOUT_DURATION_SECONDS,
      );
      expect(mockRedisService.deleteCache).toHaveBeenCalledWith(
        'login_attempts:test@test.com',
      );
    });

    it('should trigger IP lockout at MAX_IP_ATTEMPTS', async () => {
      // Email attempts = 1 (first)
      mockRedisClient.incr
        .mockResolvedValueOnce(1) // email incr
        .mockResolvedValueOnce(AUTH_CONSTANTS.MAX_IP_ATTEMPTS); // IP incr

      await service.incrementLoginAttempts('test@test.com', '192.168.1.1');

      expect(mockRedisService.setCache).toHaveBeenCalledWith(
        'login_lockout_ip:192.168.1.1',
        '1',
        AUTH_CONSTANTS.IP_LOCKOUT_DURATION_SECONDS,
      );
    });

    it('should return shouldWarn=false when far from lockout threshold', async () => {
      mockRedisClient.incr.mockResolvedValue(1);

      const result = await service.incrementLoginAttempts('test@test.com');

      expect(result.shouldWarn).toBe(false);
    });

    it('should return shouldWarn=true when near lockout threshold', async () => {
      // MAX_LOGIN_ATTEMPTS = 10, LOCKOUT_WARNING_THRESHOLD = 3
      // remaining = 10 - 8 = 2, which is <= 3 → shouldWarn = true
      mockRedisClient.incr.mockResolvedValue(
        AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS -
          AUTH_CONSTANTS.LOCKOUT_WARNING_THRESHOLD,
      );

      const result = await service.incrementLoginAttempts('test@test.com');

      expect(result.shouldWarn).toBe(true);
    });

    it('should return shouldWarn=false when already at lockout (remaining=0)', async () => {
      mockRedisClient.incr.mockResolvedValue(AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS);

      const result = await service.incrementLoginAttempts('test@test.com');

      // remaining = 0, shouldWarn requires remaining > 0
      expect(result.shouldWarn).toBe(false);
    });

    it('should not track IP attempts when ipAddress is undefined', async () => {
      mockRedisClient.incr.mockResolvedValue(1);

      await service.incrementLoginAttempts('test@test.com', undefined);

      // incr should be called only once for email, not for IP
      expect(mockRedisClient.incr).toHaveBeenCalledTimes(1);
    });
  });

  // ==========================================
  // resetLoginAttempts
  // ==========================================
  describe('resetLoginAttempts', () => {
    it('should delete both attempts and lockout keys', async () => {
      await service.resetLoginAttempts('test@test.com');

      expect(mockRedisService.deleteCache).toHaveBeenCalledWith(
        'login_attempts:test@test.com',
      );
      expect(mockRedisService.deleteCache).toHaveBeenCalledWith(
        'login_lockout:test@test.com',
      );
    });
  });
});

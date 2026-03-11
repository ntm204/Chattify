import {
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { TwoFactorService } from './two-factor.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';

// ==========================================
// Mocks
// ==========================================
jest.mock('speakeasy', () => ({
  generateSecret: jest.fn().mockReturnValue({
    base32: 'MOCK_BASE32_SECRET',
    otpauth_url: 'otpauth://totp/Chatiffy?secret=MOCK',
  }),
  totp: {
    verify: jest.fn(),
  },
}));

jest.mock('qrcode', () => ({
  toDataURL: jest.fn().mockResolvedValue('data:image/png;base64,mockQRcode'),
}));

import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

const mockRedisClient = {
  incr: jest.fn(),
  expire: jest.fn(),
};

const mockRedisService = {
  getCache: jest.fn(),
  setCache: jest.fn(),
  deleteCache: jest.fn(),
  getClient: jest.fn().mockReturnValue(mockRedisClient),
};

const mockPrismaService = {
  twoFactorAuth: {
    upsert: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
};

const mockConfigService = {
  get: jest.fn((key: string) => {
    if (key === 'TWO_FACTOR_ENCRYPTION_KEY')
      return 'test-encryption-key-32chars!!';
    if (key === 'TWO_FACTOR_SALT') return 'test-salt-from-env';
    return null;
  }),
};

describe('TwoFactorService', () => {
  let service: TwoFactorService;

  beforeEach(() => {
    jest.clearAllMocks();
    mockRedisService.getClient.mockReturnValue(mockRedisClient);

    service = new TwoFactorService(
      mockPrismaService as any,
      mockRedisService as any,
      mockConfigService as any,
    );
  });

  // ==========================================
  // Constructor — Key Derivation + Salt
  // ==========================================
  describe('constructor', () => {
    it('should read TWO_FACTOR_SALT from env (HACK-4 fix)', () => {
      expect(mockConfigService.get).toHaveBeenCalledWith('TWO_FACTOR_SALT');
    });

    it('should throw if TWO_FACTOR_ENCRYPTION_KEY is not defined', () => {
      const badConfig = {
        get: jest.fn().mockReturnValue(undefined),
      };
      expect(
        () =>
          new TwoFactorService(
            mockPrismaService as any,
            mockRedisService as any,
            badConfig as any,
          ),
      ).toThrow('FATAL ERROR');
    });
  });

  // ==========================================
  // generateTwoFactorAuthSecret
  // ==========================================
  describe('generateTwoFactorAuthSecret', () => {
    it('should generate QR code and store encrypted secret', async () => {
      const result = await service.generateTwoFactorAuthSecret(
        'user-uuid-1',
        'test@test.com',
      );

      expect(result.qrCodeDataUrl).toContain('data:image');
      expect(result.message).toContain('Quét mã QR');
      expect(mockPrismaService.twoFactorAuth.upsert).toHaveBeenCalledWith({
        where: { userId: 'user-uuid-1' },
        update: { secret: expect.any(String), isEnabled: false },
        create: {
          userId: 'user-uuid-1',
          secret: expect.any(String),
          isEnabled: false,
        },
      });
    });

    it('should encrypt the secret before storing (not plaintext)', async () => {
      await service.generateTwoFactorAuthSecret('user-uuid-1', 'test@test.com');

      const savedSecret =
        mockPrismaService.twoFactorAuth.upsert.mock.calls[0][0].create.secret;
      // Encrypted format: iv:authTag:data (hex:hex:hex)
      expect(savedSecret).toMatch(/^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/);
      expect(savedSecret).not.toBe('MOCK_BASE32_SECRET');
    });

    it('should NOT return plaintext secret in response', async () => {
      const result = await service.generateTwoFactorAuthSecret(
        'user-uuid-1',
        'test@test.com',
      );

      expect(result).not.toHaveProperty('secret');
      expect(JSON.stringify(result)).not.toContain('MOCK_BASE32_SECRET');
    });
  });

  // ==========================================
  // turnOnTwoFactorAuth / turnOffTwoFactorAuth
  // ==========================================
  describe('turnOnTwoFactorAuth', () => {
    it('should enable 2FA after verifying code', async () => {
      // Need to create a real encrypted secret using the service
      const encrypted = (service as any).encryptSecret('MOCK_BASE32_SECRET');
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue({
        userId: 'user-uuid-1',
        secret: encrypted,
        isEnabled: false,
      });
      (speakeasy.totp.verify as jest.Mock).mockReturnValue(true);

      const result = await service.turnOnTwoFactorAuth('user-uuid-1', '123456');

      expect(result.message).toContain('Bật 2FA thành công');
      expect(mockPrismaService.twoFactorAuth.update).toHaveBeenCalledWith({
        where: { userId: 'user-uuid-1' },
        data: { isEnabled: true },
      });
    });

    it('should throw if code is incorrect', async () => {
      const encrypted = (service as any).encryptSecret('MOCK_BASE32_SECRET');
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue({
        userId: 'user-uuid-1',
        secret: encrypted,
        isEnabled: false,
      });
      (speakeasy.totp.verify as jest.Mock).mockReturnValue(false);

      await expect(
        service.turnOnTwoFactorAuth('user-uuid-1', 'wrong'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw if no QR code generated yet', async () => {
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue(null);

      await expect(
        service.turnOnTwoFactorAuth('user-uuid-1', '123456'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('turnOffTwoFactorAuth', () => {
    it('should disable 2FA after verifying code', async () => {
      const encrypted = (service as any).encryptSecret('MOCK_BASE32_SECRET');
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue({
        userId: 'user-uuid-1',
        secret: encrypted,
        isEnabled: true,
      });
      (speakeasy.totp.verify as jest.Mock).mockReturnValue(true);

      const result = await service.turnOffTwoFactorAuth(
        'user-uuid-1',
        '123456',
      );

      expect(result.message).toContain('tắt 2FA thành công');
    });

    it('should throw if 2FA is already disabled', async () => {
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue({
        isEnabled: false,
      });

      await expect(
        service.turnOffTwoFactorAuth('user-uuid-1', '123456'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // ==========================================
  // verifyCode — Brute Force Protection
  // ==========================================
  describe('verifyCode', () => {
    beforeEach(() => {
      const encrypted = (service as any).encryptSecret('MOCK_BASE32_SECRET');
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue({
        userId: 'user-uuid-1',
        secret: encrypted,
        isEnabled: true,
      });
    });

    it('should return true for valid code', async () => {
      (speakeasy.totp.verify as jest.Mock).mockReturnValue(true);

      const result = await service.verifyCode('user-uuid-1', '123456');

      expect(result).toBe(true);
      expect(mockRedisService.deleteCache).toHaveBeenCalledWith(
        '2fa_attempts:user-uuid-1',
      );
    });

    it('should increment attempts and show remaining on wrong code', async () => {
      (speakeasy.totp.verify as jest.Mock).mockReturnValue(false);
      mockRedisClient.incr.mockResolvedValue(1);

      try {
        await service.verifyCode('user-uuid-1', 'wrong');
        fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).toContain(
          `${AUTH_CONSTANTS.TWO_FA_MAX_ATTEMPTS - 1}`,
        );
      }
    });

    it('should block after MAX_ATTEMPTS wrong codes', async () => {
      (speakeasy.totp.verify as jest.Mock).mockReturnValue(false);
      mockRedisClient.incr.mockResolvedValue(
        AUTH_CONSTANTS.TWO_FA_MAX_ATTEMPTS,
      );

      await expect(service.verifyCode('user-uuid-1', 'wrong')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should return false if no 2FA record exists', async () => {
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue(null);

      const result = await service.verifyCode('user-uuid-1', '123456');
      expect(result).toBe(false);
    });

    it('should return false if 2FA is not enabled (and not in enabling mode)', async () => {
      mockPrismaService.twoFactorAuth.findUnique.mockResolvedValue({
        isEnabled: false,
        secret: 'some-secret',
      });

      const result = await service.verifyCode('user-uuid-1', '123456');
      expect(result).toBe(false);
    });
  });

  // ==========================================
  // Encryption/Decryption
  // ==========================================
  describe('encryption', () => {
    it('should encrypt and decrypt symmetrically', () => {
      const plaintext = 'MY_SECRET_KEY_123';
      const encrypted = (service as any).encryptSecret(plaintext);
      const decrypted = (service as any).decryptSecret(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext each time (random IV)', () => {
      const plaintext = 'MY_SECRET_KEY_123';
      const encrypted1 = (service as any).encryptSecret(plaintext);
      const encrypted2 = (service as any).encryptSecret(plaintext);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should throw InternalServerErrorException on invalid ciphertext', () => {
      expect(() => (service as any).decryptSecret('invalid')).toThrow(
        InternalServerErrorException,
      );
    });
  });
});

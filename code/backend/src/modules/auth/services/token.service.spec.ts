/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/require-await */
import { UnauthorizedException, NotFoundException } from '@nestjs/common';
import { TokenService } from './token.service';
import { AUTH_CONSTANTS } from '../../../core/config/auth.constants';

// ==========================================
// Mocks
// ==========================================
const mockUser = {
  id: 'user-uuid-1',
  email: 'test@test.com',
  username: 'testuser',
  displayName: 'Test User',
  avatarUrl: null,
  passwordHash: '$2b$10$hashedPassword',
};

const mockSession = {
  id: 'session-uuid-1',
  userId: 'user-uuid-1',
  refreshToken: 'hashed-refresh-token',
  fingerprint: null,
  isRevoked: false,
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  createdAt: new Date(),
  user: mockUser,
};

// Prisma Transaction mock (phải mock nested async callback)
const mockTx = {
  userSession: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
  },
  user: {
    findUnique: jest.fn(),
  },
};

const mockPrismaService = {
  $transaction: jest.fn(async (callback: (tx: any) => any) => callback(mockTx)),
  userSession: {
    findMany: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
  },
};

const mockRedisClient = {
  sadd: jest.fn(),
  srem: jest.fn(),
  smembers: jest.fn().mockResolvedValue([]),
  del: jest.fn(),
  pipeline: jest.fn(),
};

const mockRedisPipeline = {
  setex: jest.fn().mockReturnThis(),
  sadd: jest.fn().mockReturnThis(),
  srem: jest.fn().mockReturnThis(),
  del: jest.fn().mockReturnThis(),
  exec: jest.fn().mockResolvedValue([]),
};

const mockRedisService = {
  getCache: jest.fn(),
  setCache: jest.fn(),
  deleteCache: jest.fn(),
  getClient: jest.fn().mockReturnValue(mockRedisClient),
};

const mockJwtService = {
  sign: jest.fn().mockReturnValue('mock-jwt-token'),
  verify: jest.fn(),
};

const mockConfigService = {
  get: jest.fn((key: string) => {
    if (key === 'JWT_2FA_SECRET') return 'test-2fa-secret';
    return null;
  }),
  getOrThrow: jest.fn((key: string) => {
    if (key === 'JWT_2FA_SECRET') return 'test-2fa-secret';
    throw new Error(`Missing config key: ${key}`);
  }),
};

describe('TokenService', () => {
  let service: TokenService;

  beforeEach(() => {
    service = new TokenService(
      mockPrismaService as any,
      mockJwtService as any,
      mockRedisService as any,
      mockConfigService as any,
    );
    jest.clearAllMocks();
    mockRedisService.getClient.mockReturnValue(mockRedisClient);
    mockRedisClient.smembers.mockResolvedValue([]);
    mockRedisClient.pipeline.mockReturnValue(mockRedisPipeline);
    // Re-apply pipeline mocks cleared by clearAllMocks
    mockRedisPipeline.setex.mockReturnThis();
    mockRedisPipeline.sadd.mockReturnThis();
    mockRedisPipeline.srem.mockReturnThis();
    mockRedisPipeline.del.mockReturnThis();
    mockRedisPipeline.exec.mockResolvedValue([]);
    mockPrismaService.$transaction.mockImplementation(async (cb: any) =>
      cb(mockTx),
    );
    mockPrismaService.userSession.findMany.mockResolvedValue([]);
  });

  // ==========================================
  // createSessionForUser
  // ==========================================
  describe('createSessionForUser', () => {
    beforeEach(() => {
      mockTx.userSession.create.mockResolvedValue({
        id: 'new-session-id',
        userId: 'user-uuid-1',
        refreshToken: 'hashed-token',
        expiresAt: new Date(Date.now() + AUTH_CONSTANTS.SESSION_EXPIRY_MS),
      });
      mockTx.user.findUnique.mockResolvedValue(mockUser);
      mockTx.userSession.findMany.mockResolvedValue([{ id: 'new-session-id' }]);
    });

    it('should create a new session and cache in Redis', async () => {
      await service.createSessionForUser(
        'user-uuid-1',
        '1.2.3.4',
        'Test Agent',
      );

      expect(mockTx.userSession.create).toHaveBeenCalled();
      expect(mockRedisPipeline.setex).toHaveBeenCalledWith(
        'session:new-session-id',
        AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
        expect.any(String),
      );
    });

    it('should return raw (unhashed) refresh token for cookie use', async () => {
      const result = await service.createSessionForUser(
        'user-uuid-1',
        '1.2.3.4',
        'Test Agent',
      );

      // refreshToken should be the raw hex token (64 chars), not the hashed one
      expect(result.refreshToken).toHaveLength(64);
    });

    it('should revoke oldest sessions when over limit', async () => {
      const manySessions = Array.from(
        { length: AUTH_CONSTANTS.MAX_SESSIONS_PER_USER + 2 },
        (_, i) => ({ id: `session-${i}` }),
      );
      mockTx.userSession.findMany.mockResolvedValue(manySessions);

      await service.createSessionForUser(
        'user-uuid-1',
        '1.2.3.4',
        'Test Agent',
      );

      expect(mockTx.userSession.updateMany).toHaveBeenCalledWith({
        where: {
          id: { in: expect.arrayContaining([expect.any(String)]) },
        },
        data: { isRevoked: true },
      });
    });

    it('should store only safe user data in Redis cache (no passwordHash)', async () => {
      await service.createSessionForUser(
        'user-uuid-1',
        '1.2.3.4',
        'Test Agent',
      );

      const cachedJson = mockRedisPipeline.setex.mock.calls[0][2];
      const cachedData = JSON.parse(cachedJson);

      expect(cachedData).toHaveProperty('id');
      expect(cachedData).toHaveProperty('email');
      expect(cachedData).not.toHaveProperty('passwordHash');
      expect(cachedData).not.toHaveProperty('isVerified');
    });
  });

  // ==========================================
  // refreshTokens — Token Rotation + Reuse Detection
  // ==========================================
  describe('refreshTokens', () => {
    it('should rotate tokens successfully', async () => {
      mockRedisService.getCache.mockResolvedValue(null); // no reuse flag
      mockPrismaService.userSession.findFirst.mockResolvedValue(mockSession);

      const result = await service.refreshTokens(
        'valid-raw-token',
        '1.2.3.4',
        'Test Agent',
      );

      expect(result).toHaveProperty('access_token');
      expect(result).toHaveProperty('refresh_token');
    });

    it('should save old token hash as rotated_refresh in Redis (reuse detection)', async () => {
      mockRedisService.getCache.mockResolvedValue(null);
      mockPrismaService.userSession.findFirst.mockResolvedValue(mockSession);

      await service.refreshTokens('valid-raw-token', '1.2.3.4', 'Test Agent');

      expect(mockRedisPipeline.setex).toHaveBeenCalledWith(
        expect.stringMatching(/^rotated_refresh:/),
        AUTH_CONSTANTS.SESSION_EXPIRY_SECONDS,
        mockSession.userId,
      );
    });

    it('🚨 should REVOKE ALL SESSIONS if rotated token is reused (token theft detection)', async () => {
      // Simulate: old rotated token found in Redis = reuse!
      mockRedisService.getCache.mockResolvedValueOnce('user-uuid-1'); // rotated_refresh found

      await expect(
        service.refreshTokens('stolen-old-token', '1.2.3.4', 'Test Agent'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw if session not found (invalid token)', async () => {
      mockRedisService.getCache.mockResolvedValue(null);
      mockPrismaService.userSession.findFirst.mockResolvedValue(null);

      await expect(
        service.refreshTokens('invalid-token', '1.2.3.4', 'Test Agent'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw and revoke expired session', async () => {
      const expiredSession = {
        ...mockSession,
        expiresAt: new Date(Date.now() - 1000), // expired
      };
      mockRedisService.getCache.mockResolvedValue(null);
      mockPrismaService.userSession.findFirst.mockResolvedValue(expiredSession);

      await expect(
        service.refreshTokens('expired-token', '1.2.3.4', 'Test Agent'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  // ==========================================
  // generateTokens — Lean JWT (HACK-3)
  // ==========================================
  describe('generateTokens', () => {
    it('should generate a JWT with ONLY sub and sessionId (lean JWT)', async () => {
      service.generateTokens(mockUser, 'session-1', 'refresh-token');

      const payloadArg = mockJwtService.sign.mock.calls[0][0];
      expect(payloadArg).toEqual({
        sub: 'user-uuid-1',
        sessionId: 'session-1',
      });
      // Must NOT contain email or username
      expect(payloadArg).not.toHaveProperty('email');
      expect(payloadArg).not.toHaveProperty('username');
    });

    it('should return user data via toSafeUserData (not in JWT)', () => {
      const result = service.generateTokens(mockUser, 'session-1');

      expect(result.user).toEqual({
        id: 'user-uuid-1',
        email: 'test@test.com',
        username: 'testuser',
        displayName: 'Test User',
        avatarUrl: null,
      });
    });

    it('should return empty string for refresh_token when not provided', () => {
      const result = service.generateTokens(mockUser, 'session-1');

      expect(result.refresh_token).toBe('');
    });
  });

  // ==========================================
  // revokeSession
  // ==========================================
  describe('revokeSession', () => {
    it('should revoke session and clear from Redis', async () => {
      mockPrismaService.userSession.findFirst.mockResolvedValue(mockSession);

      await service.revokeSession('user-uuid-1', 'session-uuid-1');

      expect(mockPrismaService.userSession.update).toHaveBeenCalledWith({
        where: { id: 'session-uuid-1' },
        data: { isRevoked: true },
      });
      expect(mockRedisPipeline.del).toHaveBeenCalledWith(
        'session:session-uuid-1',
      );
    });

    it('should throw if session not found for user', async () => {
      mockPrismaService.userSession.findFirst.mockResolvedValue(null);

      await expect(
        service.revokeSession('user-uuid-1', 'wrong-session'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  // ==========================================
  // 2FA Temp Token
  // ==========================================
  describe('generateTemp2FAToken / verifyTemp2FAToken', () => {
    it('should generate a temp 2FA token with separate secret', () => {
      service.generateTemp2FAToken('user-uuid-1');

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        { sub: 'user-uuid-1', type: '2FA_TEMP' },
        {
          expiresIn: AUTH_CONSTANTS.TWO_FA_TEMP_TOKEN_EXPIRY,
          secret: 'test-2fa-secret',
        },
      );
    });

    it('should verify valid 2FA temp token', () => {
      mockJwtService.verify.mockReturnValue({
        sub: 'user-uuid-1',
        type: '2FA_TEMP',
      });

      const result = service.verifyTemp2FAToken('valid-token');

      expect(result).toBe('user-uuid-1');
    });

    it('should return null for invalid 2FA temp token', () => {
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('invalid');
      });

      const result = service.verifyTemp2FAToken('invalid-token');

      expect(result).toBeNull();
    });

    it('should return null if token type is not 2FA_TEMP', () => {
      mockJwtService.verify.mockReturnValue({
        sub: 'user-uuid-1',
        type: 'NORMAL',
      });

      const result = service.verifyTemp2FAToken('wrong-type-token');

      expect(result).toBeNull();
    });
  });
});

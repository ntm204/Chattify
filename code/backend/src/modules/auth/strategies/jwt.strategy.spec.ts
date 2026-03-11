/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument */
import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from './jwt.strategy';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { UnauthorizedException } from '@nestjs/common';

import { RedisService } from '../../../core/redis/redis.service';

const mockConfigService = {
  get: jest.fn().mockReturnValue('test-secret'),
};

const mockUsersService = {
  findById: jest.fn(),
};

const mockPrismaService = {
  userSession: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
  },
};

const mockRedisService = {
  getCache: jest.fn(),
  setCache: jest.fn(),
  getClient: jest.fn().mockReturnValue({ sadd: jest.fn() }),
};

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: UsersService, useValue: mockUsersService },
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: RedisService, useValue: mockRedisService },
      ],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(strategy).toBeDefined();
  });

  it('should successfully validate payload', async () => {
    const payload = { sub: 'u1', sessionId: 's1' };
    const user = { id: 'u1', isActive: true, email: 'test@example.com' };

    mockRedisService.getCache.mockResolvedValue(JSON.stringify(user));

    const result = await strategy.validate(payload);

    expect(result).toEqual({ ...user, currentSessionId: 's1' });
    expect(mockRedisService.getCache).toHaveBeenCalledWith('session:s1');
  });

  it('should throw UnauthorizedException if session is invalid or revoked', async () => {
    const payload = { sub: 'u1', sessionId: 's1' };

    mockRedisService.getCache.mockResolvedValue(null);
    mockPrismaService.userSession.findUnique.mockResolvedValue(null);

    await expect(strategy.validate(payload)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('should throw UnauthorizedException if session id is missing from payload', async () => {
    const payload = { sub: 'u1' } as any;
    const user = { id: 'u1', isActive: true };

    mockUsersService.findById.mockResolvedValue(user);

    await expect(strategy.validate(payload)).rejects.toThrow(
      UnauthorizedException,
    );
  });
});

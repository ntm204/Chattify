import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtAuthGuard } from './jwt-auth.guard';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;

  const createContext = (user: unknown): ExecutionContext =>
    ({
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    }) as unknown as ExecutionContext;

  beforeEach(() => {
    guard = new JwtAuthGuard();
    jest.clearAllMocks();
  });

  describe('canActivate', () => {
    it('should return false when base passport guard validation fails', async () => {
      jest
        .spyOn(AuthGuard('jwt').prototype, 'canActivate')
        .mockResolvedValueOnce(false as never);

      const result = await guard.canActivate(createContext(null));

      expect(result).toBe(false);
    });

    it('should throw when user sessionId is missing from request', async () => {
      jest
        .spyOn(AuthGuard('jwt').prototype, 'canActivate')
        .mockResolvedValueOnce(true as never);

      await expect(
        guard.canActivate(createContext({ id: 'u1' })),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should allow request when user has valid sessionId (strategy already validated session)', async () => {
      jest
        .spyOn(AuthGuard('jwt').prototype, 'canActivate')
        .mockResolvedValueOnce(true as never);

      const result = await guard.canActivate(
        createContext({ id: 'u1', currentSessionId: 's1' }),
      );

      expect(result).toBe(true);
    });
  });

  describe('handleRequest', () => {
    it('should throw UnauthorizedException when user is missing', () => {
      expect(() => guard.handleRequest(null, null)).toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException when err exists', () => {
      expect(() =>
        guard.handleRequest(new Error('boom'), { id: 'u1' }),
      ).toThrow(UnauthorizedException);
    });

    it('should return user when request is valid', () => {
      const user = { id: 'u1' };
      expect(guard.handleRequest(null, user)).toEqual(user);
    });
  });
});

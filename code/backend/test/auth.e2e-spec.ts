import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import cookieParser from 'cookie-parser';
import { AuthGuard } from '@nestjs/passport';
import { AuthController } from '../src/modules/auth/controllers/auth.controller';
import { AuthService } from '../src/modules/auth/services/auth.service';
import { PasswordService } from '../src/modules/auth/services/password.service';
import { TwoFactorService } from '../src/modules/auth/services/two-factor.service';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../src/core/redis/redis.service';
import { AUTH_MESSAGES } from '../src/core/config/auth.messages';
import { AuthAuditService } from '../src/modules/auth/services/auth-audit.service';

const getCookieValue = (
  setCookies: string[] | undefined,
  name: string,
): string | null => {
  if (!setCookies) return null;

  for (const cookie of setCookies) {
    const match = cookie.match(new RegExp(`${name}=([^;]+)`));
    if (match?.[1]) return match[1];
  }

  return null;
};

const toCookieArray = (value: unknown): string[] | undefined => {
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value;
  }
  if (typeof value === 'string') {
    return [value];
  }
  return undefined;
};

describe('Auth Smoke (e2e)', () => {
  jest.setTimeout(30000);

  let app: INestApplication;
  let httpServer: App;
  const authService = {
    register: jest.fn(),
    login: jest.fn(),
    verifyOtp: jest.fn(),
    resendOtp: jest.fn(),
    refreshTokens: jest.fn(),
    revokeSession: jest.fn(),
    revokeAllSessions: jest.fn(),
    getSessions: jest.fn(),
    sendPhoneOtp: jest.fn(),
    loginWithPhoneOtp: jest.fn(),
    verify2FALogin: jest.fn(),
    requestChangeEmail: jest.fn(),
    verifyChangeEmail: jest.fn(),
    requestChangePhone: jest.fn(),
    verifyChangePhone: jest.fn(),
  };

  const passwordService = {
    forgotPassword: jest.fn(),
    resetPassword: jest.fn(),
    changePassword: jest.fn(),
  };

  const twoFactorService = {
    generateTwoFactorAuthSecret: jest.fn(),
    turnOnTwoFactorAuth: jest.fn(),
    turnOffTwoFactorAuth: jest.fn(),
  };

  const redisService = {
    getCache: jest.fn(),
  };

  const authAuditService = {
    log: jest.fn().mockResolvedValue(undefined),
  };

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: PasswordService, useValue: passwordService },
        { provide: TwoFactorService, useValue: twoFactorService },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('development'),
          },
        },
        {
          provide: RedisService,
          useValue: redisService,
        },
        {
          provide: AuthAuditService,
          useValue: authAuditService,
        },
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
      }),
    );

    await app.init();
    httpServer = app.getHttpServer() as App;
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    redisService.getCache.mockResolvedValue('session-user-smoke');

    jest
      .spyOn(AuthGuard('jwt').prototype, 'canActivate')
      .mockImplementation((context) => {
        const req = (
          context as {
            switchToHttp: () => {
              getRequest: () => {
                user?: { id: string; currentSessionId: string };
              };
            };
          }
        )
          .switchToHttp()
          .getRequest();

        req.user = {
          id: 'smoke-user-id',
          currentSessionId: 'smoke-session-id',
        };

        return true;
      });
  });

  it('smoke: login sets access and refresh cookies', async () => {
    authService.login.mockResolvedValue({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      user: { id: 'u1' },
    });

    const response = await request(httpServer)
      .post('/api/v1/auth/login')
      .send({ identifier: 'user@example.com', password: 'Password123!' })
      .expect(201);

    expect((response.body as { message: string }).message).toBe(
      AUTH_MESSAGES.LOGIN_SUCCESS,
    );

    const setCookies = toCookieArray(response.headers['set-cookie']);
    expect(getCookieValue(setCookies, 'access_token')).toBeTruthy();
    expect(getCookieValue(setCookies, 'refresh_token')).toBeTruthy();
  });

  it('smoke: refresh without cookie returns unauthorized', async () => {
    await request(httpServer).post('/api/v1/auth/refresh').expect(401);
  });

  it('smoke: refresh with cookie rotates tokens and resets cookies', async () => {
    authService.refreshTokens.mockResolvedValue({
      access_token: 'access-rotated',
      refresh_token: 'refresh-rotated',
      user: { id: 'u1' },
    });

    const response = await request(httpServer)
      .post('/api/v1/auth/refresh')
      .set('Cookie', ['refresh_token=refresh-old'])
      .expect(201)
      .expect({ message: AUTH_MESSAGES.REFRESH_TOKEN_SUCCESS });

    expect(authService.refreshTokens).toHaveBeenCalledWith(
      'refresh-old',
      '::ffff:127.0.0.1',
      'Unknown',
    );
    const setCookies = toCookieArray(response.headers['set-cookie']);
    expect(getCookieValue(setCookies, 'access_token')).toBeTruthy();
    expect(getCookieValue(setCookies, 'refresh_token')).toBeTruthy();
  });

  it('smoke: verify-email maps to verifyOtp and sets cookies', async () => {
    authService.verifyOtp.mockResolvedValue({
      access_token: 'at',
      refresh_token: 'rt',
      user: { id: 'u2' },
    });

    const response = await request(httpServer)
      .post('/api/v1/auth/verify-email')
      .send({ identifier: 'user@example.com', otp: '123456' })
      .expect(201)
      .expect({
        message: AUTH_MESSAGES.VERIFY_EMAIL_SUCCESS,
        user: { id: 'u2' },
      });

    const setCookies = toCookieArray(response.headers['set-cookie']);
    expect(getCookieValue(setCookies, 'access_token')).toBeTruthy();
    expect(getCookieValue(setCookies, 'refresh_token')).toBeTruthy();
  });

  it('smoke: 2FA challenge does not set cookies', async () => {
    authService.login.mockResolvedValue({
      requires2FA: true,
      message: AUTH_MESSAGES.TFA_REQUIRED,
      tempToken: 'temp-token',
    });

    const response = await request(httpServer)
      .post('/api/v1/auth/login')
      .send({ identifier: 'user@example.com', password: 'Password123!' })
      .expect(201)
      .expect({
        requires2FA: true,
        message: AUTH_MESSAGES.TFA_REQUIRED,
        tempToken: 'temp-token',
      });

    expect(toCookieArray(response.headers['set-cookie'])).toBeUndefined();
  });

  it('smoke: logout clears auth cookies', async () => {
    authService.revokeSession.mockResolvedValue({
      message: AUTH_MESSAGES.SESSION_REVOKE_SUCCESS,
    });

    const loginResponse = await request(httpServer)
      .post('/api/v1/auth/login')
      .send({ identifier: 'user@example.com', password: 'Password123!' });

    await request(httpServer)
      .post('/api/v1/auth/logout')
      .set('Cookie', toCookieArray(loginResponse.headers['set-cookie']) || [])
      .expect(201)
      .expect((res) => {
        const cookies = toCookieArray(res.headers['set-cookie']);
        expect(getCookieValue(cookies, 'access_token')).toBeFalsy();
        expect(getCookieValue(cookies, 'refresh_token')).toBeFalsy();
      });
  });
});

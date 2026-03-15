import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import cookieParser from 'cookie-parser';
import { AppModule } from '../../app.module';
import { MailService } from '../../core/mail/mail.service';
import { PrismaService } from '../../core/prisma/prisma.service';
import { RedisService } from '../../core/redis/redis.service';
import { AUTH_MESSAGES } from '../../core/config/auth.messages';

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

describe('Auth Advanced Security (e2e)', () => {
  jest.setTimeout(90000);

  let app: INestApplication;
  let httpServer: App;
  let prisma: PrismaService;
  let redis: RedisService;
  let latestEmailOtp: string | null = null;

  const mailServiceMock = {
    onModuleInit: jest.fn(() => Promise.resolve()),
    sendOtpEmail: jest.fn((_to: string, otp: string) => {
      latestEmailOtp = otp;
      return Promise.resolve();
    }),
    sendSecurityAlertEmail: jest.fn(() => Promise.resolve()),
  };

  const TEST_IP = '1.1.1.1';
  const UA_CHROME = 'Chrome-Device';
  const UA_HACKER = 'Hacker-Device';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(MailService)
      .useValue(mailServiceMock)
      .compile();

    app = moduleFixture.createNestApplication();
    const httpServerInstance = app.getHttpAdapter().getInstance() as {
      set: (k: string, v: any) => void;
    };
    httpServerInstance.set('trust proxy', 1);
    app.setGlobalPrefix('api/v1');
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({ transform: true, whitelist: true }),
    );
    await app.init();
    httpServer = app.getHttpServer() as App;
    prisma = app.get(PrismaService);
    redis = app.get(RedisService);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "auth_logs", "user_sessions", "password_histories", "users" RESTART IDENTITY CASCADE;',
    );
    await redis.getClient().flushdb();
  });

  const registerAndVerify = async (email: string, userAgent = UA_CHROME) => {
    const password = 'SafePassword2026!@#';
    await request(httpServer)
      .post('/api/v1/auth/register')
      .set('X-Forwarded-For', TEST_IP)
      .send({ email, password, displayName: 'Test User' })
      .expect(201);
    await request(httpServer)
      .post('/api/v1/auth/verify-email')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', userAgent)
      .send({ identifier: email, otp: latestEmailOtp })
      .expect(201);
    return { email, password };
  };

  it('Security: Token Binding - Should fail refresh if User-Agent changes', async () => {
    const { email, password } = await registerAndVerify(
      'binding@test.com',
      UA_CHROME,
    );

    const loginRes = await request(httpServer)
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', UA_CHROME)
      .send({ identifier: email, password })
      .expect(201);

    const cookies = toCookieArray(loginRes.headers['set-cookie']) || [];
    const refreshToken = getCookieValue(cookies, 'refresh_token');

    // Success with same UA and same IP
    await request(httpServer)
      .post('/api/v1/auth/refresh')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', UA_CHROME)
      .set('Cookie', [`refresh_token=${refreshToken}`])
      .expect(201);

    // Fail with different UA
    const failRes = await request(httpServer)
      .post('/api/v1/auth/refresh')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', UA_HACKER)
      .set('Cookie', [`refresh_token=${refreshToken}`])
      .expect(401);

    const body = failRes.body as { message: string };
    expect(body.message).toMatch(/thiết bị bất thường|token cũ/);
  });

  it('Security: Password History - Should prevent reusing old passwords', async () => {
    const { email, password } = await registerAndVerify('history@test.com');
    const loginRes = await request(httpServer)
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', UA_CHROME)
      .send({ identifier: email, password })
      .expect(201);
    const cookies = toCookieArray(loginRes.headers['set-cookie']) || [];

    // Change to NEW password (Success)
    const newPassword = 'NewPassword456!';
    await request(httpServer)
      .post('/api/v1/auth/change-password')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', UA_CHROME)
      .set('Cookie', cookies)
      .send({ oldPassword: password, newPassword })
      .expect(201);

    // Try to change back to OLD password (Fail)
    const login2 = await request(httpServer)
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', UA_CHROME)
      .send({ identifier: email, password: newPassword })
      .expect(201);
    const cookies2 = toCookieArray(login2.headers['set-cookie']) || [];

    const backRes = await request(httpServer)
      .post('/api/v1/auth/change-password')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', UA_CHROME)
      .set('Cookie', cookies2)
      .send({ oldPassword: newPassword, newPassword: password })
      .expect(400);

    const body = backRes.body as { message: string };
    expect(body.message).toBe(AUTH_MESSAGES.PASSWORD_REUSE_ERROR);
  });

  it('Security: HIBP Breach Check - Should block common/leaked passwords', async () => {
    // 'Password123!' is very common and passes Regex
    const res = await request(httpServer)
      .post('/api/v1/auth/register')
      .set('X-Forwarded-For', TEST_IP)
      .send({
        email: 'pwned@test.com',
        password: 'Password123!',
        displayName: 'Pwned User',
      })
      .expect(400);

    const body = res.body as { message: string };
    expect(body.message).toBe(AUTH_MESSAGES.PASSWORD_PWNED_ERROR);
  });

  it('Security: New Device Alert - Should trigger security email on first login from new device', async () => {
    const email = 'alert@test.com';
    await registerAndVerify(email, 'Device-1');

    // First call happened during verify-email
    expect(mailServiceMock.sendSecurityAlertEmail).toHaveBeenCalledWith(
      email,
      'Đăng nhập từ thiết bị mới',
      expect.objectContaining({ device: 'Device-1' }),
    );
    mailServiceMock.sendSecurityAlertEmail.mockClear();

    // Login from Device-1 again (No alert)
    await request(httpServer)
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', 'Device-1')
      .send({ identifier: email, password: 'SafePassword2026!@#' })
      .expect(201);

    expect(mailServiceMock.sendSecurityAlertEmail).not.toHaveBeenCalled();

    // Login from Device-2 (New Device)
    await request(httpServer)
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', TEST_IP)
      .set('User-Agent', 'Device-2-New')
      .send({ identifier: email, password: 'SafePassword2026!@#' })
      .expect(201);

    expect(mailServiceMock.sendSecurityAlertEmail).toHaveBeenCalledWith(
      email,
      'Đăng nhập từ thiết bị mới',
      expect.objectContaining({ device: 'Device-2-New' }),
    );
  });
});

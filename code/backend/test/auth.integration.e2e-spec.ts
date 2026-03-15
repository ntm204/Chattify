import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import cookieParser from 'cookie-parser';
import { createDecipheriv, createHash, scryptSync } from 'crypto';
import { ConfigService } from '@nestjs/config';
import * as speakeasy from 'speakeasy';
import { AppModule } from '../src/app.module';
import { MailService } from '../src/core/mail/mail.service';
import { SmsService } from '../src/core/sms/sms.service';
import { PrismaService } from '../src/core/prisma/prisma.service';
import { RedisService } from '../src/core/redis/redis.service';
import { AuthUtils } from '../src/core/utils/auth.util';
import { AUTH_MESSAGES } from '../src/core/config/auth.messages';
import { AUTH_CONSTANTS } from '../src/core/config/auth.constants';

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

const runIntegrationE2E = process.env.RUN_AUTH_INTEGRATION_E2E === 'true';
const describeIntegration = runIntegrationE2E ? describe : describe.skip;

if (runIntegrationE2E) {
  process.env.NODE_ENV = 'development';
}

let ipSeed = 10;
const nextTestIp = () => {
  ipSeed += 1;
  const octet = (ipSeed % 240) + 10;
  return `10.0.0.${octet}`;
};

const withIp = (req: request.Test, ip: string): request.Test =>
  req.set('X-Forwarded-For', ip);

describeIntegration('Auth Integration (e2e)', () => {
  jest.setTimeout(90000);

  let app: INestApplication;
  let httpServer: App;
  let prisma: PrismaService;
  let redis: RedisService;
  let configService: ConfigService;

  let latestEmailOtp: string | null = null;
  let latestPasswordResetOtp: string | null = null;
  let latestPhoneOtp: string | null = null;

  const mailServiceMock = {
    onModuleInit: jest.fn(),
    sendOtpEmail: jest.fn((_to: string, otp: string) => {
      latestEmailOtp = otp;
      return Promise.resolve();
    }),
    sendPasswordResetOtpEmail: jest.fn((_to: string, otp: string) => {
      latestPasswordResetOtp = otp;
      return Promise.resolve();
    }),
  };

  const smsServiceMock = {
    sendSms: jest.fn(() => Promise.resolve(true)),
    sendOtp: jest.fn((_to: string, otp: string) => {
      latestPhoneOtp = otp;
      return Promise.resolve(true);
    }),
  };

  const createIdentity = () => {
    const suffix =
      Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    return {
      email: `e2e_${suffix}@example.com`,
      displayName: `E2E ${suffix}`,
      password: 'Password123!',
    };
  };

  const registerAndVerify = async (ip: string) => {
    const identity = createIdentity();

    await withIp(request(httpServer).post('/api/v1/auth/register'), ip)
      .send(identity)
      .expect(201);
    expect(latestEmailOtp).toBeTruthy();

    const verifyResponse = await withIp(
      request(httpServer).post('/api/v1/auth/verify-email'),
      ip,
    )
      .set('User-Agent', 'Auth-E2E-Agent')
      .send({ identifier: identity.email, otp: latestEmailOtp })
      .expect(201);

    const authCookies =
      toCookieArray(verifyResponse.headers['set-cookie']) || [];
    const refreshToken = getCookieValue(authCookies, 'refresh_token');
    const accessToken = getCookieValue(authCookies, 'access_token');

    expect(refreshToken).toBeTruthy();
    expect(accessToken).toBeTruthy();

    return {
      ...identity,
      refreshToken: refreshToken as string,
      authCookies,
    };
  };

  const decryptTwoFactorSecret = (ciphertext: string): string => {
    const rawKey = configService.get<string>('TWO_FACTOR_ENCRYPTION_KEY');
    const salt = configService.get<string>('TWO_FACTOR_SALT');

    if (!rawKey || !salt) {
      throw new Error('Missing 2FA encryption config in integration test env');
    }

    const encryptionKey = scryptSync(rawKey, salt, 32);
    const [ivHex, authTagHex, encryptedHex] = ciphertext.split(':');

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  };

  const generate2FACode = (secret: string): string =>
    speakeasy.totp({
      secret,
      encoding: 'base32',
    });

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(MailService)
      .useValue(mailServiceMock)
      .overrideProvider(SmsService)
      .useValue(smsServiceMock)
      .compile();

    app = moduleFixture.createNestApplication();
    const httpServerInstance = app.getHttpAdapter().getInstance() as {
      set: (name: string, value: unknown) => void;
    };
    httpServerInstance.set('trust proxy', 1);
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
      }),
    );

    await app.init();
    httpServer = app.getHttpServer() as App;

    prisma = app.get(PrismaService);
    redis = app.get(RedisService);
    configService = app.get(ConfigService);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    latestEmailOtp = null;
    latestPasswordResetOtp = null;
    latestPhoneOtp = null;

    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "auth_logs", "user_sessions", "two_factor_auths", "users" RESTART IDENTITY CASCADE;',
    );
    await redis.getClient().flushdb();
  });

  it('Feature: register + verify-email + session access', async () => {
    const ip = nextTestIp();
    const identity = await registerAndVerify(ip);

    const sessionsResponse = await request(httpServer)
      .get('/api/v1/auth/sessions')
      .set('Cookie', identity.authCookies)
      .expect(200);

    expect(Array.isArray(sessionsResponse.body)).toBe(true);
    expect((sessionsResponse.body as Array<unknown>).length).toBeGreaterThan(0);

    const meLogin = await withIp(
      request(httpServer).post('/api/v1/auth/login'),
      ip,
    )
      .send({ identifier: identity.email, password: identity.password })
      .expect(201);

    expect((meLogin.body as { message: string }).message).toBe(
      AUTH_MESSAGES.LOGIN_SUCCESS,
    );
  });

  it('Feature: refresh rotation + reuse detection hardening', async () => {
    const ip = nextTestIp();
    const identity = await registerAndVerify(ip);

    const firstRefresh = await request(httpServer)
      .post('/api/v1/auth/refresh')
      .set('Cookie', identity.authCookies)
      .expect(201);
    expect((firstRefresh.body as { message: string }).message).toBe(
      AUTH_MESSAGES.REFRESH_TOKEN_SUCCESS,
    );

    const rotatedRefreshToken = getCookieValue(
      toCookieArray(firstRefresh.headers['set-cookie']),
      'refresh_token',
    );
    expect(rotatedRefreshToken).toBeTruthy();

    const staleHash = createHash('sha256')
      .update(identity.refreshToken)
      .digest('hex');
    await redis.deleteCache(`refresh_grace:${staleHash}`);

    await request(httpServer)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refresh_token=${identity.refreshToken}`])
      .expect(401);

    await request(httpServer)
      .get('/api/v1/auth/sessions')
      .set('Cookie', identity.authCookies)
      .expect(401);
  });

  it('Feature: forgot-password + reset-password invalidates old password', async () => {
    const ip = nextTestIp();
    const identity = createIdentity();

    await withIp(request(httpServer).post('/api/v1/auth/register'), ip)
      .send(identity)
      .expect(201);

    expect(latestEmailOtp).toBeTruthy();

    await withIp(request(httpServer).post('/api/v1/auth/verify-email'), ip)
      .send({ identifier: identity.email, otp: latestEmailOtp })
      .expect(201);

    await withIp(request(httpServer).post('/api/v1/auth/forgot-password'), ip)
      .send({ identifier: identity.email })
      .expect(201)
      .expect({ message: AUTH_MESSAGES.FORGOT_PASSWORD_GENERIC });

    expect(latestPasswordResetOtp).toBeTruthy();

    const newPassword = 'NewPassword123!';
    await withIp(request(httpServer).post('/api/v1/auth/reset-password'), ip)
      .set('User-Agent', 'Reset-E2E-Agent')
      .send({
        identifier: identity.email,
        otp: latestPasswordResetOtp,
        newPassword,
      })
      .expect(201)
      .expect({ message: AUTH_MESSAGES.RESET_PASSWORD_SUCCESS });

    await withIp(request(httpServer).post('/api/v1/auth/login'), ip)
      .send({ identifier: identity.email, password: identity.password })
      .expect(401);

    await withIp(request(httpServer).post('/api/v1/auth/login'), ip)
      .send({ identifier: identity.email, password: newPassword })
      .expect(201)
      .expect((res) => {
        expect((res.body as { message: string }).message).toBe(
          AUTH_MESSAGES.LOGIN_SUCCESS,
        );
      });
  });

  it('Feature: phone OTP login works for new and existing user', async () => {
    const ip = nextTestIp();
    const phoneNumber = '+84912345678';

    await withIp(request(httpServer).post('/api/v1/auth/phone/send-otp'), ip)
      .send({ phoneNumber })
      .expect(201)
      .expect({ message: AUTH_MESSAGES.OTP_SENT_GENERIC });

    expect(latestPhoneOtp).toBeTruthy();

    const firstLogin = await withIp(
      request(httpServer).post('/api/v1/auth/phone/login'),
      ip,
    )
      .set('User-Agent', 'Phone-E2E-Agent')
      .send({ phoneNumber, otp: latestPhoneOtp })
      .expect(201);

    expect((firstLogin.body as { isNewUser?: boolean }).isNewUser).toBe(true);

    const normalizedPhone = AuthUtils.normalizeIdentifier(phoneNumber);
    await redis.deleteCache(`otp_cooldown:PHONE_LOGIN:${normalizedPhone}`);

    await withIp(request(httpServer).post('/api/v1/auth/phone/send-otp'), ip)
      .send({ phoneNumber })
      .expect(201);

    expect(latestPhoneOtp).toBeTruthy();

    const secondLogin = await withIp(
      request(httpServer).post('/api/v1/auth/phone/login'),
      ip,
    )
      .set('User-Agent', 'Phone-E2E-Agent-2')
      .send({ phoneNumber, otp: latestPhoneOtp })
      .expect(201);

    expect((secondLogin.body as { isNewUser?: boolean }).isNewUser).toBe(false);
  });

  it('Security: OTP cooldown blocks repeated resend requests', async () => {
    const ip = nextTestIp();
    const identity = createIdentity();

    await withIp(request(httpServer).post('/api/v1/auth/register'), ip)
      .send(identity)
      .expect(201);

    await withIp(request(httpServer).post('/api/v1/auth/resend-otp'), ip)
      .send({ identifier: identity.email })
      .expect(400)
      .expect((res) => {
        expect((res.body as { message: string }).message).toContain(
          'Vui lòng đợi',
        );
      });
  });

  it('Security: account lockout after repeated invalid password attempts', async () => {
    const attackIp = nextTestIp();
    const checkIp = nextTestIp();
    const identity = createIdentity();

    await withIp(request(httpServer).post('/api/v1/auth/register'), attackIp)
      .send(identity)
      .expect(201);
    expect(latestEmailOtp).toBeTruthy();

    await withIp(
      request(httpServer).post('/api/v1/auth/verify-email'),
      attackIp,
    )
      .send({ identifier: identity.email, otp: latestEmailOtp })
      .expect(201);

    for (
      let attempt = 0;
      attempt < AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS;
      attempt += 1
    ) {
      await withIp(request(httpServer).post('/api/v1/auth/login'), attackIp)
        .send({ identifier: identity.email, password: 'WrongPassword123!' })
        .expect(401);
    }

    await withIp(request(httpServer).post('/api/v1/auth/login'), checkIp)
      .send({ identifier: identity.email, password: identity.password })
      .expect(401)
      .expect((res) => {
        expect((res.body as { message: string }).message).toContain(
          'khóa tạm thời',
        );
      });
  });

  it('Feature: 2FA lifecycle (generate -> enable -> login challenge -> verify -> disable)', async () => {
    const ip = nextTestIp();
    const identity = await registerAndVerify(ip);

    const generated = await request(httpServer)
      .post('/api/v1/auth/2fa/generate')
      .set('Cookie', identity.authCookies)
      .expect(201);
    expect(
      (generated.body as { qrCodeDataUrl?: string }).qrCodeDataUrl,
    ).toContain('data:image/png;base64');

    const user = await prisma.user.findUnique({
      where: { email: identity.email },
      select: { id: true },
    });
    expect(user).toBeTruthy();

    const twoFactor = await prisma.twoFactorAuth.findUnique({
      where: { userId: user!.id },
      select: { secret: true, isEnabled: true },
    });
    expect(twoFactor).toBeTruthy();
    expect(twoFactor!.isEnabled).toBe(false);

    const secret = decryptTwoFactorSecret(twoFactor!.secret);
    const enableCode = generate2FACode(secret);

    const enabled = await request(httpServer)
      .post('/api/v1/auth/2fa/turn-on')
      .set('Cookie', identity.authCookies)
      .send({ code: enableCode })
      .expect(201);
    expect((enabled.body as { message: string }).message).toBe(
      AUTH_MESSAGES.TFA_ENABLE_SUCCESS,
    );
    expect(
      (enabled.body as { recoveryCodes?: string[] }).recoveryCodes,
    ).toHaveLength(8);

    await request(httpServer)
      .post('/api/v1/auth/logout')
      .set('Cookie', identity.authCookies)
      .expect(201);

    const challenge = await withIp(
      request(httpServer).post('/api/v1/auth/login'),
      ip,
    )
      .send({ identifier: identity.email, password: identity.password })
      .expect(201);

    expect((challenge.body as { requires2FA?: boolean }).requires2FA).toBe(
      true,
    );

    const tempToken = (challenge.body as { tempToken?: string }).tempToken;
    expect(tempToken).toBeTruthy();

    const verifyCode = generate2FACode(secret);
    const verified = await withIp(
      request(httpServer).post('/api/v1/auth/2fa/verify'),
      ip,
    )
      .send({ tempToken, code: verifyCode })
      .expect(201);

    expect((verified.body as { message: string }).message).toBe(
      AUTH_MESSAGES.LOGIN_SUCCESS,
    );

    const verifyCookies = toCookieArray(verified.headers['set-cookie']) || [];
    const disableCode = generate2FACode(secret);

    await request(httpServer)
      .post('/api/v1/auth/2fa/turn-off')
      .set('Cookie', verifyCookies)
      .send({ code: disableCode })
      .expect(201)
      .expect({ message: AUTH_MESSAGES.TFA_DISABLE_SUCCESS });

    const disabledState = await prisma.twoFactorAuth.findUnique({
      where: { userId: user!.id },
      select: { isEnabled: true },
    });
    expect(disabledState?.isEnabled).toBe(false);
  });

  it('Security: auth audit log captures failed/success/reset events', async () => {
    const ip = nextTestIp();
    const identity = createIdentity();

    await withIp(request(httpServer).post('/api/v1/auth/register'), ip)
      .send(identity)
      .expect(201);

    expect(latestEmailOtp).toBeTruthy();

    await withIp(request(httpServer).post('/api/v1/auth/verify-email'), ip)
      .send({ identifier: identity.email, otp: latestEmailOtp })
      .expect(201);

    const user = await prisma.user.findUnique({
      where: { email: identity.email },
      select: { id: true },
    });
    expect(user).toBeTruthy();

    await withIp(request(httpServer).post('/api/v1/auth/login'), ip)
      .send({ identifier: identity.email, password: 'WrongPassword123!' })
      .expect(401);

    await withIp(request(httpServer).post('/api/v1/auth/login'), ip)
      .send({ identifier: identity.email, password: identity.password })
      .expect(201);

    await withIp(request(httpServer).post('/api/v1/auth/forgot-password'), ip)
      .send({ identifier: identity.email })
      .expect(201);

    expect(latestPasswordResetOtp).toBeTruthy();

    await withIp(request(httpServer).post('/api/v1/auth/reset-password'), ip)
      .send({
        identifier: identity.email,
        otp: latestPasswordResetOtp,
        newPassword: 'ResetPassword123!',
      })
      .expect(201);

    const logs = await prisma.authLog.findMany({
      where: { userId: user!.id },
      select: { action: true, status: true },
    });

    expect(
      logs.some(
        (entry) => entry.action === 'LOGIN_FAILED' && entry.status === 'FAILED',
      ),
    ).toBe(true);
    expect(
      logs.some(
        (entry) =>
          entry.action === 'LOGIN_SUCCESS' && entry.status === 'SUCCESS',
      ),
    ).toBe(true);
    expect(
      logs.some(
        (entry) =>
          entry.action === 'PASSWORD_RESET_SUCCESS' &&
          entry.status === 'SUCCESS',
      ),
    ).toBe(true);
  });
});

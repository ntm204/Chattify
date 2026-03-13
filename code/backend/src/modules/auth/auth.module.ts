import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './services/auth.service';
import { AuthController } from './controllers/auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { TokenService } from './services/token.service';
import { OtpService } from './services/otp.service';
import { TwoFactorService } from './services/two-factor.service';
import { LockoutService } from './services/lockout.service';
import { PasswordService } from './services/password.service';
import { SessionCleanupCron } from './cron/session-cleanup.cron';
import { AUTH_CONSTANTS } from '../../core/config/auth.constants';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const secret = configService.get<string>('JWT_SECRET');
        if (!secret) {
          throw new Error(
            'FATAL ERROR: JWT_SECRET environment variable is not defined!',
          );
        }
        return {
          secret: secret,
          signOptions: {
            expiresIn: AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY,
            algorithm: 'HS256' as const,
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    TokenService,
    OtpService,
    TwoFactorService,
    LockoutService,
    PasswordService,
    SessionCleanupCron,
  ],
  exports: [AuthService, JwtStrategy, PassportModule],
})
export class AuthModule {}

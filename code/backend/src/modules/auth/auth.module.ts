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
          signOptions: { expiresIn: '15m' }, // Token hết hạn sau 15 phút
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
  ],
  exports: [AuthService, JwtStrategy, PassportModule],
})
export class AuthModule {}
